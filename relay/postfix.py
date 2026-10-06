"""The bridge between Postfix and the agent.

Postfix is left doing what it is good at: SMTP, TLS, SPF, DKIM, connection
tracking and rate limiting. It hands us a message on disk and expects a verdict.

The pipeline is a pipe, not a socket:

1. Postfix writes the message into ``maildrop_dir`` as a file and runs the
   agent's ``receive`` command.
2. The agent claims the file with an atomic rename, the same pattern the queue
   uses, so two Postfix workers cannot both pick up the same message.
3. The message is sealed to the reader's public key, fetched from the Orbit
   Mail server, and put on the durable queue *first*; only then does the
   agent tell Postfix it was accepted. A reader without a key yet means the
   message is deferred, never queued readable.

That ordering is the whole point. Once Postfix is told the message was
accepted, Postfix considers its job done and will not retry. So the agent
accepts only after the message is on disk, where its own queue owns it from
that moment on. The reverse order would create a window in which a crash loses
mail that nothing else holds.
"""

from __future__ import annotations

import email
import email.policy
import logging
import os

from .crypto import EncryptionError, seal
from .queue import QueuedMessage

logger = logging.getLogger(__name__)


def split_headers(raw_bytes):
    """Return ``(header_block, body)`` of an RFC 822 message as bytes."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        index = raw_bytes.find(separator)
        if index != -1:
            return raw_bytes[:index], raw_bytes[index + len(separator):]
    return raw_bytes, b""


def has_attachments(parsed):
    """Whether any part is an attachment, judged the way the server does."""
    if not parsed.is_multipart():
        return False
    for part in parsed.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition or part.get_filename():
            return True
    return False


def _original_name(path):
    """Strip the ``<name>.<pid>`` suffix added when a file is claimed."""
    name = os.path.basename(path)
    stem, _, suffix = name.rpartition(".")
    return stem if stem and suffix.isdigit() else name

#: Messages larger than this are rejected at the door rather than filling the
#: queue. Matches the default ceiling of most receiving MTAs.
MAX_MESSAGE_BYTES = 50 * 1024 * 1024


class Maildrop:
    """Reads messages Postfix has written, and reports delivery verdicts."""

    def __init__(self, directory, queue, node_name="", keys=None):
        if keys is None:
            # There is no readable mode. Refusing here, rather than at the
            # first message, keeps a misconfigured node from accepting mail
            # it would then have to hold.
            raise EncryptionError("The maildrop needs a key directory; mail is never queued readable.")
        self.directory = os.path.abspath(directory)
        self.queue = queue
        self.node_name = node_name
        #: ``lookup(address) -> (kid, raw_public)``, raising KeyUnavailable.
        #: Every message is sealed to its reader before it is queued, so the
        #: plaintext never rests on disk and never reaches the server.
        self.keys = keys
        self.processing_dir = os.path.join(self.directory, ".processing")
        os.makedirs(self.processing_dir, exist_ok=True)

    def claim(self, filename):
        """Atomically take ownership of one dropped file.

        Returns the claimed path, or None when another worker got there first,
        which is normal under concurrent delivery, not an error.
        """
        source = os.path.join(self.directory, filename)
        if not os.path.isfile(source):
            return None
        target = os.path.join(self.processing_dir, f"{filename}.{os.getpid()}")
        try:
            os.rename(source, target)
        except (FileNotFoundError, OSError):
            return None
        return target

    def release(self, path):
        """Return a claimed file to the drop directory for another attempt.

        The claim suffix added by :meth:`claim` is stripped here rather than
        split on a dot, because the drop filename is an email address and
        contains dots of its own.
        """
        original = _original_name(path)
        try:
            os.rename(path, os.path.join(self.directory, original))
        except OSError:
            # Falling back to removal is wrong for a retry path (it would drop
            # the message), so the file is left in place for Postfix to notice.
            logger.warning("Could not release %s back to the maildrop.", path)

    def discard(self, path):
        try:
            os.remove(path)
        except OSError:
            pass

    def process_file(self, path):
        """Read one dropped message and enqueue it.

        Returns the queued message. Raises ValueError for a message that is
        too large or has no usable envelope recipient, which the caller turns
        into an SMTP rejection, and KeyUnavailable when the reader's public
        key cannot be had right now, which the caller turns into a deferral.
        """
        size = os.path.getsize(path)
        if size > MAX_MESSAGE_BYTES:
            raise ValueError(f"Message is {size} bytes, over the {MAX_MESSAGE_BYTES} limit.")

        with open(path, "rb") as handle:
            raw_bytes = handle.read()

        parsed = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        recipient, envelope_from = self._envelope(parsed, path)

        message = QueuedMessage(
            recipient=recipient,
            envelope_from=envelope_from,
            relay_host=self.node_name,
            received_at=_now_iso(),
        )
        # The whole message is sealed to the reader's key so the browser can
        # parse it in full. The header block travels readable beside it: the
        # server needs From, To, Subject and the threading headers to file
        # the message, and they are the part a mail relay sees anyway.
        kid, raw_public = self.keys.lookup(recipient)
        header_block, _body = split_headers(raw_bytes)
        envelope, ciphertext = seal(raw_bytes, [(kid, raw_public)])
        message.raw = ciphertext
        message.encoding = "base64"
        message.encryption = envelope
        message.headers = header_block.decode("utf-8", errors="replace")
        message.has_attachments = has_attachments(parsed)
        message.plain_size = size
        # Durability first: Postfix is about to be told this was accepted.
        self.queue.enqueue(message)
        return message

    @staticmethod
    def _envelope(parsed, path):
        """Recover the envelope recipient and sender.

        Postfix writes them into the ``Return-Path`` / ``X-Original-To``
        headers it adds, which is more reliable than trusting the visible
        ``To:``, since that header can list several addresses or none at all.
        """
        envelope_from = (parsed.get("Return-Path") or "").strip().lstrip("<").rstrip(">")
        if not envelope_from:
            # Postfix normally adds Return-Path, but a message assembled
            # elsewhere (or one this agent re-reads from disk) may lack it.
            # Falling back to From: is a guess about the envelope sender, and a
            # bounce computed from it could misdirect a reply, so this is
            # recorded as the best available value rather than treated as
            # authoritative.
            envelope_from = (email.utils.parseaddr(str(parsed.get("From") or ""))[1] or "").strip()

        recipients = []
        for header in ("X-Original-To", "Delivered-To", "Envelope-To"):
            value = parsed.get(header)
            if value:
                recipients.append(str(value).strip().strip("<>"))
        if not recipients:
            raw = parsed.get("To")
            if raw:
                # `getaddresses` handles "A <a@x>, B <b@y>" correctly, where a
                # naive split on comma would break display names containing one.
                recipients = [addr for _name, addr in email.utils.getaddresses([str(raw)]) if addr]

        recipient = recipients[0].lower() if recipients else ""

        # Postfix names the drop file after the envelope recipient, which is the
        # only value that is correct when a message has several `To:` headers
        # and was delivered to exactly one mailbox. The filename is recovered by
        # stripping only the numeric claim suffix, because an email address contains
        # dots of its own, so splitting on "." would truncate the domain.
        stem = _original_name(path)
        if stem and "@" in stem:
            recipient = stem.lower()

        return recipient, envelope_from.lower()


def _now_iso():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
