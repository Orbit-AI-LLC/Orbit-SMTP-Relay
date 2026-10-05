"""Sending outgoing mail that Orbit Mail has queued.

The agent claims a batch over the API, hands each message to the local Postfix
through ``sendmail``, and reports the result. Postfix then does the real work:
DNS, MX lookup, TLS, retries to the remote server, DKIM signing if configured.

What counts as which result:

* ``sent``: Postfix accepted the message into its own queue. From here on
  Postfix owns delivery and will bounce to the sender if it ultimately fails.
* ``deferred``: sendmail was unavailable or refused temporarily (exit 75, or a
  missing binary). The server re-queues the message.
* ``failed``: sendmail rejected the message outright, for instance a malformed
  recipient. The server marks it failed and the sender sees it in the client.

When the relay encrypts, outgoing mail arrives from the server as a sealed
JSON document the browser produced (body and attachments) plus the readable
headers. The message is assembled here, on the node, so the server never
holds the plaintext of what was written.
"""

from __future__ import annotations

import base64
import email.utils
import json
import logging
import os
import subprocess
from email.message import EmailMessage

from .crypto import EncryptionError

logger = logging.getLogger("orbit.relay.outbound")

#: Headers the server may hand over readable for an encrypted message. Bcc is
#: deliberately absent: envelope recipients are passed to sendmail instead.
ALLOWED_HEADERS = ("From", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "In-Reply-To", "References", "User-Agent")

#: Exit statuses from <sysexits.h> that mean "try again later".
TEMPORARY_EXIT_CODES = {75, 69, 73}


class Sender:
    """Hands a message to the local MTA."""

    def __init__(self, sendmail_path="/usr/sbin/sendmail", timeout=60.0):
        self.sendmail_path = sendmail_path
        self.timeout = timeout

    def available(self):
        return bool(self.sendmail_path) and os.path.isfile(self.sendmail_path) and os.access(self.sendmail_path, os.X_OK)

    def send(self, envelope_from, recipients, raw):
        """Return ``(status, error)`` where status is sent / deferred / failed."""
        recipients = [r for r in recipients if r and "@" in r and not r.startswith("-")]
        if not recipients:
            return "failed", "No valid recipients."
        if not envelope_from or "@" not in envelope_from or envelope_from.startswith("-"):
            return "failed", "Invalid envelope sender."
        if not self.available():
            return "deferred", f"sendmail is not available at {self.sendmail_path}."

        command = [self.sendmail_path, "-i", "-f", envelope_from, "--", *recipients]
        try:
            completed = subprocess.run(
                command, input=raw, capture_output=True, timeout=self.timeout, check=False
            )
        except subprocess.TimeoutExpired:
            return "deferred", "sendmail timed out."
        except OSError as error:
            return "deferred", f"Could not run sendmail: {error}"

        if completed.returncode == 0:
            return "sent", ""
        detail = (completed.stderr or completed.stdout or b"").decode("utf-8", errors="replace").strip()[:500]
        if completed.returncode in TEMPORARY_EXIT_CODES:
            return "deferred", f"sendmail exit {completed.returncode}: {detail}"
        return "failed", f"sendmail exit {completed.returncode}: {detail}"


def decode_raw(item):
    """The RFC 822 bytes from an outbound claim entry."""
    if "raw_base64" in item:
        return base64.b64decode(item["raw_base64"])
    return (item.get("raw") or "").encode("utf-8", errors="replace")


def build_message(headers, body, attachments=()):
    """Assemble RFC 822 bytes from readable headers and a decrypted body."""
    mime = EmailMessage()
    for name in ALLOWED_HEADERS:
        value = (headers or {}).get(name) or (headers or {}).get(name.lower())
        if value:
            mime[name] = str(value)
    if not mime.get("Date"):
        mime["Date"] = email.utils.formatdate(localtime=False)
    if not mime.get("Message-ID"):
        domain = (str(mime.get("From") or "relay").rpartition("@")[2] or "relay").strip("<> ")
        mime["Message-ID"] = email.utils.make_msgid(domain=domain)
    mime.set_content(body or "", subtype="plain", charset="utf-8")
    for attachment in attachments or ():
        content_type = attachment.get("content_type") or "application/octet-stream"
        maintype, _, subtype = content_type.partition("/")
        try:
            data = base64.b64decode(attachment.get("data_base64") or "")
        except (ValueError, TypeError):
            continue
        mime.add_attachment(
            data,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=(attachment.get("filename") or "attachment")[:255],
        )
    return mime.as_bytes()


def decode_item(item, cipher=None):
    """The bytes to hand to sendmail for one claimed message.

    A plain item is used as it is. An encrypted one is opened with this
    node's key and assembled; EncryptionError is raised when the key is
    missing or does not match, which the caller reports as deferred so a node
    that does hold the key can pick the message up.
    """
    envelope = item.get("encrypted")
    if not envelope:
        return decode_raw(item)
    if cipher is None:
        raise EncryptionError("This node has no encryption key configured.")
    plaintext = cipher.open(envelope, item.get("raw_base64") or item.get("raw") or "")
    fmt = (item.get("format") or "compose").lower()
    if fmt == "mime":
        return plaintext
    try:
        document = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        raise EncryptionError("The decrypted message is not a valid compose document.") from error
    return build_message(item.get("headers") or {}, document.get("body") or "", document.get("attachments") or [])
