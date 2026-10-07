"""Telling a sender that a message will not be delivered.

By the time the agent posts a message to the Orbit Mail server, Postfix has
long told the sending server it was accepted, so a refusal from Orbit Mail
for good (a message over its size limit, a mailbox removed since the tables
were written) reaches nobody upstream on its own. The agent then does what
Postfix does for mail it cannot deliver: it sends the envelope sender a
delivery status notification (RFC 3464) from MAILER-DAEMON, under the null
envelope sender so that it can never bounce back itself. The message is kept
in ``dead/`` as well, for the operator.

The message itself was sealed before it was queued, so the notification
returns its readable header block only, which is what most mail servers
return anyway.
"""

from __future__ import annotations

import email.utils
from datetime import datetime, timezone
from email.message import Message
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#: Enhanced status codes (RFC 3463) for the server's refusals, by its ``code``
#: or else by HTTP status.
STATUS_BY_CODE = {"too_large": "5.3.4", "no_mailbox": "5.1.1", "forbidden": "5.7.1"}
STATUS_BY_HTTP = {413: "5.3.4", 422: "5.1.1", 403: "5.7.1"}
#: A message the relay stopped retrying (ORBIT_MAX_RETRY_HOURS).
EXPIRED = "4.4.7"

#: What the sender reads, by enhanced status code.
EXPLANATIONS = {
    "5.3.4": "It is larger than the recipient's mail system accepts.",
    "5.1.1": "The recipient's mailbox does not exist.",
    "5.7.1": "This mail system may not deliver to that mailbox.",
    EXPIRED: "The recipient's mail system could not take it before the time for delivering it ran out.",
}
DEFAULT_EXPLANATION = "The recipient's mail system refused it."


def should_bounce(envelope_from):
    """Whether a message from ``envelope_from`` may be bounced.

    Never to the null sender (a bounce itself) or to a mailer daemon, which
    is how bounce loops start.
    """
    sender = (envelope_from or "").strip().strip("<>")
    if not sender or "@" not in sender or sender.startswith("-"):
        return False
    return sender.rpartition("@")[0].lower() != "mailer-daemon"


def status_for(error):
    """The enhanced status code for a permanent refusal from the server."""
    code = getattr(error, "code", None)
    if code in STATUS_BY_CODE:
        return STATUS_BY_CODE[code]
    return STATUS_BY_HTTP.get(getattr(error, "status", None), "5.0.0")


def _text(body, subtype):
    part = MIMEText(body, subtype, "us-ascii" if body.isascii() else "utf-8")
    del part["MIME-Version"]
    return part


def _header_block(headers):
    """The readable headers as returned: LF line ends, no mbox ``From `` line."""
    lines = (headers or "").replace("\r\n", "\n").split("\n")
    if lines and lines[0].startswith("From ") and ":" not in lines[0].split(" ", 1)[0]:
        lines = lines[1:]
    return "\n".join(lines).strip("\n") + "\n"


def _arrival(received_at):
    try:
        moment = datetime.fromisoformat(received_at)
    except (TypeError, ValueError):
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return email.utils.format_datetime(moment)


def build(message, diagnostic, *, status="5.0.0", hostname="relay"):
    """The notification for one queued message as RFC 822 bytes.

    ``message`` is the :class:`~relay.queue.QueuedMessage` that will not be
    delivered; ``diagnostic`` is the server's answer.
    """
    hostname = hostname or "relay"
    recipient = message.recipient or "unknown"
    # Header values: one line each, whatever the server's answer held.
    diagnostic = " ".join(str(diagnostic or "").split())[:500]
    explanation = EXPLANATIONS.get(status, DEFAULT_EXPLANATION)

    report = MIMEMultipart("report", report_type="delivery-status")
    report["From"] = f"Mail Delivery System <MAILER-DAEMON@{hostname}>"
    report["To"] = " ".join((message.envelope_from or "").split())
    report["Subject"] = "Undelivered Mail Returned to Sender"
    report["Date"] = email.utils.formatdate(usegmt=True)
    report["Message-ID"] = email.utils.make_msgid(domain=hostname)
    report["Auto-Submitted"] = "auto-replied"

    report.attach(_text(
        f"This is the mail system at host {hostname}.\n\n"
        f"Your message to {recipient} could not be delivered. {explanation}\n\n"
        "It will not be tried again. The headers of your message are attached.\n\n"
        f"<{recipient}>: {diagnostic}\n",
        "plain",
    ))

    per_message = Message()
    per_message["Reporting-MTA"] = f"dns; {hostname}"
    per_message["X-Orbit-Queue-ID"] = message.id
    arrival = _arrival(message.received_at)
    if arrival:
        per_message["Arrival-Date"] = arrival
    per_recipient = Message()
    per_recipient["Final-Recipient"] = f"rfc822; {recipient}"
    per_recipient["Action"] = "failed"
    per_recipient["Status"] = status
    per_recipient["Diagnostic-Code"] = f"X-Orbit-Mail; {diagnostic}"
    delivery_status = MIMEBase("message", "delivery-status")
    del delivery_status["MIME-Version"]
    delivery_status.set_payload([per_message, per_recipient])
    report.attach(delivery_status)

    report.attach(_text(_header_block(message.headers), "rfc822-headers"))
    return report.as_bytes()
