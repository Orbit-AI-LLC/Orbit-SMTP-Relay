"""What the node checks about itself.

Before every heartbeat the agent looks at the parts of the node a heartbeat
alone does not show, and sends what it found with it (``health`` in the
heartbeat body). Orbit Mail keeps it on the node's row and passes the fleet's
to Mission Control, which warns its super admins when a node is down or one
of these goes wrong.

Each check is ``{check, label, status, detail}``, ``status`` being ``ok``,
``warning`` or ``critical``; the node's status is the worst of them.

``smtp``           Postfix answers on port 25 with a 220 greeting
``tls``            it offers STARTTLS, and its certificate has not expired or is not about to
``postfix_queue``  Postfix's own queue: outgoing mail it cannot hand to the internet (port 25
                   blocked, a blocklisted address), and inbound mail the receive hook deferred
``delivery``       inbound mail reaching Orbit Mail, from the delivery worker's run of failures
``sending``        outgoing mail reaching Postfix through sendmail
``tables``         the domain and address tables Postfix accepts mail by were written
``disk``           free space where the queue lives
``parked``         messages the server refused for good in the last day
``sender_checks``  the libraries SPF, DKIM and DMARC need
``paused``         the operator's switch (``ORBIT_ACCEPTING_MAIL=0``)

The agent adds ``workers`` and ``server`` for the local endpoint (``/health``)
and ``orbit-relay health``, which are what an operator watching the host from
the inside needs too. A check never raises: one that cannot run says so.
"""

from __future__ import annotations

import json
import os
import shutil
import smtplib
import socket
import ssl
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone

OK, WARNING, CRITICAL = "ok", "warning", "critical"
_RANK = {OK: 0, WARNING: 1, CRITICAL: 2}

#: The SMTP probe's timeout, seconds.
SMTP_TIMEOUT = 5.0
#: Warn this many days before the STARTTLS certificate expires.
CERTIFICATE_WARNING_DAYS = 14
#: Messages deferred in Postfix's queue before it is a warning, and critical.
DEFERRED_WARNING = 20
DEFERRED_CRITICAL = 200
POSTQUEUE_TIMEOUT = 20.0
#: How long delivery or sending may keep failing before it is a warning, and critical.
FAILING_WARNING_SECONDS = 10 * 60
FAILING_CRITICAL_SECONDS = 60 * 60
#: Free space on the queue's filesystem is low when it is under both a share
#: of the disk and a size (a large disk with a small share free still has
#: room for plenty of mail), or under the floor whatever the disk.
DISK_WARNING = (0.10, 5 * 1024**3)
DISK_CRITICAL = (0.05, 1024**3)
DISK_FLOOR = 256 * 1024**2
#: Messages parked in a day before it is a warning.
PARKED_WARNING = 10
PARKED_WINDOW_SECONDS = 24 * 3600

LABELS = {
    "smtp": "SMTP",
    "tls": "TLS certificate",
    "postfix_queue": "Postfix queue",
    "delivery": "Delivery to Orbit Mail",
    "sending": "Sending",
    "tables": "Postfix tables",
    "disk": "Disk space",
    "parked": "Parked mail",
    "sender_checks": "Sender checks",
    "paused": "Accepting mail",
    "workers": "Workers",
    "server": "Orbit Mail",
    "agent": "Agent",
}


def result(check, status, detail):
    return {"check": check, "label": LABELS.get(check, check), "status": status, "detail": detail}


def worst(checks):
    """The node's status: the worst of its checks."""
    return max((c["status"] for c in checks), key=_RANK.get, default=OK)


def report(checks):
    return {
        "status": worst(checks),
        "checks": checks,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _plural(count, noun):
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _duration(seconds):
    minutes = int(seconds // 60)
    if minutes < 60:
        return _plural(max(minutes, 1), "minute")
    hours = minutes // 60
    if hours < 48:
        return _plural(hours, "hour")
    return _plural(hours // 24, "day")


class Streak:
    """A run of failures with no success in between: since when, and the last error.

    The agent keeps one for delivery, one for sending and one for its
    heartbeat; one failure among successes is retried and forgotten, a run
    of them is what a check reports.
    """

    def __init__(self):
        self.since = None
        self.count = 0
        self.error = ""

    def failed(self, error, now=None):
        if self.since is None:
            self.since = now if now is not None else time.time()
        self.count += 1
        self.error = str(error or "")[:300]

    def succeeded(self):
        self.since = None
        self.count = 0
        self.error = ""

    def seconds(self, now=None):
        if self.since is None:
            return 0.0
        return (now if now is not None else time.time()) - self.since


def failing(check, streak, what, now=None):
    """A check from a ``Streak``: fine until it has failed for ten minutes."""
    seconds = streak.seconds(now)
    if streak.since is None:
        return result(check, OK, f"{what.capitalize()} is working.")
    detail = f"{what.capitalize()} has failed for {_duration(seconds)} ({_plural(streak.count, 'attempt')}): {streak.error}"
    if seconds >= FAILING_CRITICAL_SECONDS:
        return result(check, CRITICAL, detail)
    if seconds >= FAILING_WARNING_SECONDS:
        return result(check, WARNING, detail)
    return result(check, OK, f"{what.capitalize()} failing for {_duration(seconds)}, retrying: {streak.error}")


class HealthChecker:
    """The checks that look at the host rather than the agent's own state.

    ``smtp`` (a factory like ``smtplib.SMTP``) and ``run`` (like
    ``subprocess.run``) are there so the tests need neither Postfix nor a
    socket.
    """

    def __init__(self, config, queue, sender=None, tables=None, smtp=smtplib.SMTP, run=subprocess.run,
                 postqueue_path="postqueue"):
        self.config = config
        self.queue = queue
        self.sender = sender
        self.tables = tables
        self.smtp = smtp
        self.run_command = run
        self.postqueue_path = postqueue_path

    def run(self, *, delivery=None, sending=None, tables_error="", now=None):
        """Every check, in the order they are listed above."""
        now = now if now is not None else time.time()
        checks = []
        for step in (
            self.check_smtp,
            self.check_postfix_queue,
            lambda: [failing("delivery", delivery, "delivery to Orbit Mail", now)] if delivery else [],
            lambda: self.check_sending(sending, now),
            lambda: self.check_tables(tables_error),
            self.check_disk,
            lambda: self.check_parked(now),
            self.check_sender_libraries,
            self.check_paused,
        ):
            try:
                checks.extend(step())
            except Exception as error:  # a check must never stop the heartbeat
                checks.append(result("agent", WARNING, f"A health check could not run: {error}"))
        return checks

    # --- Postfix ----------------------------------------------------------

    def check_smtp(self):
        """Postfix's greeting on port 25, and the certificate it offers for STARTTLS."""
        port = self.config.health_smtp_port
        if not port:
            return []
        host = "127.0.0.1"
        try:
            with self.smtp(host, port, timeout=SMTP_TIMEOUT) as client:
                checks = [result("smtp", OK, f"Postfix answers on port {port}.")]
                client.ehlo()
                if not client.has_extn("starttls"):
                    checks.append(result("tls", WARNING, "Postfix does not offer STARTTLS, so mail reaches this node unencrypted."))
                    return checks
                context = ssl.create_default_context()
                # Whether the certificate is trusted is the sender's business;
                # this only reads its dates.
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    client.starttls(context=context)
                except (smtplib.SMTPException, ssl.SSLError, OSError) as error:
                    checks.append(result("tls", CRITICAL, f"STARTTLS fails: {error}"))
                    return checks
                checks.append(certificate_check(client.sock.getpeercert(binary_form=True)))
                return checks
        except (smtplib.SMTPException, OSError) as error:
            return [result("smtp", CRITICAL, f"Postfix is not answering on port {port}: {str(error) or type(error).__name__}")]

    def check_postfix_queue(self):
        """Postfix's deferred mail, split into outgoing and inbound."""
        path = shutil.which(self.postqueue_path)
        if not self.config.postfix_dir or not path:
            return []
        try:
            completed = self.run_command([path, "-j"], capture_output=True, timeout=POSTQUEUE_TIMEOUT, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            return [result("postfix_queue", WARNING, f"Could not read Postfix's queue: {error}")]
        if completed.returncode != 0:
            detail = (completed.stderr or b"").decode("utf-8", "replace").strip()[:200]
            return [result("postfix_queue", WARNING, f"Could not read Postfix's queue: {detail or completed.returncode}")]
        return [postfix_queue_check(completed.stdout, self._our_domains())]

    def _our_domains(self):
        """The domains this node accepts mail for, from the table Postfix reads."""
        if self.tables is None or not self.tables.enabled:
            return set()
        try:
            with open(self.tables.paths()["domains"], encoding="utf-8") as handle:
                return {line.split()[0].lower() for line in handle if line.strip()}
        except OSError:
            return set()

    def check_sending(self, streak, now):
        if self.sender is not None and not self.sender.available():
            return [result("sending", CRITICAL, f"sendmail is missing at {self.sender.sendmail_path}, so no outgoing mail can be sent.")]
        if streak is None:
            return []
        return [failing("sending", streak, "handing outgoing mail to Postfix", now)]

    def check_tables(self, error):
        if self.tables is None or not self.tables.enabled:
            return []
        if error:
            return [result("tables", WARNING, f"Could not update the tables Postfix accepts mail by, so changed addresses are not picked up: {error}")]
        return [result("tables", OK, "Up to date.")]

    # --- The host ---------------------------------------------------------

    def check_disk(self):
        path = self.config.queue_dir
        while path and not os.path.exists(path):
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        usage = shutil.disk_usage(path or "/")
        free_share = usage.free / usage.total if usage.total else 1.0
        detail = f"{usage.free / 1024**3:.1f} GB free of {usage.total / 1024**3:.1f} GB ({free_share:.0%}) where the queue is."
        if usage.free < DISK_FLOOR or (free_share < DISK_CRITICAL[0] and usage.free < DISK_CRITICAL[1]):
            return [result("disk", CRITICAL, detail + " Postfix stops accepting mail when it runs out.")]
        if free_share < DISK_WARNING[0] and usage.free < DISK_WARNING[1]:
            return [result("disk", WARNING, detail)]
        return [result("disk", OK, detail)]

    def check_parked(self, now):
        count = self.queue.dead_since(now - PARKED_WINDOW_SECONDS)
        total = self.queue.stats()["dead"]
        detail = f"{_plural(count, 'message')} parked in the last day, {total} in all."
        if count >= PARKED_WARNING:
            return [result("parked", WARNING, detail + " `orbit-relay dead` shows why.")]
        return [result("parked", OK, detail)]

    def check_sender_libraries(self):
        try:
            import dkim  # noqa: F401
            import dns.resolver  # noqa: F401
            import spf  # noqa: F401
        except ImportError as error:
            return [result("sender_checks", WARNING, f"Off: {error.name} is missing, so mail arrives without SPF, DKIM or DMARC results. Re-run the installer.")]
        return [result("sender_checks", OK, "SPF, DKIM and DMARC are checked.")]

    def check_paused(self):
        if not self.config.accepting_mail:
            return [result("paused", WARNING, "Paused on this node (ORBIT_ACCEPTING_MAIL=0): inbound mail waits in Postfix's queue.")]
        if self.tables is not None and self.tables.enabled and not self.tables.accepting_flag():
            return [result("paused", OK, "Paused by Mission Control's switch for the whole fleet.")]
        return [result("paused", OK, "Accepting mail.")]


def certificate_check(der, now=None):
    """The ``tls`` check for the certificate Postfix presented."""
    from cryptography import x509

    try:
        certificate = x509.load_der_x509_certificate(der)
    except (ValueError, TypeError) as error:
        return result("tls", WARNING, f"Could not read the certificate Postfix presents: {error}")
    expires = getattr(certificate, "not_valid_after_utc", None)
    if expires is None:  # cryptography before 42, as Debian 12 ships
        expires = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    days = (expires - now).total_seconds() / 86400
    when = expires.strftime("%Y-%m-%d")
    if days < 0:
        return result("tls", CRITICAL, f"The certificate Postfix presents expired on {when}; senders that check it refuse to deliver.")
    if days < CERTIFICATE_WARNING_DAYS:
        return result("tls", WARNING, f"The certificate Postfix presents expires on {when}, in {_plural(int(days), 'day')}. Renew it and run `systemctl reload postfix`.")
    return result("tls", OK, f"Certificate valid until {when}.")


def postfix_queue_check(output, our_domains):
    """The ``postfix_queue`` check from ``postqueue -j``: one JSON object per line."""
    outgoing = inbound = 0
    reasons = Counter()
    for line in (output or b"").decode("utf-8", "replace").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("queue_name") != "deferred":
            continue
        recipients = entry.get("recipients") or []
        domains = {str(r.get("address", "")).rpartition("@")[2].lower() for r in recipients}
        if domains and domains <= our_domains:
            inbound += 1
            continue
        outgoing += 1
        for recipient in recipients:
            reason = str(recipient.get("delay_reason") or "").strip()
            if reason:
                reasons[reason[:160]] += 1
    count = max(outgoing, inbound)
    parts = []
    if outgoing:
        parts.append(f"{_plural(outgoing, 'outgoing message')} deferred")
    if inbound:
        parts.append(f"{_plural(inbound, 'inbound message')} the agent deferred (waiting for a reader's key, or paused)")
    if not parts:
        return result("postfix_queue", OK, "Nothing deferred.")
    detail = "; ".join(parts) + "."
    if reasons:
        detail += f" Most often: {reasons.most_common(1)[0][0]}"
    if count >= DEFERRED_CRITICAL:
        return result("postfix_queue", CRITICAL, detail)
    if count >= DEFERRED_WARNING:
        return result("postfix_queue", WARNING, detail)
    return result("postfix_queue", OK, detail)


def ask_agent(address, port, timeout=3.0):
    """The running agent's ``/health``, or None when nothing answers."""
    import urllib.error
    import urllib.request

    host = f"[{address}]" if ":" in address else address
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        # 503 is the agent answering that something is critical.
        try:
            return json.loads(error.read().decode("utf-8"))
        except ValueError:
            return None
    except (OSError, ValueError, socket.timeout):
        return None
