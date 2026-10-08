"""The relay agent's runtime.

Three loops, deliberately separated by thread:

* **Delivery worker** drains the durable queue of inbound mail to the Orbit
  Mail server. This is the thread whose failure would mean mail loss, so it
  never gives up and never crashes on a single bad message.
* **Control loop** heartbeats on an interval and applies the fleet
  configuration (domains, addresses) to Postfix.
* **Outbound worker** claims outgoing mail from the server and hands it to
  Postfix through sendmail, reporting each result.

Why threads and not processes: the queue is on disk and every operation on it
is an atomic rename, so correctness does not depend on there being one process.
Threads are simply cheaper to supervise here.
"""

from __future__ import annotations

import copy
import logging
import os
import signal
import socket
import threading
import time
import urllib.request

from . import bounce
from .config import load_config
from .crypto import EncryptionError, load_cipher
from .health import CRITICAL, OK, Dropouts, HealthChecker, Streak, failing, report, result
from .keys import PublicKeyDirectory
from .outbound import Sender, decode_item
from .postfix import Maildrop
from .postfix_config import PostfixTables
from .queue import Queue
from .transport import MailServerClient, PermanentError, RetryableError

logger = logging.getLogger("orbit.relay")

#: How often the delivery worker wakes to look for due messages.
POLL_INTERVAL = 1.0


class RelayAgent:
    def __init__(self, config=None, server=None, sender=None, tables=None, cipher=None, keys=None):
        self.config = config or load_config()
        from .logging_setup import setup_logging

        setup_logging(
            level=self.config.log_level,
            backend=self.config.log_backend,
            max_entries=self.config.log_max_entries,
            path=self.config.log_path,
        )

        self.queue = Queue(
            self.config.queue_dir,
            max_attempts=self.config.max_attempts,
            max_age_hours=self.config.max_retry_hours,
            backoff_base=self.config.backoff_base,
            backoff_max=self.config.backoff_max,
            backoff_jitter=self.config.backoff_jitter,
        )
        self.queue.on_exhausted = self.expired
        self.queue.ensure_dirs()

        # Raises EncryptionError when the node has no key: there is no
        # readable mode, so the agent cannot be built without one.
        self.cipher = cipher or load_cipher(self.config)
        self.server = server or MailServerClient(self.config)
        self.keys = keys or PublicKeyDirectory(
            self.server, os.path.join(self.config.state_dir, "keys"),
            ttl=self.config.key_cache_seconds, missing_ttl=self.config.missing_key_cache_seconds,
        )
        self.maildrop = Maildrop(self.config.maildrop_dir, self.queue, self.config.node_name, keys=self.keys)
        self.sender = sender or Sender(self.config.sendmail_path)
        self.tables = tables or PostfixTables(self.config.postfix_dir, db_type=self.config.postfix_db_type)
        self.checker = HealthChecker(self.config, self.queue, self.sender, self.tables)

        self._stop = threading.Event()
        self._threads = []
        self._lock = threading.Lock()

        self.started_at = time.time()
        self.config_digest = ""
        self.domains = []
        self.recipient_count = 0
        self.accepting_mail = True
        self.peers = []
        self.server_reachable = False
        self.heartbeat_interval = max(10, self.config.heartbeat_interval)
        self.outbound_poll_interval = max(1, self.config.outbound_poll_interval)
        self.stats = {
            "delivered": 0,
            "failed": 0,
            "parked": 0,
            "bounced": 0,
            "sent": 0,
            "send_failed": 0,
            "last_error": "",
            "last_heartbeat": None,
        }
        # Runs of failures the health checks report (relay/health.py), and
        # the checks' last result, which /health serves.
        self.delivery_failures = Streak()
        self.sending_failures = Streak()
        self.heartbeat_failures = Streak()
        # Requests to the server that got no answer at all, from any thread.
        self.dropouts = Dropouts()
        self.tables_error = ""
        self.health = None

    # --- Lifecycle --------------------------------------------------------

    def run(self):
        """Start every thread and block until asked to stop."""
        problems = self.config.validate()
        if problems:
            for problem in problems:
                logger.error("Configuration problem: %s", problem)
            raise SystemExit(1)

        logger.info("Orbit relay %s starting as %s -> %s", _version(), self.config.node_name, self.config.server_url)

        recovered = self.queue.recover_inflight()
        if recovered:
            logger.warning("Recovered %d message(s) left in flight by a previous run.", len(recovered))
        if not self.config.has_api_key:
            logger.warning("ORBIT_RELAY_API_KEY is not set; mail will queue locally until it is.")
        logger.info("Inbound mail is sealed to each reader's key; this node's own key is %s.", self.cipher.kid)

        self._install_signal_handlers()
        self._start("orbit-relay-deliver", self._delivery_loop)
        self._start("orbit-relay-control", self._control_loop)
        self._start("orbit-relay-outbound", self._outbound_loop)

        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            self._stop.set()

        logger.info("Shutting down; waiting for workers to finish.")
        for thread in self._threads:
            thread.join(timeout=15)
        logger.info("Stopped.")
        return 0

    def stop(self):
        self._stop.set()

    def _install_signal_handlers(self):
        def stop(signum, _frame):
            logger.info("Received signal %s; shutting down.", signum)
            self._stop.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, stop)
            except ValueError:
                pass

    def _start(self, name, target):
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    # --- Inbound delivery --------------------------------------------------

    def _delivery_loop(self):
        while not self._stop.is_set():
            try:
                batch = self.queue.due(limit=25)
            except Exception:
                logger.exception("Failed to read the queue.")
                self._stop.wait(2.0)
                continue
            if not batch:
                self._stop.wait(POLL_INTERVAL)
                continue
            for message in batch:
                if self._stop.is_set():
                    return
                try:
                    self.deliver_one(message)
                except Exception:
                    logger.exception("Unexpected error delivering %s", message.id)
                    try:
                        self.queue.requeue(message, "internal error")
                    except Exception:
                        # A full disk, say. Raising here would end this thread
                        # while the agent kept running; the message is retried
                        # from where it is, at the latest after a restart.
                        logger.exception("Could not requeue %s", message.id)
                    with self._lock:
                        self.stats["failed"] += 1
                        self.delivery_failures.failed("internal error")

    def deliver_one(self, message):
        if not self.queue.mark_inflight(message):
            return
        try:
            result = self.server.deliver(message)
        except RetryableError as error:
            logger.warning("Retry %d for %s -> %s: %s", message.attempts + 1, message.id, message.recipient, error)
            self.queue.requeue(message, str(error))
            with self._lock:
                self.stats["failed"] += 1
                self.stats["last_error"] = str(error)
                self.delivery_failures.failed(error)
                if not error.answered:
                    self.dropouts.failed(error)
            return
        except PermanentError as error:
            # Postfix accepted this long ago, so the sender hears of the
            # refusal from here or not at all. The message is kept as well.
            outcome = self.notify_sender(message, error)
            logger.error("Rejecting %s -> %s: %s (%s)", message.id, message.recipient, error, outcome)
            self.queue.move_to_dead(message, f"{error}; {outcome}")
            with self._lock:
                self.stats["parked"] += 1
                self.stats["last_error"] = str(error)
                # The server answered: the message was the problem, not the path.
                self.delivery_failures.succeeded()
            return
        self.queue.complete(message)
        with self._lock:
            self.stats["delivered"] += 1
            self.delivery_failures.succeeded()
        logger.info("Delivered %s -> %s (thread %s)", message.id, message.recipient, (result or {}).get("thread_id", "-"))

    def notify_sender(self, message, error, status=None):
        """Send the sender a delivery status notification for a message the
        server refused for good. Returns what happened, in a few words."""
        if not bounce.should_bounce(message.envelope_from):
            return "not bounced: no sender to tell"
        status = status or bounce.status_for(error)
        raw = bounce.build(message, str(error), status=status, hostname=self.config.hostname)
        status, detail = self.sender.bounce(message.envelope_from, raw)
        if status != "sent":
            logger.error("Could not bounce %s to %s: %s", message.id, message.envelope_from, detail)
            return f"bounce not sent: {detail}"
        with self._lock:
            self.stats["bounced"] += 1
        return f"bounced to {message.envelope_from}"

    def expired(self, message):
        """A message that ran out of retries: its sender hears, as Postfix
        would tell them. Never raises; the message is parked either way."""
        try:
            return self.notify_sender(message, message.last_error or "retries exhausted", status=bounce.EXPIRED)
        except Exception:
            logger.exception("Could not bounce expired %s", message.id)
            return "bounce not sent"

    # --- Control loop -----------------------------------------------------

    def _control_loop(self):
        # A short delay lets Postfix finish starting and the network settle.
        if self._stop.wait(3.0):
            return
        while not self._stop.is_set():
            try:
                self.heartbeat()
            except RetryableError as error:
                logger.warning("Heartbeat failed: %s", error)
                self.server_reachable = False
                with self._lock:
                    self.heartbeat_failures.failed(error)
                    if not error.answered:
                        self.dropouts.failed(error)
            except PermanentError as error:
                logger.error("Heartbeat rejected: %s", error)
                self.server_reachable = False
                with self._lock:
                    self.heartbeat_failures.failed(error)
            except Exception:
                logger.exception("Unexpected error during heartbeat.")
            if self._stop.wait(self.heartbeat_interval):
                return

    def status_report(self):
        """What the node tells the server about itself."""
        queue_stats = self.queue.stats()
        with self._lock:
            last_error = self.stats["last_error"]
        return {
            "node": self.config.node_name,
            "hostname": self.config.hostname,
            "public_ip": _public_ip(),
            "version": _version(),
            "queue": queue_stats,
            "last_error": last_error,
            "accepting_mail": self.config.accepting_mail,
            "encryption_kid": self.cipher.kid,
            "encryption_public_key": self.cipher.public_key_text,
            "health": self.check_health(),
        }

    def check_health(self):
        """Run the node's checks (``relay/health.py``) and keep the result for ``/health``."""
        with self._lock:
            delivery = copy.copy(self.delivery_failures)
            sending = copy.copy(self.sending_failures)
            dropouts = copy.deepcopy(self.dropouts)
        self.health = report(self.checker.run(delivery=delivery, dropouts=dropouts, sending=sending, tables_error=self.tables_error))
        return self.health

    def local_health(self):
        """What ``/health`` answers: the last checks, the agent's own threads,
        and whether it reaches the server, which the heartbeat cannot report."""
        last = self.health or self.check_health()
        with self._lock:
            heartbeat = copy.copy(self.heartbeat_failures)
        checks = list(last["checks"]) + [self._workers_check(), self._server_check(heartbeat)]
        return dict(report(checks), checked_at=last["checked_at"])

    def _workers_check(self):
        stopped = [thread.name for thread in self._threads if not thread.is_alive()]
        if stopped and not self._stop.is_set():
            return result("workers", CRITICAL, f"{', '.join(stopped)} stopped; restart the service (systemctl restart orbit-relay).")
        return result("workers", OK, "Delivering, heartbeating and sending." if self._threads else "Starting.")

    def _server_check(self, streak):
        if not self.config.has_api_key:
            return result("server", CRITICAL, "ORBIT_RELAY_API_KEY is not set, so mail queues here and nothing is sent.")
        return failing("server", streak, "reaching Orbit Mail")

    def heartbeat(self):
        """Report liveness and apply any configuration the server sends."""
        payload = self.server.heartbeat(self.status_report(), config_digest=self.config_digest)
        self.server_reachable = True
        with self._lock:
            self.stats["last_heartbeat"] = time.time()
            self.heartbeat_failures.succeeded()
        self.apply_config(payload)
        return payload

    def apply_config(self, payload):
        if not payload:
            return
        self.peers = payload.get("peers", [])
        self.accepting_mail = bool(payload.get("accepting_mail", True)) and self.config.accepting_mail
        self.heartbeat_interval = max(10, int(payload.get("heartbeat_interval") or self.config.heartbeat_interval))
        self.outbound_poll_interval = max(1, int(payload.get("outbound_poll_interval") or self.config.outbound_poll_interval))
        if "domains" in payload:
            previous = self.recipient_count
            self.domains = list(payload.get("domains") or [])
            self.recipient_count = len(payload.get("recipients") or []) + len(payload.get("catch_all_domains") or [])
            if self.recipient_count != previous:
                logger.info("Deliverable addresses: %d -> %d across %d domain(s)", previous, self.recipient_count, len(self.domains))
        try:
            # The receive hook defers mail while the switch is off; it reads
            # what is written here (``postfix_config.accepting_mail``).
            self.tables.apply(payload, accepting=self.accepting_mail)
        except Exception as error:
            # The old digest stays, so the next heartbeat is sent the full
            # lists again instead of being told nothing changed.
            logger.exception("Could not update the Postfix tables.")
            self.tables_error = str(error)[:300] or type(error).__name__
            return
        self.tables_error = ""
        self.config_digest = payload.get("config_digest", self.config_digest)

    # --- Outbound ---------------------------------------------------------

    def _outbound_loop(self):
        if self._stop.wait(5.0):
            return
        while not self._stop.is_set():
            handled = 0
            try:
                handled = self.send_batch()
            except RetryableError as error:
                logger.warning("Outbound poll failed: %s", error)
                if not error.answered:
                    with self._lock:
                        self.dropouts.failed(error)
            except PermanentError as error:
                logger.error("Outbound poll rejected: %s", error)
            except Exception:
                logger.exception("Unexpected error sending outbound mail.")
            # Keep going immediately while there is more to send; otherwise
            # back off to the poll interval.
            if handled == 0 and self._stop.wait(self.outbound_poll_interval):
                return

    def send_batch(self):
        """Claim and send one batch. Returns the number of messages handled.

        A deferred message goes straight back on the server's queue, so it
        does not count: a batch that was all deferred makes the loop wait
        before claiming again rather than claim the same messages at once.
        """
        if not self.config.has_api_key:
            return 0
        payload = self.server.claim_outbound(limit=self.config.outbound_batch, encryption_kid=self.cipher.kid)
        items = payload.get("messages") or []
        handled = 0
        for item in items:
            if self._stop.is_set():
                break
            if self.send_one(item) != "deferred":
                handled += 1
        return handled

    def send_one(self, item):
        outbound_id = item.get("id")
        try:
            raw = decode_item(item, self.cipher)
        except EncryptionError as problem:
            # Another node may hold the right key; the claim lapses and the
            # server offers the message again.
            status, error = "deferred", str(problem)
            raw = None
        except Exception as problem:
            # A message that cannot be assembled (a header with a line break
            # in it, say) never will be. Raising would leave the rest of the
            # batch claimed and unsent, to be claimed again beside this one.
            status, error = "failed", f"Could not assemble the message: {problem}"
            raw = None
        if raw is not None:
            status, error = self.sender.send(item.get("envelope_from", ""), item.get("recipients") or [], raw)
        with self._lock:
            if status == "sent":
                self.stats["sent"] += 1
            else:
                self.stats["send_failed"] += 1
                self.stats["last_error"] = error
            if raw is not None:
                # Only sendmail's answer says whether the way out works; a
                # message this node cannot open says nothing about it.
                if status == "deferred":
                    self.sending_failures.failed(error)
                else:
                    self.sending_failures.succeeded()
        if status == "sent":
            logger.info("Sent %s from %s to %s", outbound_id, item.get("envelope_from"), ", ".join(item.get("recipients") or []))
        else:
            logger.warning("Outbound %s %s: %s", outbound_id, status, error)
        try:
            self.server.report_outbound(outbound_id, status, error)
        except (RetryableError, PermanentError) as report_error:
            # The claim expires on the server side, so an unreported "sent"
            # could be re-sent later. Log loudly; this is the one duplicate
            # path in the design and it needs the server to be unreachable at
            # exactly this moment.
            logger.error("Could not report result for %s (%s): %s", outbound_id, status, report_error)
        return status

    # --- Status -----------------------------------------------------------

    def status(self):
        with self._lock:
            snapshot = dict(self.stats)
            peers = list(self.peers)
        return {
            "node": self.config.node_name,
            "hostname": self.config.hostname,
            "version": _version(),
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "server": self.config.server_url,
            "server_reachable": self.server_reachable,
            "has_api_key": self.config.has_api_key,
            "accepting_mail": self.accepting_mail,
            "encryption": {"enabled": True, "kid": self.cipher.kid, "public_key": self.cipher.public_key_text},
            "queue": self.queue.stats(),
            "queue_bytes": self.queue.total_bytes(),
            "domains": self.domains,
            "deliverable_addresses": self.recipient_count,
            "peers": peers,
            "stats": snapshot,
            "health": self.health,
        }


def _version():
    from . import __version__

    return __version__


_public_ip_cache = {"value": None, "at": 0.0}


def _public_ip():
    """This node's public address, cached for an hour; best effort only."""
    now = time.time()
    if _public_ip_cache["value"] is not None and now - _public_ip_cache["at"] < 3600:
        return _public_ip_cache["value"]
    value = os.environ.get("ORBIT_RELAY_PUBLIC_IP", "")
    if not value:
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=3) as response:
                value = response.read().decode("ascii", errors="ignore").strip()[:45]
        except Exception:
            try:
                value = socket.gethostbyname(socket.gethostname())
            except OSError:
                value = ""
    _public_ip_cache.update(value=value, at=now)
    return value
