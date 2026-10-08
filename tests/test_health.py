"""The node's health checks (relay/health.py) and where they go.

Postfix, the network and the disk are stood in for: the checks are tested on
what they make of each answer, and the agent on carrying their result in its
heartbeat and on ``/health``.
"""

import contextlib
import io
import json
import os
import smtplib
import ssl
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from unittest import mock

from relay import health
from relay.health import CRITICAL, OK, WARNING, HealthChecker, Streak, certificate_check, failing, postfix_queue_check
from relay.queue import Queue, QueuedMessage

from test_end_to_end import FakeSendmail, ScriptedServer, make_config


def make_certificate(not_after):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay.example.com")])
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - timedelta(days=90)).not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def fake_smtp(refuse=None, starttls=True, starttls_error=None, der=b""):
    """A stand-in for ``smtplib.SMTP`` that answers as told."""

    class Client:
        def __init__(self, host, port, timeout=None):
            if refuse is not None:
                raise refuse
            self.sock = mock.Mock()
            self.sock.getpeercert.return_value = der

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def ehlo(self):
            return 250, b"ok"

        def has_extn(self, name):
            return starttls and name == "starttls"

        def starttls(self, context=None):
            if starttls_error is not None:
                raise starttls_error

    return Client


def by_check(checks):
    return {c["check"]: c for c in checks}


class CheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.queue = Queue(os.path.join(self._tmp.name, "queue"))
        self.queue.ensure_dirs()

    def tearDown(self):
        self._tmp.cleanup()

    def checker(self, **config):
        values = dict(queue_dir=self.queue.root, health_smtp_port=25)
        values.update(config)
        return HealthChecker(make_config(**values), self.queue)

    # --- SMTP and TLS -----------------------------------------------------

    def test_postfix_not_answering_is_critical(self):
        checker = self.checker()
        checker.smtp = fake_smtp(refuse=ConnectionRefusedError(111, "Connection refused"))
        (check,) = checker.check_smtp()
        self.assertEqual((check["check"], check["status"]), ("smtp", CRITICAL))
        self.assertIn("Connection refused", check["detail"])

    def test_a_timeout_names_itself(self):
        checker = self.checker()
        checker.smtp = fake_smtp(refuse=TimeoutError())
        self.assertIn("TimeoutError", checker.check_smtp()[0]["detail"])

    def test_a_greeting_other_than_220_is_critical(self):
        checker = self.checker()
        checker.smtp = fake_smtp(refuse=smtplib.SMTPConnectError(554, b"No SMTP service here"))
        self.assertEqual(checker.check_smtp()[0]["status"], CRITICAL)

    def test_a_valid_certificate_is_healthy(self):
        checker = self.checker()
        checker.smtp = fake_smtp(der=make_certificate(datetime.now(timezone.utc) + timedelta(days=60)))
        checks = by_check(checker.check_smtp())
        self.assertEqual(checks["smtp"]["status"], OK)
        self.assertEqual(checks["tls"]["status"], OK)

    def test_no_starttls_is_a_warning(self):
        checker = self.checker()
        checker.smtp = fake_smtp(starttls=False)
        self.assertEqual(by_check(checker.check_smtp())["tls"]["status"], WARNING)

    def test_a_failing_starttls_is_critical(self):
        checker = self.checker()
        checker.smtp = fake_smtp(starttls_error=smtplib.SMTPResponseException(454, b"TLS not available due to local problem"))
        checks = by_check(checker.check_smtp())
        self.assertEqual(checks["smtp"]["status"], OK)
        self.assertEqual(checks["tls"]["status"], CRITICAL)

    def test_the_probe_can_be_turned_off(self):
        self.assertEqual(self.checker(health_smtp_port=0).check_smtp(), [])

    def test_certificate_dates(self):
        now = datetime.now(timezone.utc)
        self.assertEqual(certificate_check(make_certificate(now + timedelta(days=90)))["status"], OK)
        soon = certificate_check(make_certificate(now + timedelta(days=5)))
        self.assertEqual(soon["status"], WARNING)
        self.assertIn("4 days", soon["detail"])
        self.assertEqual(certificate_check(make_certificate(now - timedelta(days=1)))["status"], CRITICAL)
        self.assertEqual(certificate_check(b"not a certificate")["status"], WARNING)

    # --- Postfix's queue --------------------------------------------------

    @staticmethod
    def postqueue(*entries):
        return "\n".join(json.dumps(e) for e in entries).encode() + b"\n"

    def test_outgoing_mail_piling_up_is_a_warning_with_the_reason(self):
        reason = "connect to mx.example.org[192.0.2.1]:25: Connection timed out"
        entries = [{"queue_name": "deferred", "recipients": [{"address": f"r{i}@example.org", "delay_reason": reason}]}
                   for i in range(health.DEFERRED_WARNING)]
        entries.append({"queue_name": "active", "recipients": [{"address": "x@example.org"}]})
        check = postfix_queue_check(self.postqueue(*entries), {"example.com"})
        self.assertEqual(check["status"], WARNING)
        self.assertIn(f"{health.DEFERRED_WARNING} outgoing messages deferred", check["detail"])
        self.assertIn("Connection timed out", check["detail"])

    def test_inbound_mail_the_hook_deferred_is_counted_apart(self):
        entries = [{"queue_name": "deferred", "recipients": [{"address": "ada@example.com", "delay_reason": "temporary failure"}]}]
        check = postfix_queue_check(self.postqueue(*entries), {"example.com"})
        self.assertEqual(check["status"], OK)
        self.assertIn("1 inbound message", check["detail"])
        self.assertNotIn("outgoing", check["detail"])

    def test_an_empty_queue_is_healthy(self):
        self.assertEqual(postfix_queue_check(b"", set())["status"], OK)
        self.assertEqual(postfix_queue_check(b"Mail queue is empty\n", set())["status"], OK)

    def test_a_queue_far_behind_is_critical(self):
        entries = [{"queue_name": "deferred", "recipients": [{"address": f"r{i}@example.org"}]} for i in range(health.DEFERRED_CRITICAL)]
        self.assertEqual(postfix_queue_check(self.postqueue(*entries), set())["status"], CRITICAL)

    def test_postqueue_is_run_and_read(self):
        from relay.postfix_config import PostfixTables

        postfix_dir = os.path.join(self._tmp.name, "postfix")
        tables = PostfixTables(postfix_dir)
        tables.apply({"domains": ["example.com"], "recipients": ["ada@example.com"], "config_digest": "d"})
        Completed = namedtuple("Completed", "returncode stdout stderr")
        output = self.postqueue({"queue_name": "deferred", "recipients": [{"address": "ada@example.com"}]})
        checker = HealthChecker(make_config(queue_dir=self.queue.root, postfix_dir=postfix_dir), self.queue, tables=tables,
                                run=lambda *a, **k: Completed(0, output, b""), postqueue_path="sh")
        (check,) = checker.check_postfix_queue()
        self.assertIn("1 inbound message", check["detail"])
        checker.run_command = lambda *a, **k: Completed(69, b"", b"postqueue: fatal: Queue report unavailable")
        self.assertEqual(checker.check_postfix_queue()[0]["status"], WARNING)

    # --- Runs of failures -------------------------------------------------

    def test_a_short_run_of_failures_is_still_healthy(self):
        streak = Streak()
        now = time.time()
        self.assertEqual(failing("delivery", streak, "delivery", now)["status"], OK)
        streak.failed("HTTP 503", now=now - 60)
        self.assertEqual(failing("delivery", streak, "delivery", now)["status"], OK)
        streak.failed("HTTP 503", now=now)
        warning = failing("delivery", streak, "delivery", now + health.FAILING_WARNING_SECONDS - 60)
        self.assertEqual(warning["status"], WARNING)
        self.assertIn("2 attempts", warning["detail"])
        self.assertIn("HTTP 503", warning["detail"])
        self.assertEqual(failing("delivery", streak, "delivery", now + health.FAILING_CRITICAL_SECONDS)["status"], CRITICAL)
        streak.succeeded()
        self.assertEqual(failing("delivery", streak, "delivery", now)["status"], OK)

    def test_missing_sendmail_is_critical(self):
        from relay.outbound import Sender

        checker = HealthChecker(make_config(queue_dir=self.queue.root), self.queue, Sender(os.path.join(self._tmp.name, "missing")))
        self.assertEqual(checker.check_sending(None, time.time())[0]["status"], CRITICAL)
        checker.sender = Sender(FakeSendmail(self._tmp.name).path)
        self.assertEqual(checker.check_sending(None, time.time()), [])
        self.assertEqual(checker.check_sending(Streak(), time.time())[0]["status"], OK)

    # --- The host ---------------------------------------------------------

    def test_disk_space(self):
        Usage = namedtuple("Usage", "total used free")
        checker = self.checker()
        gib = 1024**3
        def status(total, free):
            with mock.patch("shutil.disk_usage", return_value=Usage(total, total - free, free)):
                return checker.check_disk()[0]["status"]

        self.assertEqual(status(100 * gib, 50 * gib), OK)
        self.assertEqual(status(20 * gib, 1.5 * gib), WARNING)
        self.assertEqual(status(20 * gib, 0.5 * gib), CRITICAL)
        # A large disk with a small share free still has room.
        self.assertEqual(status(460 * gib, 22 * gib), OK)
        # And a small one is never let run right down.
        self.assertEqual(status(2 * gib, 200 * 1024**2), CRITICAL)

    def test_disk_is_checked_where_the_queue_will_be(self):
        checker = self.checker(queue_dir=os.path.join(self._tmp.name, "not", "made", "yet"))
        self.assertEqual(checker.check_disk()[0]["check"], "disk")

    def test_parked_mail_counts_the_last_day(self):
        now = time.time()
        for index in range(health.PARKED_WARNING + 1):
            message = self.queue.enqueue(QueuedMessage(recipient="ada@example.com", raw="x"))
            self.queue.move_to_dead(message, "too large")
            if index == 0:
                path = os.path.join(self.queue.dead_dir, f"{message.id}.json")
                os.utime(path, (now - 2 * 86400, now - 2 * 86400))
        self.assertEqual(self.queue.dead_since(now - 86400), health.PARKED_WARNING)
        check = self.checker().check_parked(now)
        self.assertEqual(check[0]["status"], WARNING)
        self.assertIn(f"{health.PARKED_WARNING + 1} in all", check[0]["detail"])

    def test_paused(self):
        self.assertEqual(self.checker(accepting_mail=False).check_paused()[0]["status"], WARNING)
        self.assertEqual(self.checker().check_paused()[0]["status"], OK)

    def test_a_check_that_breaks_is_reported_not_raised(self):
        checker = self.checker(health_smtp_port=0)
        with mock.patch.object(HealthChecker, "check_disk", side_effect=PermissionError("denied")):
            checks = checker.run()
        self.assertIn("denied", by_check(checks)["agent"]["detail"])

    def test_the_node_is_as_well_as_its_worst_check(self):
        self.assertEqual(health.worst([]), OK)
        self.assertEqual(health.worst([health.result("a", OK, ""), health.result("b", WARNING, "")]), WARNING)
        self.assertEqual(health.report([health.result("a", CRITICAL, ""), health.result("b", WARNING, "")])["status"], CRITICAL)


class AgentHealthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def agent(self, **overrides):
        from relay.agent import RelayAgent

        values = dict(queue_dir=os.path.join(self._tmp.name, "q"), maildrop_dir=os.path.join(self._tmp.name, "m"),
                      state_dir=os.path.join(self._tmp.name, "s"), sendmail_path=FakeSendmail(self._tmp.name).path,
                      log_backend="memory")
        values.update(overrides)
        agent = RelayAgent(config=make_config(**values))
        agent.server.http.request = self.server = ScriptedServer()
        return agent

    def test_the_heartbeat_carries_the_checks(self):
        agent = self.agent()
        self.server.queue_reply((200, json.dumps({"config_digest": "abc"})))
        agent.heartbeat()
        sent = self.server.requests[0]["payload"]["health"]
        self.assertIn(sent["status"], (OK, WARNING, CRITICAL))
        self.assertIn("disk", by_check(sent["checks"]))
        self.assertIn("checked_at", sent)
        # The node's view of its own link to the server is not sent: a
        # heartbeat that arrives has answered that.
        self.assertNotIn("server", by_check(sent["checks"]))

    def test_delivery_failing_for_a_while_is_reported(self):
        agent = self.agent()
        message = agent.queue.enqueue(QueuedMessage(recipient="ada@example.com", raw="c2VhbGVk", encoding="base64",
                                                    encryption={"alg": "ECDH-P256-A256GCM", "kid": "k"}, headers="To: ada@example.com\r\n"))
        self.server.queue_reply((503, "{}"))
        agent.deliver_one(message)
        self.assertEqual(agent.delivery_failures.count, 1)
        agent.delivery_failures.since -= health.FAILING_WARNING_SECONDS + 1

        self.server.queue_reply((200, json.dumps({"config_digest": "abc"})))
        agent.heartbeat()
        delivery = by_check(self.server.requests[-1]["payload"]["health"]["checks"])["delivery"]
        self.assertEqual(delivery["status"], WARNING)
        self.assertIn("HTTP 503", delivery["detail"])

        # One delivery that lands ends the run.
        message = agent.queue.due(now=time.time() + 3600)[0]
        self.server.queue_reply((200, json.dumps({"status": "stored"})))
        agent.deliver_one(message)
        self.assertIsNone(agent.delivery_failures.since)

    def test_sendmail_deferring_starts_a_run_and_sending_ends_it(self):
        import base64

        agent = self.agent()
        item = {"id": "ob-1", "envelope_from": "ada@example.com", "recipients": ["bob@example.org"],
                "raw_base64": base64.b64encode(b"Subject: x\r\n\r\ny\r\n").decode()}
        agent.sender = mock.Mock()
        agent.sender.send.return_value = ("deferred", "sendmail exit 75: queue file write error")
        self.server.queue_reply((200, "{}"))
        agent.send_one(item)
        self.assertEqual(agent.sending_failures.count, 1)
        agent.sender.send.return_value = ("sent", "")
        self.server.queue_reply((200, "{}"))
        agent.send_one(item)
        self.assertIsNone(agent.sending_failures.since)

    def test_a_table_that_cannot_be_written_is_reported(self):
        tables = mock.Mock()
        tables.apply.side_effect = OSError(28, "No space left on device")
        agent = self.agent()
        agent.tables = agent.checker.tables = tables
        self.server.queue_reply((200, json.dumps({"domains": ["example.com"], "config_digest": "abc"})))
        agent.heartbeat()
        self.assertIn("No space left", agent.tables_error)
        self.server.queue_reply((200, json.dumps({"domains": ["example.com"], "config_digest": "abc"})))
        agent.heartbeat()
        self.assertEqual(by_check(self.server.requests[-1]["payload"]["health"]["checks"])["tables"]["status"], WARNING)

    def test_local_health_adds_the_workers_and_the_server(self):
        agent = self.agent(api_key="")
        checks = by_check(agent.local_health()["checks"])
        self.assertEqual(checks["server"]["status"], CRITICAL)
        self.assertEqual(checks["workers"]["detail"], "Starting.")

        stopped = mock.Mock(is_alive=lambda: False)
        stopped.name = "orbit-relay-deliver"
        agent._threads = [stopped]
        self.assertIn("orbit-relay-deliver stopped", by_check(agent.local_health()["checks"])["workers"]["detail"])

    def test_health_endpoint_answers_503_when_critical(self):
        from relay.cli import _start_status_server

        agent = self.agent(api_key="")
        server = _start_status_server(agent, "127.0.0.1", 0)
        try:
            port = server.server_address[1]
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5)
            self.assertEqual(caught.exception.code, 503)
            self.assertEqual(json.loads(caught.exception.read())["status"], CRITICAL)
            caught.exception.close()

            agent.config.api_key = "orbk_test"
            with mock.patch.object(HealthChecker, "run", return_value=[]):
                agent.check_health()
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
                    self.assertEqual(response.status, 200)
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=5) as response:
                    self.assertIn("health", json.loads(response.read()))
        finally:
            server.shutdown()
            server.server_close()


class HealthCommandTests(unittest.TestCase):
    def run_command(self, **environment):
        from relay import cli

        names = ("ORBIT_CONFIG_FILE", "ORBIT_RELAY_ENCRYPTION_KEY", "ORBIT_QUEUE_DIR", "ORBIT_POSTFIX_DIR",
                 "ORBIT_HEALTH_SMTP_PORT", "ORBIT_STATUS_PORT")
        saved = {name: os.environ.pop(name, None) for name in names}
        with tempfile.TemporaryDirectory() as workdir:
            from relay.crypto import generate_key

            os.environ.update(ORBIT_CONFIG_FILE="", ORBIT_RELAY_ENCRYPTION_KEY=generate_key(),
                              ORBIT_QUEUE_DIR=os.path.join(workdir, "q"), ORBIT_POSTFIX_DIR=os.path.join(workdir, "p"),
                              ORBIT_HEALTH_SMTP_PORT="0", **environment)
            out = io.StringIO()
            # Only what the command adds is under test, not this machine's
            # disk or Postfix.
            quiet = {name: mock.patch.object(HealthChecker, name, return_value=[])
                     for name in ("check_sender_libraries", "check_postfix_queue", "check_disk")}
            try:
                with contextlib.ExitStack() as stack:
                    for patch in quiet.values():
                        stack.enter_context(patch)
                    stack.enter_context(contextlib.redirect_stdout(out))
                    code = cli.main(["health"])
            finally:
                for name in names:
                    os.environ.pop(name, None)
                    if saved[name] is not None:
                        os.environ[name] = saved[name]
        return code, json.loads(out.getvalue())

    def test_without_an_agent_to_ask_it_checks_the_host_itself(self):
        code, answer = self.run_command(ORBIT_STATUS_PORT="0")
        self.assertEqual(answer["status"], OK)
        self.assertEqual(code, 0)
        self.assertIn("parked", by_check(answer["checks"]))

    def test_an_agent_that_does_not_answer_is_critical(self):
        import socket

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        code, answer = self.run_command(ORBIT_STATUS_PORT=str(free_port))
        self.assertEqual(code, 2)
        self.assertEqual(by_check(answer["checks"])["agent"]["status"], CRITICAL)


if __name__ == "__main__":
    unittest.main()
