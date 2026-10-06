"""End-to-end tests of the relay pipeline.

Exercises the path a message takes on a node: Postfix drops a file, the agent
accepts it, it lands on the durable queue, and the delivery loop posts it to the
Orbit Mail server and retries until it succeeds. The outbound direction is
covered too: the agent claims queued mail from the server, hands it to a fake
sendmail, and reports the result.

The HTTP layer is stubbed rather than run against a real socket, because the
contract under test is the relay's *behaviour* on a failure, not urllib's.
"""

import base64
import json
import os
import stat
import tempfile
import time
import unittest

from relay.config import Config
from relay.crypto import Cipher, generate_key
from relay.outbound import Sender, decode_raw
from relay.postfix import Maildrop
from relay.postfix_config import PostfixTables
from relay.queue import Queue
from relay.transport import MailServerClient, PermanentError, Response, RetryableError

RAW = (
    "From: Bob <bob@example.org>\r\n"
    "To: alice@example.com\r\n"
    "Subject: Lunch\r\n"
    "Message-ID: <e2e-1@example.org>\r\n"
    "\r\n"
    "Noon?\r\n"
)


def make_config(**overrides):
    values = dict(node_name="relay-test", hostname="relay-test.example.com",
                  server_url="https://mail.example.com", api_key="orbk_test", postfix_dir="",
                  encryption_key=generate_key())
    values.update(overrides)
    return Config(**values)


class ScriptedServer:
    """A server whose replies are scripted, one per call."""

    def __init__(self):
        self.replies = []
        self.requests = []

    def queue_reply(self, *replies):
        self.replies.extend(replies)

    def __call__(self, url, *, method="POST", payload=None, headers=None, timeout=None):
        self.requests.append({"url": url, "payload": payload, "headers": headers or {}})
        if not self.replies:
            raise AssertionError("No scripted reply left; the client called too many times.")
        status, body = self.replies.pop(0)
        if status == 401 or status == 429 or status >= 500:
            raise RetryableError(f"HTTP {status}")
        if status >= 400:
            raise PermanentError(f"HTTP {status}", status=status)
        return Response(status, body, {})


class AnyReader:
    """A key directory that gives every address the same reader, for tests
    about the pipeline rather than about keys."""

    def __init__(self):
        self.reader = Cipher.from_text(generate_key())

    def readers(self, address):
        return [(self.reader.kid, self.reader.public_key)]

    def lookup(self, address):
        return self.readers(address)[0]


class Harness:
    """Drives one message through accept, seal, queue and deliver."""

    def __init__(self, root, server):
        self.maildrop_dir = os.path.join(root, "incoming")
        os.makedirs(self.maildrop_dir, exist_ok=True)
        self.queue = Queue(os.path.join(root, "queue"), max_attempts=3, backoff_base=0.0, backoff_max=0.0, backoff_jitter=0.0)
        self.queue.ensure_dirs()
        self.keys = AnyReader()
        self.maildrop = Maildrop(self.maildrop_dir, self.queue, "relay-test", keys=self.keys)
        self.server = server
        self.client = MailServerClient(make_config())
        self.client.http.request = server

    def accept(self, name="alice@example.com", raw=RAW):
        with open(os.path.join(self.maildrop_dir, name), "w") as handle:
            handle.write(raw)
        claimed = self.maildrop.claim(name)
        message = self.maildrop.process_file(claimed)
        self.maildrop.discard(claimed)
        return message

    def drain(self, rounds=10):
        for _ in range(rounds):
            batch = self.queue.due(limit=50)
            if not batch:
                if self.queue.stats()["pending"] == 0:
                    return
                time.sleep(0.55)
                continue
            for message in batch:
                if not self.queue.mark_inflight(message):
                    continue
                try:
                    self.client.deliver(message)
                    self.queue.complete(message)
                except RetryableError as error:
                    self.queue.requeue(message, str(error))
                except PermanentError as error:
                    self.queue.move_to_dead(message, str(error))


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.server = ScriptedServer()
        self.h = Harness(self._tmp.name, self.server)

    def tearDown(self):
        self._tmp.cleanup()

    def test_postfix_to_server(self):
        self.server.queue_reply((200, json.dumps({"status": "stored", "thread_id": "t1"})))
        message = self.h.accept()
        self.assertEqual(self.h.queue.stats()["pending"], 1)
        self.h.drain()
        self.assertEqual(self.h.queue.stats(), {"pending": 0, "inflight": 0, "dead": 0})
        request = self.server.requests[0]
        self.assertTrue(request["url"].endswith("/api/relay/inbound/"))
        self.assertEqual(request["headers"]["Authorization"], "Bearer orbk_test")
        self.assertEqual(request["headers"]["X-Orbit-Relay-Node"], "relay-test")
        self.assertEqual(request["payload"]["recipient"], "alice@example.com")
        self.assertEqual(request["payload"]["encoding"], "base64")
        # Only ciphertext travels; the reader's key opens it.
        self.assertNotIn("Noon?", base64.b64decode(request["payload"]["raw"]).decode("latin-1"))
        self.assertEqual(self.h.keys.reader.open(request["payload"]["encrypted"], request["payload"]["raw"]), RAW.encode())
        self.assertIn("Subject: Lunch", request["payload"]["headers"])
        self.assertEqual(request["payload"]["message_id"], message.id)

    def test_retries_until_the_server_recovers(self):
        self.server.queue_reply((503, ""), (503, ""), (200, json.dumps({"status": "stored"})))
        self.h.accept()
        self.h.drain()
        self.assertEqual(len(self.server.requests), 3)
        self.assertEqual(self.h.queue.stats()["pending"], 0)

    def test_rotated_key_is_retryable(self):
        self.server.queue_reply((401, ""), (200, json.dumps({"status": "stored"})))
        self.h.accept()
        self.h.drain()
        self.assertEqual(self.h.queue.stats(), {"pending": 0, "inflight": 0, "dead": 0})

    def test_server_can_ask_for_no_retry_even_with_200(self):
        self.server.queue_reply((200, json.dumps({"retryable": False, "error": "no such mailbox"})))
        self.h.accept()
        self.h.drain()
        self.assertEqual(self.h.queue.stats()["dead"], 1)

    def test_4xx_is_permanent(self):
        self.server.queue_reply((422, ""))
        self.h.accept()
        self.h.drain()
        self.assertEqual(self.h.queue.stats()["dead"], 1)

    def test_message_survives_a_restart(self):
        self.h.accept()
        reopened = Queue(self.h.queue.root, max_attempts=3, backoff_base=0.0, backoff_max=0.0, backoff_jitter=0.0)
        self.assertEqual(reopened.stats()["pending"], 1)

    def test_attempt_budget_eventually_parks_a_message(self):
        self.server.queue_reply((503, ""), (503, ""), (503, ""), (503, ""))
        self.h.accept()
        self.h.drain(rounds=20)
        self.assertEqual(self.h.queue.stats()["dead"], 1)

    def test_multiple_messages_all_arrive(self):
        for i in range(5):
            self.server.queue_reply((200, json.dumps({"status": "stored"})))
            self.h.accept(name=f"user{i}@example.com")
        self.h.drain()
        recipients = {r["payload"]["recipient"] for r in self.server.requests}
        self.assertEqual(recipients, {f"user{i}@example.com" for i in range(5)})


class FakeSendmail:
    """Writes a tiny sendmail script that records what it was given."""

    def __init__(self, root, exit_code=0):
        self.path = os.path.join(root, "sendmail")
        self.log = os.path.join(root, "sendmail.log")
        with open(self.path, "w") as handle:
            handle.write("#!/bin/sh\n")
            handle.write(f"echo \"$@\" >> '{self.log}'\n")
            handle.write(f"cat >> '{self.log}'\n")
            handle.write(f"exit {exit_code}\n")
        os.chmod(self.path, os.stat(self.path).st_mode | stat.S_IEXEC)

    def read(self):
        with open(self.log) as handle:
            return handle.read()


class OutboundTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_sender_hands_message_to_sendmail(self):
        fake = FakeSendmail(self._tmp.name)
        sender = Sender(fake.path)
        status, error = sender.send("ada@example.com", ["bob@example.org", "c@example.net"], b"Subject: Hi\r\n\r\nHello\r\n")
        self.assertEqual((status, error), ("sent", ""))
        log = fake.read()
        self.assertIn("-i -f ada@example.com -- bob@example.org c@example.net", log)
        self.assertIn("Subject: Hi", log)

    def test_sender_classifies_exit_codes(self):
        self.assertEqual(Sender(FakeSendmail(self._tmp.name, exit_code=75).path).send("a@x.com", ["b@y.com"], b"x")[0], "deferred")
        self.assertEqual(Sender(FakeSendmail(self._tmp.name, exit_code=67).path).send("a@x.com", ["b@y.com"], b"x")[0], "failed")

    def test_sender_without_binary_defers(self):
        status, error = Sender(os.path.join(self._tmp.name, "missing")).send("a@x.com", ["b@y.com"], b"x")
        self.assertEqual(status, "deferred")
        self.assertIn("not available", error)

    def test_sender_rejects_option_like_addresses(self):
        fake = FakeSendmail(self._tmp.name)
        status, _ = Sender(fake.path).send("-oQ/tmp", ["b@y.com"], b"x")
        self.assertEqual(status, "failed")
        status, _ = Sender(fake.path).send("a@x.com", ["-bv"], b"x")
        self.assertEqual(status, "failed")

    def test_agent_claims_sends_and_reports(self):
        from relay.agent import RelayAgent

        fake = FakeSendmail(self._tmp.name)
        config = make_config(queue_dir=os.path.join(self._tmp.name, "q"), maildrop_dir=os.path.join(self._tmp.name, "m"),
                             state_dir=os.path.join(self._tmp.name, "s"), sendmail_path=fake.path, log_backend="memory")
        server = ScriptedServer()
        raw = base64.b64encode(b"Subject: Out\r\n\r\nBye\r\n").decode()
        server.queue_reply(
            (200, json.dumps({"messages": [{"id": "ob-1", "envelope_from": "ada@example.com", "recipients": ["bob@example.org"], "raw_base64": raw}], "remaining": 0})),
            (200, json.dumps({"id": "ob-1", "status": "sent"})),
        )
        agent = RelayAgent(config=config)
        agent.server.http.request = server
        handled = agent.send_batch()
        self.assertEqual(handled, 1)
        self.assertIn("Subject: Out", fake.read())
        claim, report = server.requests
        self.assertTrue(claim["url"].endswith("/api/relay/outbound/claim/"))
        self.assertTrue(report["url"].endswith("/api/relay/outbound/ob-1/result/"))
        self.assertEqual(report["payload"]["status"], "sent")
        self.assertEqual(agent.stats["sent"], 1)

    def test_decode_raw_prefers_base64(self):
        self.assertEqual(decode_raw({"raw_base64": base64.b64encode(b"hi").decode()}), b"hi")
        self.assertEqual(decode_raw({"raw": "hi"}), b"hi")


class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_heartbeat_applies_config_and_writes_tables(self):
        from relay.agent import RelayAgent

        postfix_dir = os.path.join(self._tmp.name, "postfix")
        config = make_config(queue_dir=os.path.join(self._tmp.name, "q"), maildrop_dir=os.path.join(self._tmp.name, "m"),
                             state_dir=os.path.join(self._tmp.name, "s"), postfix_dir=postfix_dir, log_backend="memory")
        server = ScriptedServer()
        server.queue_reply((200, json.dumps({
            "domains": ["example.com"], "recipients": ["ada@example.com", "bob@example.com"], "catch_all_domains": ["example.com"],
            "config_digest": "abc", "accepting_mail": True, "heartbeat_interval": 30, "outbound_poll_interval": 2, "peers": ["relay-2"],
        })))
        agent = RelayAgent(config=config)
        agent.server.http.request = server
        agent.heartbeat()
        self.assertTrue(agent.server_reachable)
        self.assertEqual(agent.domains, ["example.com"])
        self.assertEqual(agent.recipient_count, 3)
        self.assertEqual(agent.heartbeat_interval, 30)
        self.assertEqual(agent.peers, ["relay-2"])
        self.assertEqual(agent.config_digest, "abc")
        sent = server.requests[0]["payload"]
        self.assertEqual(sent["node"], "relay-test")
        self.assertIn("queue", sent)
        self.assertEqual(sent["encryption_kid"], agent.cipher.kid)
        self.assertEqual(sent["encryption_public_key"], agent.cipher.public_key_text)
        with open(os.path.join(postfix_dir, "relay_domains")) as handle:
            self.assertEqual(handle.read(), "example.com\tOK\n")
        with open(os.path.join(postfix_dir, "relay_recipients")) as handle:
            self.assertEqual(handle.read().splitlines(), ["ada@example.com\tOK", "bob@example.com\tOK", "@example.com\tOK"])

        # An unchanged answer leaves the tables alone.
        server.queue_reply((200, json.dumps({"unchanged": True, "config_digest": "abc", "accepting_mail": True})))
        before = os.stat(os.path.join(postfix_dir, "relay_domains")).st_mtime_ns
        agent.heartbeat()
        self.assertEqual(server.requests[1]["payload"]["config_digest"], "abc")
        self.assertEqual(os.stat(os.path.join(postfix_dir, "relay_domains")).st_mtime_ns, before)

    def test_tables_disabled_without_directory(self):
        tables = PostfixTables("")
        self.assertFalse(tables.apply({"domains": ["x.com"], "recipients": [], "config_digest": "z"}))

    def test_tables_are_built_with_the_configured_type(self):
        with tempfile.TemporaryDirectory() as workdir:
            calls = os.path.join(workdir, "calls")
            postmap = os.path.join(workdir, "postmap")
            with open(postmap, "w") as handle:
                handle.write(f'#!/bin/sh\necho "$1" >> {calls}\n')
            os.chmod(postmap, 0o755)
            tables = PostfixTables(os.path.join(workdir, "orbit"), postmap_path=postmap,
                                   postfix_path=os.path.join(workdir, "absent"), db_type="lmdb")
            self.assertTrue(tables.apply({"domains": ["x.com"], "recipients": ["a@x.com"], "config_digest": "z"}))
            with open(calls) as handle:
                self.assertEqual([line.split(":")[0] for line in handle.read().splitlines()], ["lmdb", "lmdb"])


class ConfigTests(unittest.TestCase):
    def test_validation_catches_missing_settings(self):
        problems = Config(node_name="", server_url="not-a-url").validate()
        self.assertTrue(any("ORBIT_RELAY_NAME" in p for p in problems))
        self.assertTrue(any("http" in p for p in problems))

    def test_valid_config_has_no_problems(self):
        self.assertEqual(Config(node_name="relay-1", server_url="https://m.example.com", encryption_key=generate_key()).validate(), [])

    def test_a_node_without_its_own_key_is_unusable(self):
        problems = Config(node_name="relay-1", server_url="https://m.example.com", encryption_key="", encryption_key_file="").validate()
        self.assertTrue(any("key is required" in p for p in problems))

    def test_backoff_max_below_base_is_rejected(self):
        config = Config(node_name="r", server_url="https://m", backoff_base=10, backoff_max=5, encryption_key=generate_key())
        self.assertTrue(any("ORBIT_BACKOFF_MAX" in p for p in config.validate()))

    def test_environment_is_read(self):
        os.environ["ORBIT_RELAY_NAME"] = "relay-env"
        os.environ["ORBIT_MAIL_SERVER_URL"] = "https://mail.example.com/"
        os.environ["ORBIT_RELAY_API_KEY"] = "orbk_abc"
        os.environ["ORBIT_RELAY_ENCRYPTION_KEY"] = generate_key()
        try:
            from relay.config import load_config

            config = load_config()
            self.assertEqual(config.node_name, "relay-env")
            self.assertEqual(config.server_url, "https://mail.example.com")
            self.assertEqual(config.validate(), [])
            self.assertTrue(config.has_api_key)
        finally:
            for key in ("ORBIT_RELAY_NAME", "ORBIT_MAIL_SERVER_URL", "ORBIT_RELAY_API_KEY", "ORBIT_RELAY_ENCRYPTION_KEY"):
                del os.environ[key]

    def test_settings_file_is_read_and_the_environment_wins(self):
        from relay.config import load_config

        names = ("ORBIT_CONFIG_FILE", "ORBIT_RELAY_NAME", "ORBIT_MAIL_SERVER_URL", "ORBIT_RELAY_API_KEY", "ORBIT_STATUS_PORT")
        saved = {name: os.environ.pop(name, None) for name in names}
        with tempfile.TemporaryDirectory() as workdir:
            path = os.path.join(workdir, "relay.env")
            with open(path, "w") as handle:
                handle.write("# a comment\n\nORBIT_RELAY_NAME=from-file\nORBIT_MAIL_SERVER_URL='https://file.example.com'\n"
                             "ORBIT_RELAY_API_KEY=orbk_file\nnot a setting\n")
            os.environ["ORBIT_CONFIG_FILE"] = path
            os.environ["ORBIT_RELAY_NAME"] = "from-environment"
            try:
                config = load_config()
                self.assertEqual(config.node_name, "from-environment")
                self.assertEqual(config.server_url, "https://file.example.com")
                self.assertEqual(config.api_key, "orbk_file")
            finally:
                for name in names:
                    os.environ.pop(name, None)
                    if saved[name] is not None:
                        os.environ[name] = saved[name]

    def test_a_missing_settings_file_is_not_an_error(self):
        from relay.config import load_env_file

        load_env_file("/nonexistent/relay.env")
        load_env_file("")

    def test_status_endpoint_listens_on_loopback_by_default(self):
        config = Config()
        self.assertEqual(config.status_address, "127.0.0.1")
        self.assertEqual(config.status_port, 8080)

    def test_memory_logging_is_bounded(self):
        import logging

        from relay.logging_setup import recent_events, setup_logging

        setup_logging(level="INFO", backend="memory", max_entries=5)
        log = logging.getLogger("test.bounded")
        for i in range(50):
            log.info("event %d", i)
        self.assertLessEqual(len(recent_events(limit=100)), 5)


if __name__ == "__main__":
    unittest.main()
