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
import io
import json
import os
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest import mock

from relay.config import Config
from relay.crypto import Cipher, generate_key
from relay.keys import PublicKeyDirectory
from relay.outbound import Sender, decode_raw
from relay.postfix import Maildrop
from relay.postfix_config import PostfixTables
from relay.queue import Queue, QueuedMessage
from relay.transport import HttpClient, MailServerClient, PermanentError, Response, RetryableError

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

    def test_a_failed_requeue_does_not_end_the_delivery_loop(self):
        from relay.agent import RelayAgent

        root = self._tmp.name
        config = make_config(queue_dir=os.path.join(root, "agent-q"), maildrop_dir=os.path.join(root, "agent-m"),
                             state_dir=os.path.join(root, "agent-s"), log_backend="memory")
        agent = RelayAgent(config=config, keys=AnyReader())
        agent.queue.enqueue(QueuedMessage(recipient="alice@example.com", raw="x", encryption={"kid": "k"}))
        agent.server.deliver = mock.Mock(side_effect=RuntimeError("unexpected"))
        agent.queue.requeue = mock.Mock(side_effect=OSError(28, "No space left on device"))
        threading.Timer(0.3, agent.stop).start()
        # Returns once stopped; before, the requeue error ended the thread.
        agent._delivery_loop()
        self.assertEqual(agent.stats["failed"], 1)


class ReceiveHookTests(unittest.TestCase):
    """deploy/orbit-relay-receive and `orbit-relay receive` together, as
    Postfix runs them, with the reader's key in the node's cache."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = self._tmp.name
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        command = os.path.join(root, "orbit-relay")
        with open(command, "w") as handle:
            handle.write(f'#!/bin/sh\nPYTHONPATH="{repo}" exec "{sys.executable}" -m relay.cli "$@"\n')
        os.chmod(command, 0o755)
        with open(os.path.join(repo, "deploy", "orbit-relay-receive")) as handle:
            hook = handle.read().replace("/usr/local/bin/orbit-relay", command)
        self.hook = os.path.join(root, "orbit-relay-receive")
        with open(self.hook, "w") as handle:
            handle.write(hook)
        os.chmod(self.hook, 0o755)
        self.maildrop_dir = os.path.join(root, "incoming")
        self.queue = Queue(os.path.join(root, "queue"))
        self.keys = PublicKeyDirectory(None, os.path.join(root, "state", "keys"))
        self.reader = Cipher.from_text(generate_key())
        # Nothing listens on port 9: the keys come from the cache or not at all.
        self.postfix_dir = os.path.join(root, "postfix")
        self.env = dict(os.environ, ORBIT_CONFIG_FILE="", ORBIT_MAIL_SERVER_URL="http://127.0.0.1:9",
                        ORBIT_RELAY_API_KEY="orbk_test", ORBIT_RELAY_ENCRYPTION_KEY=generate_key(),
                        ORBIT_QUEUE_DIR=self.queue.root, ORBIT_MAILDROP_DIR=self.maildrop_dir,
                        ORBIT_STATE_DIR=os.path.join(root, "state"), ORBIT_POSTFIX_DIR=self.postfix_dir,
                        ORBIT_LOG_LEVEL="ERROR")
        self.env.pop("ORBIT_ACCEPTING_MAIL", None)

    def tearDown(self):
        self._tmp.cleanup()

    def set_key(self, present=True):
        record = {"address": "alice@example.com", "fetched_at": time.time()}
        if present:
            record["readers"] = [{"kid": self.reader.kid, "public_key": self.reader.public_key_text}]
        self.keys._write("alice@example.com", record)

    def start(self, subject="Lunch"):
        process = subprocess.Popen([self.hook, "alice@example.com"], stdin=subprocess.PIPE, env=self.env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.stdin.write(RAW.replace("Lunch", subject).replace("\r\n", "\n").encode())
        process.stdin.close()
        return process

    def queued(self):
        names = os.listdir(self.queue.pending_dir) if os.path.isdir(self.queue.pending_dir) else []
        return [self.queue.peek(name[:-len(".json")]) for name in names]

    def test_a_deferred_message_is_accepted_on_the_retry(self):
        self.set_key(present=False)
        self.assertEqual(self.start().wait(), 75)
        # Postfix keeps the message and pipes it again; no copy stays here.
        self.assertEqual([name for _, _, names in os.walk(self.maildrop_dir) for name in names], [])
        self.set_key()
        self.assertEqual(self.start().wait(), 0)
        self.assertEqual([m.recipient for m in self.queued()], ["alice@example.com"])

    def test_messages_for_one_address_arriving_together_all_land(self):
        self.set_key()
        processes = [self.start(subject=f"Lunch {i}") for i in range(8)]
        self.assertEqual([p.wait() for p in processes], [0] * 8)
        queued = self.queued()
        self.assertEqual({m.recipient for m in queued}, {"alice@example.com"})
        subjects = {self.reader.open(m.encryption, m.raw).split(b"Subject: ")[1].split(b"\n")[0] for m in queued}
        self.assertEqual(subjects, {f"Lunch {i}".encode() for i in range(8)})

    def drop_files(self):
        return [name for _, _, names in os.walk(self.maildrop_dir) for name in names]

    def test_a_node_the_server_paused_defers_every_message(self):
        # The reader's key is at hand, so only the switch can defer it.
        self.set_key()
        PostfixTables(self.postfix_dir).set_accepting(False)
        self.assertEqual(self.start().wait(), 75)
        # Nothing sealed, queued or kept: Postfix holds the message and retries.
        self.assertEqual((self.queued(), self.drop_files()), ([], []))
        PostfixTables(self.postfix_dir).set_accepting(True)
        self.assertEqual(self.start().wait(), 0)
        self.assertEqual([m.recipient for m in self.queued()], ["alice@example.com"])

    def test_the_operators_switch_defers_every_message(self):
        self.set_key()
        self.env["ORBIT_ACCEPTING_MAIL"] = "0"
        self.assertEqual(self.start().wait(), 75)
        self.assertEqual((self.queued(), self.drop_files()), ([], []))


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
        # The server hands sealed mail only to a node it was sealed to; the
        # key id says which, whatever other node shares this one's name.
        self.assertEqual(claim["payload"]["encryption_kid"], agent.cipher.kid)
        self.assertTrue(report["url"].endswith("/api/relay/outbound/ob-1/result/"))
        self.assertEqual(report["payload"]["status"], "sent")
        self.assertEqual(agent.stats["sent"], 1)

    def test_an_all_deferred_batch_counts_as_nothing_handled(self):
        # Deferred mail is back on the server's queue at once; claiming again
        # without waiting would spin on it.
        from relay.agent import RelayAgent

        config = make_config(queue_dir=os.path.join(self._tmp.name, "q"), maildrop_dir=os.path.join(self._tmp.name, "m"),
                             state_dir=os.path.join(self._tmp.name, "s"), sendmail_path=os.path.join(self._tmp.name, "missing"),
                             log_backend="memory")
        server = ScriptedServer()
        raw = base64.b64encode(b"Subject: Out\r\n\r\nBye\r\n").decode()
        items = [{"id": f"ob-{i}", "envelope_from": "ada@example.com", "recipients": ["bob@example.org"], "raw_base64": raw}
                 for i in range(2)]
        server.queue_reply((200, json.dumps({"messages": items})), (200, "{}"), (200, "{}"))
        agent = RelayAgent(config=config)
        agent.server.http.request = server
        self.assertEqual(agent.send_batch(), 0)
        self.assertEqual([r["payload"]["status"] for r in server.requests[1:]], ["deferred", "deferred"])

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

    def test_a_failed_table_write_keeps_the_old_digest(self):
        from relay.agent import RelayAgent

        tables = mock.Mock()
        tables.apply.side_effect = OSError(28, "No space left on device")
        config = make_config(queue_dir=os.path.join(self._tmp.name, "q"), maildrop_dir=os.path.join(self._tmp.name, "m"),
                             state_dir=os.path.join(self._tmp.name, "s"), log_backend="memory")
        server = ScriptedServer()
        full = {"domains": ["example.com"], "recipients": ["ada@example.com"], "config_digest": "abc"}
        server.queue_reply((200, json.dumps(full)), (200, json.dumps(full)))
        agent = RelayAgent(config=config, tables=tables)
        agent.server.http.request = server
        agent.heartbeat()
        self.assertEqual(agent.config_digest, "")
        # So the next heartbeat asks for the full lists again.
        agent.heartbeat()
        self.assertEqual(server.requests[1]["payload"]["config_digest"], "")

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

    def agent(self, **overrides):
        from relay.agent import RelayAgent

        postfix_dir = os.path.join(self._tmp.name, "postfix")
        config = make_config(queue_dir=os.path.join(self._tmp.name, "q"), maildrop_dir=os.path.join(self._tmp.name, "m"),
                             state_dir=os.path.join(self._tmp.name, "s"), postfix_dir=postfix_dir, log_backend="memory",
                             **overrides)
        # No postmap or reload: these tests are about the switch, not the tables.
        absent = os.path.join(self._tmp.name, "absent")
        agent = RelayAgent(config=config, tables=PostfixTables(postfix_dir, postmap_path=absent, postfix_path=absent))
        agent.server.http.request = ScriptedServer()
        return agent

    def test_the_servers_switch_reaches_the_receive_hook_on_every_heartbeat(self):
        from relay.postfix_config import accepting_mail

        agent = self.agent()
        full = {"domains": ["example.com"], "recipients": ["ada@example.com"], "config_digest": "abc", "accepting_mail": True}
        unchanged = {"unchanged": True, "config_digest": "abc"}
        agent.server.http.request.queue_reply(
            (200, json.dumps(full)),
            (200, json.dumps(dict(unchanged, accepting_mail=False))),
            (200, json.dumps(dict(unchanged, accepting_mail=True))),
        )
        agent.heartbeat()
        self.assertTrue(accepting_mail(agent.config))
        # The fleet is paused with nothing else changed: the server leaves the
        # lists out, and the switch must land all the same.
        agent.heartbeat()
        self.assertFalse(agent.accepting_mail)
        self.assertFalse(accepting_mail(agent.config))
        agent.heartbeat()
        self.assertTrue(accepting_mail(agent.config))

    def test_the_operators_switch_is_written_too(self):
        agent = self.agent(accepting_mail=False)
        agent.server.http.request.queue_reply((200, json.dumps({"domains": [], "config_digest": "abc", "accepting_mail": True})))
        agent.heartbeat()
        self.assertFalse(PostfixTables(agent.config.postfix_dir).accepting_flag())

    def test_a_node_accepts_mail_unless_told_otherwise(self):
        from relay.postfix_config import accepting_mail

        postfix_dir = os.path.join(self._tmp.name, "postfix")
        # Before the agent has written anything, as on a fresh install.
        self.assertTrue(accepting_mail(make_config(postfix_dir=postfix_dir)))
        self.assertFalse(accepting_mail(make_config(postfix_dir=postfix_dir, accepting_mail=False)))
        PostfixTables(postfix_dir).set_accepting(False)
        self.assertFalse(accepting_mail(make_config(postfix_dir=postfix_dir)))
        PostfixTables(postfix_dir).set_accepting(True)
        self.assertTrue(accepting_mail(make_config(postfix_dir=postfix_dir)))


class BounceTests(unittest.TestCase):
    """A message the server refuses for good goes back to its sender, and is
    kept in dead/ as well."""

    def setUp(self):
        from relay.agent import RelayAgent

        self._tmp = tempfile.TemporaryDirectory()
        root = self._tmp.name
        self.sendmail = FakeSendmail(root)
        config = make_config(queue_dir=os.path.join(root, "q"), maildrop_dir=os.path.join(root, "m"),
                             state_dir=os.path.join(root, "s"), sendmail_path=self.sendmail.path, log_backend="memory")
        self.agent = RelayAgent(config=config, keys=AnyReader())

    def tearDown(self):
        self._tmp.cleanup()

    def accept(self, return_path="<bob@example.org>"):
        drop = os.path.join(self.agent.maildrop.directory, "alice@example.com")
        with open(drop, "w") as handle:
            handle.write(f"Return-Path: {return_path}\r\n" + RAW)
        claimed = self.agent.maildrop.claim("alice@example.com")
        message = self.agent.maildrop.process_file(claimed)
        self.agent.maildrop.discard(claimed)
        return message

    def refuse(self, status, body):
        """Deliver the queued message to a server that answers ``status``."""
        answer = body if isinstance(body, bytes) else json.dumps(body).encode()
        error = urllib.error.HTTPError("https://mail.example.com/api/relay/inbound/", status, "refused", {}, io.BytesIO(answer))
        with mock.patch("urllib.request.urlopen", side_effect=error):
            self.agent.deliver_one(self.agent.queue.due()[0])
        self.assertEqual(self.agent.queue.stats(), {"pending": 0, "inflight": 0, "dead": 1})
        return self.agent.queue.list_dead()[0]

    def test_a_message_too_large_for_the_server_is_bounced_to_its_sender(self):
        self.accept()
        parked = self.refuse(413, {"error": "The request is 80000000 bytes, over the 75147968 this endpoint accepts.",
                                   "retryable": False, "code": "too_large"})
        log = self.sendmail.read()
        # From the null sender, so the notice itself can never bounce back.
        self.assertIn("-i -f <> -- bob@example.org", log)
        self.assertIn("Content-Type: multipart/report; report-type=\"delivery-status\"", log)
        self.assertIn("Final-Recipient: rfc822; alice@example.com", log)
        self.assertIn("Status: 5.3.4", log)
        self.assertIn("over the 75147968 this endpoint accepts.", log)
        # The readable headers come back; the sealed body never could.
        self.assertIn("Subject: Lunch", log)
        self.assertNotIn("Noon?", log)
        self.assertIn("bounced to bob@example.org", parked.last_error)
        self.assertEqual((self.agent.stats["bounced"], self.agent.stats["parked"]), (1, 1))

    def test_a_proxys_own_413_is_bounced_too(self):
        self.accept()
        self.refuse(413, b"<html><body>413 Request Entity Too Large</body></html>")
        self.assertIn("Status: 5.3.4", self.sendmail.read())

    def test_mail_from_the_null_sender_is_never_bounced(self):
        message = self.accept(return_path="<>")
        self.assertEqual(message.envelope_from, "")
        parked = self.refuse(422, {"error": "not a deliverable mailbox", "retryable": False, "code": "no_mailbox"})
        self.assertFalse(os.path.exists(self.sendmail.log))
        self.assertIn("not bounced", parked.last_error)

    def test_a_bounce_that_cannot_be_sent_leaves_the_message_parked(self):
        self.agent.sender = Sender(os.path.join(self._tmp.name, "missing"))
        self.accept()
        parked = self.refuse(422, {"error": "not a deliverable mailbox", "retryable": False, "code": "no_mailbox"})
        self.assertIn("bounce not sent", parked.last_error)
        self.assertEqual(self.agent.stats["bounced"], 0)

    def test_a_message_that_runs_out_of_retries_is_bounced_to_its_sender(self):
        message = self.accept()
        # One failed attempt is all it may have.
        self.agent.queue.max_attempts = 1
        self.agent.queue.mark_inflight(message)
        self.agent.queue.requeue(message, "HTTP 503: Service Unavailable")
        self.assertEqual(self.agent.queue.due(now=time.time() + 3600), [])
        self.assertEqual(self.agent.queue.stats()["dead"], 1)
        log = self.sendmail.read()
        self.assertIn("-i -f <> -- bob@example.org", log)
        self.assertIn("Status: 4.4.7", log)
        self.assertIn("HTTP 503: Service Unavailable", log)
        parked = self.agent.queue.list_dead()[0]
        self.assertIn("retries exhausted; bounced to bob@example.org", parked.last_error)

    def test_status_codes(self):
        from relay import bounce

        self.assertEqual(bounce.status_for(PermanentError("x", status=413)), "5.3.4")
        self.assertEqual(bounce.status_for(PermanentError("x", status=404, code="no_mailbox")), "5.1.1")
        self.assertEqual(bounce.status_for(PermanentError("x", status=400, code="bad_envelope")), "5.0.0")
        self.assertFalse(bounce.should_bounce("MAILER-DAEMON@example.org"))
        self.assertFalse(bounce.should_bounce(""))
        self.assertTrue(bounce.should_bounce("bob@example.org"))


class HttpClientTests(unittest.TestCase):
    """How answers from the server, and failures reaching it, are classified."""

    def answer(self, status, body):
        error = urllib.error.HTTPError("https://mail.example.com/x", status, "error", {}, io.BytesIO(json.dumps(body).encode()))
        with mock.patch("urllib.request.urlopen", side_effect=error):
            HttpClient().request("https://mail.example.com/x", method="GET")

    def test_no_key_yet_is_a_retryable_404(self):
        with self.assertRaises(RetryableError) as caught:
            self.answer(404, {"error": "no key yet", "retryable": True, "code": "no_key"})
        self.assertEqual(caught.exception.status, 404)

    def test_no_such_mailbox_carries_its_code(self):
        with self.assertRaises(PermanentError) as caught:
            self.answer(404, {"error": "not a deliverable mailbox", "retryable": False, "code": "no_mailbox"})
        self.assertEqual((caught.exception.status, caught.exception.code), (404, "no_mailbox"))

    def test_a_message_too_large_is_permanent(self):
        with self.assertRaises(PermanentError) as caught:
            self.answer(413, {"error": "over the limit", "retryable": False, "code": "too_large"})
        self.assertEqual((caught.exception.status, caught.exception.code), (413, "too_large"))

    def test_a_connection_cut_off_mid_answer_is_retryable(self):
        with mock.patch("urllib.request.urlopen", side_effect=ssl.SSLEOFError(8, "EOF occurred in violation of protocol")):
            with self.assertRaises(RetryableError):
                HttpClient().request("https://mail.example.com/api/relay/inbound/", payload={})


class CommandTests(unittest.TestCase):
    def test_ping_reports_the_node_key(self):
        # The server stores whatever key a heartbeat names, blank included.
        import contextlib

        from relay import cli

        key = generate_key()
        seen = {}

        class Client:
            def __init__(self, config):
                pass

            def health(self):
                return Response(200, "{}", {})

            def heartbeat(self, status, config_digest=""):
                seen.update(status)
                return {}

        names = ("ORBIT_CONFIG_FILE", "ORBIT_RELAY_ENCRYPTION_KEY")
        saved = {name: os.environ.pop(name, None) for name in names}
        os.environ.update(ORBIT_CONFIG_FILE="", ORBIT_RELAY_ENCRYPTION_KEY=key)
        try:
            with mock.patch("relay.transport.MailServerClient", Client), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.cmd_ping(None), 0)
        finally:
            for name in names:
                os.environ.pop(name, None)
                if saved[name] is not None:
                    os.environ[name] = saved[name]
        node = Cipher.from_text(key)
        self.assertEqual((seen["encryption_kid"], seen["encryption_public_key"]), (node.kid, node.public_key_text))


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
