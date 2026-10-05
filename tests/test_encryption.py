"""Tests for the relay's optional encryption mode.

What matters here is the contract with the other two ends: the Orbit Mail
server must receive something it can file without reading, and the browser
must be able to open it with nothing but the shared key. So these tests check
the stored and transmitted shapes, not only that encrypt followed by decrypt
is the identity.
"""

import base64
import email
import email.policy
import json
import os
import tempfile
import unittest

from relay.config import Config
from relay.crypto import ASSOCIATED_DATA, Cipher, EncryptionError, generate_key, key_id, load_cipher, parse_key, write_key_file
from relay.outbound import build_message, decode_item
from relay.postfix import Maildrop, split_headers
from relay.queue import Queue, QueuedMessage
from relay.transport import MailServerClient, Response

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
                  server_url="https://mail.example.com", api_key="orbk_test", postfix_dir="")
    values.update(overrides)
    return Config(**values)


class KeyTests(unittest.TestCase):
    def test_generated_keys_are_recognisable_and_distinct(self):
        first, second = generate_key(), generate_key()
        self.assertTrue(first.startswith("orbe_"))
        self.assertNotEqual(first, second)
        self.assertEqual(len(parse_key(first)), 32)

    def test_key_id_is_short_and_stable(self):
        raw = parse_key(generate_key())
        self.assertEqual(key_id(raw), key_id(raw))
        self.assertEqual(len(key_id(raw)), 12)

    def test_malformed_keys_are_rejected(self):
        for bad in ("", "orbk_not-this-kind", "orbe_dG9vc2hvcnQ", "orbe_!!!"):
            with self.subTest(bad=bad), self.assertRaises(EncryptionError):
                parse_key(bad)

    def test_key_file_is_owner_only_and_not_clobbered(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "relay.key")
            key = generate_key()
            write_key_file(path, key)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            with self.assertRaises(EncryptionError):
                write_key_file(path, generate_key())
            write_key_file(path, generate_key(), overwrite=True)
            config = make_config(encryption_key_file=path)
            self.assertIsNotNone(load_cipher(config))
            self.assertEqual(config.validate(), [])

    def test_config_reports_an_unreadable_key_file(self):
        problems = make_config(encryption_key_file="/nonexistent/relay.key").validate()
        self.assertTrue(any("Encryption" in p for p in problems))

    def test_config_without_a_key_has_no_cipher(self):
        self.assertIsNone(load_cipher(make_config()))
        self.assertFalse(make_config().encryption_enabled)


class CipherTests(unittest.TestCase):
    def setUp(self):
        self.cipher = Cipher.from_text(generate_key())

    def test_seal_and_open_round_trip(self):
        envelope, ciphertext = self.cipher.seal(b"hello")
        self.assertEqual(envelope["alg"], "A256GCM")
        self.assertEqual(envelope["kid"], self.cipher.kid)
        self.assertEqual(len(base64.b64decode(envelope["nonce"])), 12)
        self.assertEqual(self.cipher.open(envelope, ciphertext), b"hello")

    def test_each_message_gets_a_fresh_nonce(self):
        first, _ = self.cipher.seal(b"x")
        second, _ = self.cipher.seal(b"x")
        self.assertNotEqual(first["nonce"], second["nonce"])

    def test_wrong_key_cannot_open(self):
        envelope, ciphertext = self.cipher.seal(b"secret")
        other = Cipher.from_text(generate_key())
        with self.assertRaises(EncryptionError):
            other.open(dict(envelope, kid=other.kid), ciphertext)
        with self.assertRaises(EncryptionError):
            other.open(envelope, ciphertext)

    def test_tampering_is_detected(self):
        envelope, ciphertext = self.cipher.seal(b"secret")
        raw = bytearray(base64.b64decode(ciphertext))
        raw[0] ^= 0x01
        with self.assertRaises(EncryptionError):
            self.cipher.open(envelope, base64.b64encode(bytes(raw)).decode())

    def test_format_matches_webcrypto_expectations(self):
        # The browser decrypts with AES-GCM, a 12-byte IV, a 128-bit tag at
        # the end of the ciphertext and this exact associated data. Check the
        # layout directly against the primitive so a refactor cannot drift.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        envelope, ciphertext = self.cipher.seal(b"body")
        nonce = base64.b64decode(envelope["nonce"])
        data = base64.b64decode(ciphertext)
        self.assertEqual(len(data), len(b"body") + 16)
        self.assertEqual(AESGCM(self.cipher._key).decrypt(nonce, data, ASSOCIATED_DATA), b"body")


class InboundEncryptionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.cipher = Cipher.from_text(generate_key())
        self.queue = Queue(os.path.join(self.root, "queue"))
        self.queue.ensure_dirs()
        self.maildrop_dir = os.path.join(self.root, "incoming")
        os.makedirs(self.maildrop_dir)
        self.maildrop = Maildrop(self.maildrop_dir, self.queue, "relay-test", cipher=self.cipher)

    def tearDown(self):
        self._tmp.cleanup()

    def accept(self, raw=RAW, name="alice@example.com"):
        with open(os.path.join(self.maildrop_dir, name), "w") as handle:
            handle.write(raw)
        claimed = self.maildrop.claim(name)
        message = self.maildrop.process_file(claimed)
        self.maildrop.discard(claimed)
        return message

    def test_split_headers(self):
        head, body = split_headers(b"A: 1\r\nB: 2\r\n\r\nbody\r\n")
        self.assertEqual((head, body), (b"A: 1\r\nB: 2", b"body\r\n"))
        self.assertEqual(split_headers(b"A: 1\n\nbody"), (b"A: 1", b"body"))
        self.assertEqual(split_headers(b"A: 1"), (b"A: 1", b""))

    def test_plaintext_never_touches_the_queue(self):
        message = self.accept()
        self.assertTrue(message.is_encrypted)
        self.assertEqual(message.recipient, "alice@example.com")
        self.assertEqual(message.encoding, "base64")
        self.assertIn("Subject: Lunch", message.headers)
        self.assertNotIn("Noon?", message.headers)
        self.assertFalse(message.has_attachments)
        self.assertEqual(message.plain_size, len(RAW))
        with open(os.path.join(self.queue.pending_dir, f"{message.id}.json"), "rb") as handle:
            on_disk = handle.read()
        self.assertNotIn(b"Noon?", on_disk)
        self.assertEqual(self.cipher.open(message.encryption, message.raw), RAW.encode())

    def test_attachments_are_flagged_without_being_read(self):
        raw = (
            "From: bob@example.org\r\nTo: alice@example.com\r\nSubject: File\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n'
            '--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename="a.pdf"\r\n\r\nPDF\r\n--b--\r\n'
        )
        message = self.accept(raw=raw)
        self.assertTrue(message.has_attachments)
        self.assertNotIn("PDF", message.headers)

    def test_queue_round_trips_encrypted_fields(self):
        message = self.accept()
        reopened = Queue(self.queue.root)
        stored = reopened.peek(message.id)
        self.assertEqual(stored.encryption, message.encryption)
        self.assertEqual(stored.headers, message.headers)
        self.assertTrue(stored.is_encrypted)

    def test_delivery_payload_carries_the_envelope(self):
        message = self.accept()
        client = MailServerClient(make_config())
        seen = {}

        def fake(url, *, method="POST", payload=None, headers=None, timeout=None):
            seen.update(payload)
            return Response(200, json.dumps({"status": "stored"}), {})

        client.http.request = fake
        client.deliver(message)
        self.assertEqual(seen["encrypted"], message.encryption)
        self.assertEqual(seen["headers"], message.headers)
        self.assertEqual(seen["encoding"], "base64")
        self.assertEqual(seen["size"], len(RAW))
        self.assertNotIn("Noon?", base64.b64decode(seen["raw"]).decode("latin-1"))
        self.assertEqual(self.cipher.open(seen["encrypted"], seen["raw"]), RAW.encode())

    def test_old_queue_files_without_the_new_fields_still_load(self):
        legacy = QueuedMessage.from_dict({"id": "abc", "recipient": "a@b.c", "raw": RAW})
        self.assertFalse(legacy.is_encrypted)
        self.assertEqual(legacy.encoding, "")


class OutboundEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.cipher = Cipher.from_text(generate_key())

    def compose_item(self, cipher=None, **extra):
        cipher = cipher or self.cipher
        document = {"body": "Hello from the browser", "attachments": [
            {"filename": "note.txt", "content_type": "text/plain", "data_base64": base64.b64encode(b"note").decode()},
        ]}
        envelope, ciphertext = cipher.seal(json.dumps(document).encode())
        item = {
            "id": "ob-1", "envelope_from": "ada@example.com", "recipients": ["bob@example.org"],
            "raw_base64": ciphertext, "encrypted": envelope, "format": "compose",
            "headers": {"From": "Ada <ada@example.com>", "To": "bob@example.org", "Subject": "Sealed",
                        "Message-ID": "<x@example.com>", "Bcc": "hidden@example.net"},
        }
        item.update(extra)
        return item

    def test_build_message_from_decrypted_document(self):
        raw = decode_item(self.compose_item(), self.cipher)
        parsed = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertEqual(parsed["Subject"], "Sealed")
        self.assertEqual(parsed["Message-ID"], "<x@example.com>")
        self.assertIsNone(parsed["Bcc"])
        self.assertEqual(parsed.get_body(preferencelist=("plain",)).get_content().strip(), "Hello from the browser")
        attachments = [p for p in parsed.iter_attachments()]
        self.assertEqual([a.get_filename() for a in attachments], ["note.txt"])
        self.assertEqual(attachments[0].get_content(), "note")

    def test_build_message_fills_in_date_and_id(self):
        parsed = email.message_from_bytes(build_message({"From": "a@example.com"}, "x"), policy=email.policy.default)
        self.assertTrue(parsed["Date"])
        self.assertTrue(parsed["Message-ID"].endswith("@example.com>"))

    def test_plain_items_are_untouched(self):
        self.assertEqual(decode_item({"raw_base64": base64.b64encode(b"hi").decode()}, self.cipher), b"hi")
        self.assertEqual(decode_item({"raw": "hi"}, None), b"hi")

    def test_mime_format_is_passed_through(self):
        envelope, ciphertext = self.cipher.seal(RAW.encode())
        self.assertEqual(decode_item({"raw_base64": ciphertext, "encrypted": envelope, "format": "mime"}, self.cipher), RAW.encode())

    def test_missing_or_wrong_key_raises(self):
        with self.assertRaises(EncryptionError):
            decode_item(self.compose_item(), None)
        with self.assertRaises(EncryptionError):
            decode_item(self.compose_item(), Cipher.from_text(generate_key()))

    def test_agent_defers_when_it_lacks_the_key_and_sends_when_it_has_it(self):
        from tests.test_end_to_end import FakeSendmail, ScriptedServer
        from relay.agent import RelayAgent

        with tempfile.TemporaryDirectory() as root:
            fake = FakeSendmail(root)
            config = make_config(queue_dir=os.path.join(root, "q"), maildrop_dir=os.path.join(root, "m"),
                                 sendmail_path=fake.path, log_backend="memory")
            server = ScriptedServer()
            server.queue_reply((200, json.dumps({"id": "ob-1", "status": "deferred"})))
            agent = RelayAgent(config=config, cipher=Cipher.from_text(generate_key()))
            agent.server.http.request = server
            self.assertEqual(agent.send_one(self.compose_item()), "deferred")
            self.assertIn("not", server.requests[0]["payload"]["error"])

            server.queue_reply((200, json.dumps({"id": "ob-1", "status": "sent"})))
            agent = RelayAgent(config=config, cipher=self.cipher)
            agent.server.http.request = server
            self.assertEqual(agent.send_one(self.compose_item()), "sent")
            self.assertIn("Hello from the browser", fake.read())
            self.assertEqual(agent.status()["encryption"]["kid"], self.cipher.kid)
            self.assertEqual(agent.status_report()["encryption_kid"], self.cipher.kid)


if __name__ == "__main__":
    unittest.main()
