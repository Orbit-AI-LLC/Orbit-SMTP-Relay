"""Tests for the relay's encryption: sealing inbound mail to the reader's key
and opening outgoing mail sealed to the node's own key.

What matters here is the contract with the other two ends: the Orbit Mail
server must receive something it can file without reading, and the browser
must be able to open it with nothing but the reader's private key. So these
tests check the stored and transmitted shapes, not only that seal followed by
open is the identity.
"""

import base64
import email
import email.policy
import json
import os
import tempfile
import time
import unittest

from relay.config import Config
from relay.crypto import (
    ALGORITHM, ASSOCIATED_DATA, PUBLIC_KEY_BYTES, WRAP_INFO, Cipher, EncryptionError, generate_key, key_id, load_cipher,
    parse_private_key, parse_public_key, public_key_of, scalar_from_seed, seal, write_key_file,
)
from relay.keys import KeyUnavailable, PublicKeyDirectory
from relay.outbound import build_message, decode_item
from relay.postfix import Maildrop, split_headers
from relay.queue import Queue, QueuedMessage
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


class StaticKeys:
    """A key directory that answers from a dict, like the server would.

    A value is one reader's key, or a list of keys for a shared mailbox.
    """

    def __init__(self, **readers):
        self.by_address = {
            address: [Cipher.from_text(text) for text in (texts if isinstance(texts, list) else [texts])]
            for address, texts in readers.items()
        }

    def readers(self, address):
        found = self.by_address.get(address.lower())
        if not found:
            raise KeyUnavailable(f"{address} has not set an encryption key yet.")
        return [(reader.kid, reader.public_key) for reader in found]

    def lookup(self, address):
        return self.readers(address)[0]


class KeyTests(unittest.TestCase):
    def test_generated_keys_are_recognisable_and_distinct(self):
        first, second = generate_key(), generate_key()
        self.assertTrue(first.startswith("orbp_"))
        self.assertNotEqual(first, second)
        self.assertEqual(len(parse_private_key(first)), 32)

    def test_key_id_comes_from_the_public_half(self):
        seed = parse_private_key(generate_key())
        public = public_key_of(seed)
        self.assertEqual(len(public), PUBLIC_KEY_BYTES)
        self.assertTrue(public.startswith(bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")))
        self.assertEqual(key_id(public), key_id(public))
        self.assertEqual(len(key_id(public)), 12)
        self.assertEqual(Cipher(seed).kid, key_id(public))

    def test_the_seed_becomes_a_scalar_the_way_the_browser_does_it(self):
        # seed mod (n - 1) + 1, so a derived key is never zero and the same
        # seed gives the same key in Python and in e2ee.js.
        self.assertEqual(scalar_from_seed(bytes(32)), 1)
        self.assertEqual(scalar_from_seed(b"\xff" * 32), (2 ** 256 - 1) % (0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 - 1) + 1)

    def test_public_keys_parse_in_either_base64_alphabet(self):
        public = public_key_of(parse_private_key(generate_key()))
        standard = base64.b64encode(public).decode()
        urlsafe = base64.urlsafe_b64encode(public).decode().rstrip("=")
        self.assertEqual(parse_public_key(standard), public)
        self.assertEqual(parse_public_key(urlsafe), public)
        # The same SPKI form Orbit Chat stores for a person's identity.
        from cryptography.hazmat.primitives import serialization

        self.assertIsNotNone(serialization.load_der_public_key(public))

    def test_malformed_keys_are_rejected(self):
        for bad in ("", "orbk_not-this-kind", "orbe_old-format", "orbp_dG9vc2hvcnQ", "orbp_!!!"):
            with self.subTest(bad=bad), self.assertRaises(EncryptionError):
                parse_private_key(bad)
        off_curve = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04" + b"\x01" * 64
        for bad in ("", "dG9vc2hvcnQ", "***", base64.b64encode(b"\x00" * 91).decode(), base64.b64encode(off_curve).decode()):
            with self.subTest(bad=bad), self.assertRaises(EncryptionError):
                parse_public_key(bad)

    def test_key_file_is_owner_only_and_not_clobbered(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "relay.key")
            write_key_file(path, generate_key())
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            with self.assertRaises(EncryptionError):
                write_key_file(path, generate_key())
            write_key_file(path, generate_key(), overwrite=True)
            config = make_config(encryption_key="", encryption_key_file=path)
            self.assertIsNotNone(load_cipher(config))
            self.assertEqual(config.validate(), [])

    def test_config_reports_a_missing_or_unreadable_key(self):
        problems = make_config(encryption_key="", encryption_key_file="/nonexistent/relay.key").validate()
        self.assertTrue(any("Encryption" in p for p in problems))
        problems = make_config(encryption_key="", encryption_key_file="").validate()
        self.assertTrue(any("required" in p for p in problems))
        with self.assertRaises(EncryptionError):
            load_cipher(make_config(encryption_key="", encryption_key_file=""))


class SealTests(unittest.TestCase):
    def setUp(self):
        self.reader = Cipher.from_text(generate_key())

    def test_seal_and_open_round_trip(self):
        envelope, ciphertext = seal(b"hello", [(self.reader.kid, self.reader.public_key)])
        self.assertEqual(envelope["v"], 2)
        self.assertEqual(envelope["alg"], ALGORITHM)
        self.assertEqual(envelope["kid"], self.reader.kid)
        self.assertEqual(len(base64.b64decode(envelope["nonce"])), 12)
        self.assertEqual([k["kid"] for k in envelope["keys"]], [self.reader.kid])
        self.assertEqual(self.reader.open(envelope, ciphertext), b"hello")

    def test_each_message_gets_fresh_parameters(self):
        first, _ = seal(b"x", [(self.reader.kid, self.reader.public_key)])
        second, _ = seal(b"x", [(self.reader.kid, self.reader.public_key)])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["keys"][0]["epk"], second["keys"][0]["epk"])

    def test_several_readers_can_open_one_ciphertext(self):
        other = Cipher.from_text(generate_key())
        envelope, ciphertext = seal(b"shared", [(self.reader.kid, self.reader.public_key), (other.kid, other.public_key)])
        self.assertEqual(envelope["kid"], self.reader.kid)
        self.assertEqual(self.reader.open(envelope, ciphertext), b"shared")
        self.assertEqual(other.open(envelope, ciphertext), b"shared")

    def test_wrong_key_cannot_open(self):
        envelope, ciphertext = seal(b"secret", [(self.reader.kid, self.reader.public_key)])
        other = Cipher.from_text(generate_key())
        with self.assertRaises(EncryptionError):
            other.open(envelope, ciphertext)
        forged = dict(envelope, keys=[dict(envelope["keys"][0], kid=other.kid)])
        with self.assertRaises(EncryptionError):
            other.open(forged, ciphertext)

    def test_tampering_is_detected(self):
        envelope, ciphertext = seal(b"secret", [(self.reader.kid, self.reader.public_key)])
        raw = bytearray(base64.b64decode(ciphertext))
        raw[0] ^= 0x01
        with self.assertRaises(EncryptionError):
            self.reader.open(envelope, base64.b64encode(bytes(raw)).decode())
        wrapped = bytearray(base64.b64decode(envelope["keys"][0]["wk"]))
        wrapped[0] ^= 0x01
        tampered = dict(envelope, keys=[dict(envelope["keys"][0], wk=base64.b64encode(bytes(wrapped)).decode())])
        with self.assertRaises(EncryptionError):
            self.reader.open(tampered, ciphertext)

    def test_format_matches_webcrypto_expectations(self):
        # The browser does ECDH P-256 agreement with the ephemeral key (SPKI),
        # HKDF-SHA256 with this info string, AES-GCM over the wrapped content
        # key with the key id as associated data, then AES-GCM over the
        # message with a 12-byte nonce, a 128-bit tag at the end and this
        # associated data. Check the layout directly against the primitives
        # so a refactor cannot drift from what e2ee.js implements.
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        envelope, ciphertext = seal(b"body", [(self.reader.kid, self.reader.public_key)])
        entry = envelope["keys"][0]
        ephemeral = base64.b64decode(entry["epk"])
        self.assertEqual(len(ephemeral), PUBLIC_KEY_BYTES)
        private = ec.derive_private_key(scalar_from_seed(self.reader._seed), ec.SECP256R1())
        shared = private.exchange(ec.ECDH(), serialization.load_der_public_key(ephemeral))
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=WRAP_INFO + ephemeral + self.reader.public_key).derive(shared)
        content_key = AESGCM(kek).decrypt(base64.b64decode(entry["iv"]), base64.b64decode(entry["wk"]), self.reader.kid.encode())
        self.assertEqual(len(content_key), 32)
        data = base64.b64decode(ciphertext)
        self.assertEqual(len(data), len(b"body") + 16)
        self.assertEqual(AESGCM(content_key).decrypt(base64.b64decode(envelope["nonce"]), data, ASSOCIATED_DATA), b"body")


class KeyDirectoryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.reader = Cipher.from_text(generate_key())
        self.client = MailServerClient(make_config())
        self.requests = []
        self.replies = []

        def fake(url, *, method="POST", payload=None, headers=None, timeout=None):
            self.requests.append(url)
            reply = self.replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        self.client.http.request = fake
        self.directory = PublicKeyDirectory(self.client, os.path.join(self._tmp.name, "keys"), ttl=600, missing_ttl=60)

    def tearDown(self):
        self._tmp.cleanup()

    def found(self):
        return Response(200, json.dumps({"address": "alice@example.com", "kid": self.reader.kid, "public_key": self.reader.public_key_text}), {})

    def test_fetches_once_then_serves_from_cache(self):
        self.replies.append(self.found())
        self.assertEqual(self.directory.lookup("Alice@example.com"), (self.reader.kid, self.reader.public_key))
        self.assertEqual(self.directory.lookup("alice@example.com"), (self.reader.kid, self.reader.public_key))
        self.assertEqual(len(self.requests), 1)
        self.assertIn("address=alice%40example.com", self.requests[0])
        self.assertTrue(self.requests[0].startswith("https://mail.example.com/api/relay/keys/"))

    def test_reader_without_a_key_is_retryable_and_remembered_briefly(self):
        self.replies.append(PermanentError("HTTP 404: no key", status=404))
        with self.assertRaises(KeyUnavailable) as caught:
            self.directory.lookup("alice@example.com")
        self.assertTrue(caught.exception.retryable)
        with self.assertRaises(KeyUnavailable):
            self.directory.lookup("alice@example.com")
        self.assertEqual(len(self.requests), 1)

    def test_no_key_answer_is_remembered_and_never_served_from_a_stale_cache(self):
        # The server sends no_key as a retryable 404. A reader list cached
        # earlier is no longer the right one, so it is not used.
        self.directory._write("alice@example.com", {
            "address": "alice@example.com", "readers": [{"kid": self.reader.kid, "public_key": self.reader.public_key_text}],
            "fetched_at": time.time() - 3600,
        })
        self.replies.append(RetryableError("HTTP 404: alice@example.com has no encryption key yet.", status=404))
        with self.assertRaises(KeyUnavailable) as caught:
            self.directory.readers("alice@example.com")
        self.assertTrue(caught.exception.retryable)
        with self.assertRaises(KeyUnavailable):
            self.directory.readers("alice@example.com")
        self.assertEqual(len(self.requests), 1)

    def test_no_such_mailbox_is_not_retryable(self):
        self.replies.append(PermanentError("HTTP 404: not a deliverable mailbox", status=404, code="no_mailbox"))
        with self.assertRaises(KeyUnavailable) as caught:
            self.directory.readers("gone@example.com")
        self.assertFalse(caught.exception.retryable)

    def test_forbidden_mailbox_is_not_retryable(self):
        self.replies.append(PermanentError("HTTP 403: not yours", status=403))
        with self.assertRaises(KeyUnavailable) as caught:
            self.directory.lookup("alice@example.com")
        self.assertFalse(caught.exception.retryable)

    def test_server_outage_uses_a_recent_key_and_otherwise_defers(self):
        self.replies.append(RetryableError("down"))
        with self.assertRaises(KeyUnavailable) as caught:
            self.directory.lookup("alice@example.com")
        self.assertTrue(caught.exception.retryable)
        self.replies.append(self.found())
        self.directory.lookup("alice@example.com")
        # Expire the cache, then take the server away: the stale key still serves.
        self.directory.ttl = 0
        time.sleep(0.01)
        self.replies.append(RetryableError("down"))
        self.assertEqual(self.directory.lookup("alice@example.com"), (self.reader.kid, self.reader.public_key))

    def test_every_reader_of_a_shared_mailbox_is_returned(self):
        other = Cipher.from_text(generate_key())
        body = {
            "address": "support@example.com", "kid": self.reader.kid, "public_key": self.reader.public_key_text,
            "readers": [
                {"kid": self.reader.kid, "public_key": self.reader.public_key_text},
                {"kid": other.kid, "public_key": other.public_key_text},
            ],
        }
        self.replies.append(Response(200, json.dumps(body), {}))
        expected = [(self.reader.kid, self.reader.public_key), (other.kid, other.public_key)]
        self.assertEqual(self.directory.readers("support@example.com"), expected)
        self.assertEqual(self.directory.readers("support@example.com"), expected)
        self.assertEqual(self.directory.lookup("support@example.com"), expected[0])
        self.assertEqual(len(self.requests), 1)

    def test_a_reader_with_a_mismatched_id_spoils_the_lookup(self):
        other = Cipher.from_text(generate_key())
        body = {"readers": [
            {"kid": self.reader.kid, "public_key": self.reader.public_key_text},
            {"kid": "000000000000", "public_key": other.public_key_text},
        ]}
        self.replies.append(Response(200, json.dumps(body), {}))
        with self.assertRaises(KeyUnavailable) as caught:
            self.directory.readers("support@example.com")
        self.assertFalse(caught.exception.retryable)

    def test_a_cache_written_by_an_older_relay_still_serves(self):
        self.directory._write("alice@example.com", {
            "address": "alice@example.com", "kid": self.reader.kid,
            "public_key": self.reader.public_key_text, "fetched_at": time.time(),
        })
        self.assertEqual(self.directory.readers("alice@example.com"), [(self.reader.kid, self.reader.public_key)])
        self.assertEqual(self.requests, [])

    def test_mismatched_key_id_is_refused(self):
        self.replies.append(Response(200, json.dumps({"kid": "000000000000", "public_key": self.reader.public_key_text}), {}))
        with self.assertRaises(KeyUnavailable) as caught:
            self.directory.lookup("alice@example.com")
        self.assertFalse(caught.exception.retryable)


class InboundEncryptionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.reader_text = generate_key()
        self.reader = Cipher.from_text(self.reader_text)
        self.queue = Queue(os.path.join(self.root, "queue"))
        self.queue.ensure_dirs()
        self.maildrop_dir = os.path.join(self.root, "incoming")
        os.makedirs(self.maildrop_dir)
        self.maildrop = Maildrop(self.maildrop_dir, self.queue, "relay-test", keys=StaticKeys(**{"alice@example.com": self.reader_text}))

    def tearDown(self):
        self._tmp.cleanup()

    def accept(self, raw=RAW, name="alice@example.com"):
        with open(os.path.join(self.maildrop_dir, name), "w") as handle:
            handle.write(raw)
        claimed = self.maildrop.claim(name)
        try:
            message = self.maildrop.process_file(claimed)
        except Exception:
            self.maildrop.release(claimed)
            raise
        self.maildrop.discard(claimed)
        return message

    def test_maildrop_refuses_to_exist_without_keys(self):
        with self.assertRaises(EncryptionError):
            Maildrop(self.maildrop_dir, self.queue, "relay-test")

    def test_split_headers(self):
        head, body = split_headers(b"A: 1\r\nB: 2\r\n\r\nbody\r\n")
        self.assertEqual((head, body), (b"A: 1\r\nB: 2", b"body\r\n"))
        self.assertEqual(split_headers(b"A: 1\n\nbody"), (b"A: 1", b"body"))
        self.assertEqual(split_headers(b"A: 1"), (b"A: 1", b""))
        # Postfix pipes bare LF; a CRLF blank line later on is body.
        self.assertEqual(split_headers(b"A: 1\n\nsecret\r\n\r\nmore"), (b"A: 1", b"secret\r\n\r\nmore"))

    def test_plaintext_never_touches_the_queue(self):
        message = self.accept()
        self.assertTrue(message.is_encrypted)
        self.assertEqual(message.recipient, "alice@example.com")
        self.assertEqual(message.encoding, "base64")
        self.assertEqual(message.encryption["kid"], self.reader.kid)
        self.assertIn("Subject: Lunch", message.headers)
        self.assertNotIn("Noon?", message.headers)
        self.assertFalse(message.has_attachments)
        self.assertEqual(message.plain_size, len(RAW))
        with open(os.path.join(self.queue.pending_dir, f"{message.id}.json"), "rb") as handle:
            on_disk = handle.read()
        self.assertNotIn(b"Noon?", on_disk)
        self.assertEqual(self.reader.open(message.encryption, message.raw), RAW.encode())

    def test_shared_mailbox_mail_opens_for_every_member(self):
        members = [generate_key(), generate_key(), generate_key()]
        self.maildrop.keys = StaticKeys(**{"support@example.com": members})
        message = self.accept(raw=RAW.replace("alice@example.com", "support@example.com"), name="support@example.com")
        self.assertEqual(len(message.encryption["keys"]), 3)
        for text in members:
            self.assertEqual(Cipher.from_text(text).open(message.encryption, message.raw), RAW.replace("alice@example.com", "support@example.com").encode())

    def test_a_suffixed_drop_file_is_for_the_address(self):
        # The receive hook adds a numeric suffix to every drop file.
        message = self.accept(name="alice@example.com.4242")
        self.assertEqual(message.recipient, "alice@example.com")

    def test_reader_without_a_key_is_not_queued(self):
        with self.assertRaises(KeyUnavailable):
            self.accept(name="nobody@example.com")
        self.assertEqual(self.queue.stats()["pending"], 0)
        # The drop file is back where Postfix left it, for the next attempt.
        self.assertTrue(os.path.exists(os.path.join(self.maildrop_dir, "nobody@example.com")))

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
        self.assertEqual(self.reader.open(seen["encrypted"], seen["raw"]), RAW.encode())

    def test_readable_queue_files_are_parked_not_posted(self):
        legacy = QueuedMessage(id="legacy1", recipient="alice@example.com", raw=RAW)
        self.assertFalse(legacy.is_encrypted)
        client = MailServerClient(make_config())
        client.http.request = lambda *a, **k: self.fail("a readable message must never be posted")
        with self.assertRaises(PermanentError):
            client.deliver(legacy)


class OutboundEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.node = Cipher.from_text(generate_key())
        self.author = Cipher.from_text(generate_key())

    def compose_item(self, readers=None, **extra):
        document = {"body": "Hello from the browser", "attachments": [
            {"filename": "note.txt", "content_type": "text/plain", "data_base64": base64.b64encode(b"note").decode()},
        ]}
        readers = readers or [(self.author.kid, self.author.public_key), (self.node.kid, self.node.public_key)]
        envelope, ciphertext = seal(json.dumps(document).encode(), readers)
        item = {
            "id": "ob-1", "envelope_from": "ada@example.com", "recipients": ["bob@example.org"],
            "raw_base64": ciphertext, "encrypted": envelope, "format": "compose",
            "headers": {"From": "Ada <ada@example.com>", "To": "bob@example.org", "Subject": "Sealed",
                        "Message-ID": "<x@example.com>", "Bcc": "hidden@example.net"},
        }
        item.update(extra)
        return item

    def test_build_message_from_decrypted_document(self):
        raw = decode_item(self.compose_item(), self.node)
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
        self.assertEqual(decode_item({"raw_base64": base64.b64encode(b"hi").decode()}, self.node), b"hi")
        self.assertEqual(decode_item({"raw": "hi"}, None), b"hi")

    def test_mime_format_is_passed_through(self):
        envelope, ciphertext = seal(RAW.encode(), [(self.node.kid, self.node.public_key)])
        self.assertEqual(decode_item({"raw_base64": ciphertext, "encrypted": envelope, "format": "mime"}, self.node), RAW.encode())

    def test_missing_or_wrong_key_raises(self):
        with self.assertRaises(EncryptionError):
            decode_item(self.compose_item(), None)
        only_author = self.compose_item(readers=[(self.author.kid, self.author.public_key)])
        with self.assertRaises(EncryptionError):
            decode_item(only_author, self.node)

    def test_a_message_that_cannot_be_built_fails_without_holding_up_the_batch(self):
        from tests.test_end_to_end import FakeSendmail, ScriptedServer
        from relay.agent import RelayAgent

        with tempfile.TemporaryDirectory() as root:
            fake = FakeSendmail(root)
            config = make_config(queue_dir=os.path.join(root, "q"), maildrop_dir=os.path.join(root, "m"),
                                 state_dir=os.path.join(root, "s"), sendmail_path=fake.path, log_backend="memory")
            broken = self.compose_item(id="ob-1")
            broken["headers"]["Subject"] = "Hi\nBcc: someone@example.net"
            good = self.compose_item(id="ob-2")
            server = ScriptedServer()
            server.queue_reply(
                (200, json.dumps({"messages": [broken, good], "remaining": 0})),
                (200, json.dumps({"id": "ob-1", "status": "failed"})),
                (200, json.dumps({"id": "ob-2", "status": "sent"})),
            )
            agent = RelayAgent(config=config, cipher=self.node)
            agent.server.http.request = server
            self.assertEqual(agent.send_batch(), 2)
            reports = {r["url"].split("/")[-3]: r["payload"]["status"] for r in server.requests[1:]}
            self.assertEqual(reports, {"ob-1": "failed", "ob-2": "sent"})
            self.assertIn("Hello from the browser", fake.read())

    def test_agent_defers_when_not_sealed_to_it_and_sends_when_it_is(self):
        from tests.test_end_to_end import FakeSendmail, ScriptedServer
        from relay.agent import RelayAgent

        with tempfile.TemporaryDirectory() as root:
            fake = FakeSendmail(root)
            config = make_config(queue_dir=os.path.join(root, "q"), maildrop_dir=os.path.join(root, "m"),
                                 state_dir=os.path.join(root, "s"), sendmail_path=fake.path, log_backend="memory")
            server = ScriptedServer()
            server.queue_reply((200, json.dumps({"id": "ob-1", "status": "deferred"})))
            agent = RelayAgent(config=config, cipher=Cipher.from_text(generate_key()))
            agent.server.http.request = server
            self.assertEqual(agent.send_one(self.compose_item()), "deferred")
            self.assertIn("not sealed", server.requests[0]["payload"]["error"])

            server.queue_reply((200, json.dumps({"id": "ob-1", "status": "sent"})))
            agent = RelayAgent(config=config, cipher=self.node)
            agent.server.http.request = server
            self.assertEqual(agent.send_one(self.compose_item()), "sent")
            self.assertIn("Hello from the browser", fake.read())
            self.assertEqual(agent.status()["encryption"]["kid"], self.node.kid)
            self.assertEqual(agent.status()["encryption"]["public_key"], self.node.public_key_text)
            report = agent.status_report()
            self.assertEqual(report["encryption_kid"], self.node.kid)
            self.assertEqual(report["encryption_public_key"], self.node.public_key_text)


if __name__ == "__main__":
    unittest.main()
