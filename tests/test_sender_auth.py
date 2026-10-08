"""Checking who sent a message: SPF, DKIM and DMARC, then BIMI (sender_auth).

DNS and SPF are stubbed; DKIM is real (dkimpy signs and verifies against a
key made here), so these need python3-dkim but no network. Without dkimpy the
DKIM tests are skipped and the rest still run.
"""

import base64
import email
import email.policy
import json
import os
import tempfile
import unittest

from relay.sender_auth import PublicSuffixList, SenderCheck, TempError, connection, header_from_domain

from test_end_to_end import Harness, ScriptedServer

try:
    import dkim
    import dkim.util
except ImportError:  # the distribution's python3-dkim, on a node
    dkim = None

SUFFIXES = PublicSuffixList(["com", "example", "co.uk", "*.ck", "!www.ck"])
RECEIVED = (
    "Received: from mx.brand.example (mx.brand.example [203.0.113.5])\n"
    "\tby relay1.orbit.test (Postfix) with ESMTPS id 4ABC\n"
    "\tfor <ada@example.com>; Wed,  8 Oct 2026 10:00:01 +0000 (UTC)\n"
)


def message(sender="news@brand.example", from_header="Brand <news@brand.example>", body="Hello there.\r\n"):
    return (
        f"From: {from_header}\r\nTo: ada@example.com\r\nSubject: News\r\n"
        "Date: Wed, 08 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@brand.example>\r\n\r\n" + body
    ).encode()


def piped(signed, sender="news@brand.example"):
    """As Postfix's pipe hands it over: the mbox line, Return-Path, our Received, LF endings."""
    return (
        f"From {sender}  Wed Oct  8 10:00:01 2026\nReturn-Path: <{sender}>\n{RECEIVED}".encode()
        + signed.replace(b"\r\n", b"\n")
    )


class Signer:
    """A DKIM key for brand.example, published as sel._domainkey.<domain>."""

    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public)
        self.domains = set()

    def sign(self, raw, domain="brand.example"):
        self.domains.add(domain)
        headers = [b"from", b"to", b"subject", b"date", b"message-id"]
        return dkim.sign(raw, b"sel", domain.encode(), self.pem, include_headers=headers) + raw

    def dns(self, name, timeout=5):
        for domain in self.domains:
            if name == f"sel._domainkey.{domain}.".encode():
                return self.record
        return None


class Fakes:
    """DNS TXT records and SPF results to check against."""

    def __init__(self, records=None, spf="none"):
        self.records = records or {}
        self.spf_answer = spf
        self.spf_calls = []

    def txt(self, name):
        value = self.records.get(name, [])
        if isinstance(value, Exception):
            raise value
        return value

    def spf(self, ip, sender, helo):
        self.spf_calls.append((ip, sender, helo))
        return self.spf_answer


BRAND = {
    "_dmarc.brand.example": ["v=DMARC1; p=reject; rua=mailto:d@brand.example"],
    "default._bimi.brand.example": ["v=BIMI1; l=https://brand.example/logo.svg; a=https://brand.example/vmc.pem"],
}


def checker(fakes, signer=None):
    return SenderCheck(txt=fakes.txt, spf=fakes.spf, dkim=dkim, suffixes=SUFFIXES, dkim_dns=signer.dns if signer else (lambda name, timeout=5: None))


def run(fakes, raw, signer=None, envelope_from="news@brand.example"):
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    return checker(fakes, signer).check(raw, parsed, envelope_from)


class PieceTests(unittest.TestCase):
    def test_organizational_domains(self):
        self.assertEqual(SUFFIXES.organizational_domain("mail.brand.com"), "brand.com")
        self.assertEqual(SUFFIXES.organizational_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(SUFFIXES.organizational_domain("shop.site.ck"), "shop.site.ck")
        self.assertEqual(SUFFIXES.organizational_domain("a.www.ck"), "www.ck")
        self.assertEqual(SUFFIXES.organizational_domain("co.uk"), "co.uk")
        # Without the list, the last two labels.
        self.assertEqual(PublicSuffixList().organizational_domain("a.b.example.co.uk"), "co.uk")

    def test_the_from_domain_needs_exactly_one_address(self):
        def domain(*values):
            text = "".join(f"From: {value}\r\n" for value in values) + "\r\n"
            return header_from_domain(email.message_from_string(text, policy=email.policy.default))

        self.assertEqual(domain('"Brand, Inc." <News@Brand.Example>'), "brand.example")
        self.assertEqual(domain("a@one.example, b@two.example"), "")
        self.assertEqual(domain("a@one.example", "b@two.example"), "")
        self.assertEqual(domain("nobody"), "")

    def test_the_connection_comes_from_our_postfixs_received_line(self):
        def parse(received):
            return connection(email.message_from_string(received + "Received: from forged (x [198.51.100.1]) by y (Postfix)\n\n", policy=email.policy.default))

        self.assertEqual(parse(RECEIVED), ("203.0.113.5", "mx.brand.example"))
        self.assertEqual(
            parse("Received: from [192.0.2.7] (unknown [192.0.2.7])\n\tby relay1 (Postfix) with ESMTP id X\n"),
            ("192.0.2.7", "192.0.2.7"),
        )
        self.assertEqual(
            parse("Received: from mail.v6.example (mail.v6.example [IPv6:2001:db8::25])\n\tby relay1 (Postfix) with ESMTPS id Y\n"),
            ("2001:db8::25", "mail.v6.example"),
        )
        # Only the top line counts, and only when Postfix wrote it.
        self.assertIsNone(parse("Received: by some-other-mta with HTTP\n"))


@unittest.skipIf(dkim is None, "needs dkimpy (python3-dkim)")
class DmarcTests(unittest.TestCase):
    def setUp(self):
        self.signer = Signer()

    def test_an_aligned_signature_passes_and_finds_the_logo(self):
        verdict = run(Fakes(BRAND), piped(self.signer.sign(message())), self.signer)
        self.assertEqual(verdict["dkim"], [{"domain": "brand.example", "result": "pass"}])
        self.assertEqual((verdict["dmarc"], verdict["dmarc_policy"]), ("pass", "reject"))
        self.assertEqual(verdict["bimi"], {
            "domain": "brand.example", "location": "https://brand.example/logo.svg", "authority": "https://brand.example/vmc.pem",
        })

    def test_spf_reads_the_connection_and_envelope_sender(self):
        fakes = Fakes(BRAND, spf="pass")
        verdict = run(fakes, piped(message(), sender="bounce@mail.brand.example"), envelope_from="bounce@mail.brand.example")
        self.assertEqual(fakes.spf_calls, [("203.0.113.5", "bounce@mail.brand.example", "mx.brand.example")])
        # Relaxed alignment: mail.brand.example and brand.example are one organization.
        self.assertEqual((verdict["spf"], verdict["spf_domain"], verdict["dmarc"]), ("pass", "mail.brand.example", "pass"))
        self.assertIn("bimi", verdict)

    def test_a_bounce_checks_the_helo_name(self):
        fakes = Fakes(BRAND, spf="pass")
        run(fakes, piped(message(), sender=""), envelope_from="")
        self.assertEqual(fakes.spf_calls[0][1], "postmaster@mx.brand.example")

    def test_an_unaligned_pass_is_a_dmarc_fail(self):
        verdict = run(Fakes(BRAND, spf="pass"), piped(self.signer.sign(message(), domain="esp.example")), self.signer, envelope_from="x@esp.example")
        self.assertEqual(verdict["dkim"], [{"domain": "esp.example", "result": "pass"}])
        self.assertEqual(verdict["dmarc"], "fail")
        self.assertNotIn("bimi", verdict)

    def test_strict_alignment_wants_the_exact_domain(self):
        records = dict(BRAND, **{"_dmarc.brand.example": ["v=DMARC1; p=reject; adkim=s"]})
        verdict = run(Fakes(records), piped(self.signer.sign(message(), domain="mail.brand.example")), self.signer)
        self.assertEqual(verdict["dmarc"], "fail")

    def test_a_changed_message_fails(self):
        signed = self.signer.sign(message()).replace(b"Hello", b"Jello")
        verdict = run(Fakes(BRAND), piped(signed), self.signer)
        self.assertEqual(verdict["dkim"], [{"domain": "brand.example", "result": "fail"}])
        self.assertEqual(verdict["dmarc"], "fail")

    def test_no_logo_without_an_enforcing_policy_on_all_mail(self):
        raw = piped(self.signer.sign(message()))
        for record in ("v=DMARC1; p=none", "v=DMARC1; p=quarantine; pct=50"):
            verdict = run(Fakes(dict(BRAND, **{"_dmarc.brand.example": [record]})), raw, self.signer)
            self.assertEqual(verdict["dmarc"], "pass")
            self.assertNotIn("bimi", verdict)
        # A subdomain under its organization's sp=none.
        records = {
            "_dmarc.brand.example": ["v=DMARC1; p=reject; sp=none"],
            "default._bimi.brand.example": BRAND["default._bimi.brand.example"],
        }
        raw = piped(self.signer.sign(message(from_header="news@news.brand.example")))
        verdict = run(Fakes(records), raw, self.signer, envelope_from="news@news.brand.example")
        self.assertEqual((verdict["dmarc"], verdict["dmarc_policy"]), ("pass", "none"))
        self.assertNotIn("bimi", verdict)

    def test_the_organizations_logo_covers_its_subdomains(self):
        raw = piped(self.signer.sign(message(from_header="news@news.brand.example")))
        verdict = run(Fakes(BRAND), raw, self.signer, envelope_from="news@news.brand.example")
        self.assertEqual(verdict["bimi"]["domain"], "brand.example")

    def test_a_declined_or_insecure_logo_is_no_logo(self):
        raw = piped(self.signer.sign(message()))
        for record in ("v=BIMI1; l=; a=;", "v=BIMI1; l=http://brand.example/logo.svg"):
            verdict = run(Fakes(dict(BRAND, **{"default._bimi.brand.example": [record]})), raw, self.signer)
            self.assertNotIn("bimi", verdict)

    def test_dns_trouble_is_no_verdict_rather_than_a_fail(self):
        records = dict(BRAND, **{"_dmarc.brand.example": TempError("timed out")})
        verdict = run(Fakes(records), piped(self.signer.sign(message())), self.signer)
        self.assertEqual(verdict["dmarc"], "temperror")
        self.assertNotIn("bimi", verdict)

    def test_two_dmarc_records_are_no_policy(self):
        records = dict(BRAND, **{"_dmarc.brand.example": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]})
        verdict = run(Fakes(records), piped(self.signer.sign(message())), self.signer)
        self.assertEqual(verdict["dmarc"], "none")
        self.assertNotIn("bimi", verdict)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.server = ScriptedServer()
        self.h = Harness(self._tmp.name, self.server)

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_verdict_travels_beside_the_ciphertext(self):
        verdict = {"from_domain": "example.org", "spf": "pass", "spf_domain": "example.org", "dkim": [], "dmarc": "pass", "dmarc_policy": "reject"}

        class Stub:
            def check(self, raw, parsed, envelope_from):
                return verdict

        self.h.maildrop.sender_check = Stub()
        self.server.queue_reply((200, json.dumps({"status": "stored"})))
        self.assertEqual(self.h.accept().authentication, verdict)
        self.h.drain()
        self.assertEqual(self.server.requests[0]["payload"]["authentication"], verdict)

    def test_a_check_that_breaks_costs_only_the_verdict(self):
        class Broken:
            def check(self, raw, parsed, envelope_from):
                raise RuntimeError("resolver exploded")

        self.h.maildrop.sender_check = Broken()
        self.server.queue_reply((200, json.dumps({"status": "stored"})))
        with self.assertLogs("relay.postfix", level="ERROR"):
            self.assertEqual(self.h.accept().authentication, {})
        self.h.drain()
        self.assertNotIn("authentication", self.server.requests[0]["payload"])
        self.assertEqual(self.h.queue.stats()["pending"], 0)


if __name__ == "__main__":
    unittest.main()
