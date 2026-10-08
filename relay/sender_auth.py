"""Who really sent an inbound message: SPF, DKIM and DMARC, then BIMI.

The relay is the MX, so it is the only place that sees the connection a
message arrived on and the message exactly as it was signed. Anything a
message says about itself (an ``Authentication-Results`` header, say) was
written before it got here, by the sender or by whoever handled it on the
way, and proves nothing. So the agent checks the message itself, before
sealing it, and sends the server its verdict beside the ciphertext:

``spf``     the connecting IP against the envelope sender's domain (the HELO
            name for a bounce), read from the ``Received`` line our own
            Postfix put on top and the ``Return-Path`` its pipe added; Postfix
            drops any ``Return-Path`` a sender wrote, and a sender cannot put
            a line above ours.
``dkim``    each signature (up to five) and the domain it vouches for.
``dmarc``   whether either of those is for the ``From:`` domain (relaxed or
            strict, as the domain's DMARC record asks), and the policy that
            applies to it.
``bimi``    for a domain that passed DMARC under an enforcing policy
            (quarantine or reject, on all its mail), its ``default._bimi``
            record: where its logo is (``l=``) and its certificate (``a=``).

Nothing here decides whether mail is delivered. A check that cannot be made
(a DNS timeout, a node without the libraries) leaves that part of the verdict
out, and the message goes on as before. The libraries come from the
distribution (python3-dkim, python3-spf, publicsuffix); without them the agent
sends no verdict at all.
"""

from __future__ import annotations

import email.utils
import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

PUBLIC_SUFFIX_LIST = "/usr/share/publicsuffix/public_suffix_list.dat"
#: Signatures checked per message; a message rarely carries more than two.
MAX_SIGNATURES = 5
#: Seconds for one DNS answer, and for the whole of an SPF evaluation (which
#: may take ten lookups). Postfix waits on the receive hook meanwhile.
DNS_TIMEOUT = 4.0
SPF_TIMEOUT = 10

ENFORCING = ("quarantine", "reject")

#: The line Postfix's smtpd puts on top of every message it receives:
#: ``from <helo> (<reverse name or unknown> [<ip>]) by <host> (Postfix) ...``.
RECEIVED_RE = re.compile(
    r"^from\s+(?P<helo>\S+)\s+\((?:\S+\s+)?\[(?:IPv6:)?(?P<ip>[0-9A-Fa-f:.]+)\](?::\d+)?\)\s+by\s+\S+\s+\(Postfix\)",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


class TempError(Exception):
    """DNS did not answer: the result is unknown, not negative."""


class PublicSuffixList:
    """The public suffix list, for a domain's organizational domain.

    DMARC's relaxed alignment counts ``mail.example.co.uk`` and
    ``example.co.uk`` as one sender because they share the name a registrar
    sold (``example.co.uk``); the list says where that name starts. Without
    the file, every domain's last two labels are taken instead, which is
    wrong for ``co.uk`` and the like but only ever errs towards "not aligned".
    """

    def __init__(self, lines=()):
        self.rules = set()
        self.wildcards = set()
        self.exceptions = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            if rule.startswith("!"):
                self.exceptions.add(rule[1:])
            elif rule.startswith("*."):
                self.wildcards.add(rule[2:])
            else:
                self.rules.add(rule)

    @classmethod
    def load(cls, path=PUBLIC_SUFFIX_LIST):
        try:
            with open(path, encoding="utf-8") as handle:
                return cls(handle)
        except OSError:
            logger.warning("No public suffix list at %s; organizational domains are guessed.", path)
            return cls()

    def organizational_domain(self, domain):
        labels = domain.lower().strip(".").split(".")
        count = len(labels)
        # The longest matching rule wins; scanning from the whole name down
        # finds it first. An exception is always longer than its wildcard.
        suffix = 1
        for start in range(count):
            name = ".".join(labels[start:])
            if name in self.exceptions:
                suffix = count - start - 1
                break
            if name in self.rules or (start + 1 < count and ".".join(labels[start + 1:]) in self.wildcards):
                suffix = count - start
                break
        if suffix >= count:
            return ".".join(labels)
        return ".".join(labels[count - suffix - 1:])


def tags(record):
    """``v=DMARC1; p=reject`` as ``{"v": "DMARC1", "p": "reject"}``; names lowercased."""
    out = {}
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if sep:
            out.setdefault(name.strip().lower(), value.strip())
    return out


def header_from_domain(parsed):
    """The one ``From:`` address's domain, or "" when there is not exactly one."""
    values = parsed.get_all("From") or []
    if len(values) != 1:
        return ""
    addresses = [address for _name, address in email.utils.getaddresses([str(values[0])]) if address]
    if len(addresses) != 1 or "@" not in addresses[0]:
        return ""
    domain = addresses[0].rpartition("@")[2].strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return domain if DOMAIN_RE.match(domain) else ""


def connection(parsed):
    """``(ip, helo)`` from the ``Received`` line our Postfix added, or None."""
    received = parsed.get_all("Received") or []
    if not received:
        return None
    match = RECEIVED_RE.match(" ".join(str(received[0]).split()))
    if not match:
        return None
    try:
        ip = str(ipaddress.ip_address(match.group("ip")))
    except ValueError:
        return None
    return ip, match.group("helo").strip("[]").lower()


def without_mbox_line(raw_bytes):
    """The message without the ``From sender date`` line Postfix's pipe puts first."""
    if raw_bytes.startswith(b"From "):
        return raw_bytes.split(b"\n", 1)[1] if b"\n" in raw_bytes else b""
    return raw_bytes


class SenderCheck:
    """The checks, with DNS, SPF and DKIM passed in so tests need no network.

    ``txt(name)`` returns a name's TXT records as strings ([] when it has
    none) and raises :class:`TempError` when DNS does not answer.
    ``spf(ip, sender, helo)`` returns an SPF result (``pass``, ``fail``,
    ``softfail``, ``neutral``, ``none``, ``temperror``, ``permerror``).
    ``dkim`` is the dkimpy module, and ``dkim_dns`` its ``dnsfunc`` (None for
    its own resolver).
    """

    def __init__(self, txt, spf, dkim, suffixes, dkim_dns=None):
        self.txt = txt
        self.spf = spf
        self.dkim = dkim
        self.dkim_dns = dkim_dns
        self.suffixes = suffixes

    def check(self, raw_bytes, parsed, envelope_from):
        from_domain = header_from_domain(parsed)
        spf_result, spf_domain = "none", ""
        arrived = connection(parsed)
        if arrived:
            spf_result, spf_domain = self.spf_result(*arrived, envelope_from)
        signatures = self.dkim_results(without_mbox_line(raw_bytes))
        verdict = {
            "from_domain": from_domain,
            "spf": spf_result,
            "spf_domain": spf_domain,
            "dkim": signatures,
            "dmarc": "none",
            "dmarc_policy": "",
        }
        if not from_domain:
            return verdict
        try:
            result, policy, enforcing, organizational = self.dmarc(from_domain, spf_result, spf_domain, signatures)
        except TempError:
            verdict["dmarc"] = "temperror"
            return verdict
        verdict["dmarc"], verdict["dmarc_policy"] = result, policy
        if result == "pass" and enforcing:
            try:
                bimi = self.bimi(from_domain, organizational)
            except TempError:
                bimi = None
            if bimi:
                verdict["bimi"] = bimi
        return verdict

    def spf_result(self, ip, helo, envelope_from):
        # A bounce has no sender; SPF checks the HELO name then (RFC 7208, 2.4).
        identity = envelope_from if "@" in envelope_from else f"postmaster@{helo}"
        domain = identity.rpartition("@")[2].strip().rstrip(".").lower()
        try:
            result = str(self.spf(ip, identity, helo) or "none").lower()
        except Exception as error:  # a library error is no reason to lose the rest
            logger.warning("SPF check failed for %s: %s", domain, error)
            result = "temperror"
        return result, domain

    def dkim_results(self, message):
        try:
            checker = self.dkim.DKIM(message, timeout=DNS_TIMEOUT)
            headers = [value for name, value in checker.headers if name.lower() == b"dkim-signature"]
        except Exception as error:
            logger.warning("Could not read the DKIM signatures: %s", error)
            return []
        results = []
        for index, value in enumerate(headers[:MAX_SIGNATURES]):
            try:
                domain = self.dkim.util.parse_tag_value(value).get(b"d", b"").decode("ascii", "replace").lower()
            except Exception:
                domain = ""
            try:
                if self.dkim_dns is None:
                    ok = checker.verify(idx=index)
                else:
                    ok = checker.verify(idx=index, dnsfunc=self.dkim_dns)
            except Exception:
                ok = False
            results.append({"domain": domain, "result": "pass" if ok else "fail"})
        return results

    def record(self, name, version):
        records = [r for r in self.txt(name) if r.strip().lower().startswith(f"v={version}")]
        # More than one is as good as none (RFC 7489, 6.6.3).
        return tags(records[0]) if len(records) == 1 else None

    def dmarc(self, from_domain, spf_result, spf_domain, signatures):
        """``(result, policy, enforcing, organizational domain)``."""
        organizational = self.suffixes.organizational_domain(from_domain)
        record = self.record(f"_dmarc.{from_domain}", "dmarc1")
        at_organizational = False
        if record is None and organizational != from_domain:
            record = self.record(f"_dmarc.{organizational}", "dmarc1")
            at_organizational = True
        if record is None or record.get("p", "").lower() not in ("none",) + ENFORCING:
            return "none", "", False, organizational
        policy = record["p"].lower()
        if at_organizational and record.get("sp", "").lower() in ("none",) + ENFORCING:
            policy = record["sp"].lower()

        def aligned(domain, mode):
            if not domain:
                return False
            if mode == "s":
                return domain == from_domain
            return self.suffixes.organizational_domain(domain) == organizational

        passed = any(s["result"] == "pass" and aligned(s["domain"], record.get("adkim", "r").lower()) for s in signatures)
        passed = passed or (spf_result == "pass" and aligned(spf_domain, record.get("aspf", "r").lower()))

        pct = record.get("pct", "100")
        enforcing = policy in ENFORCING and (not pct.isdigit() or int(pct) >= 100)
        # BIMI asks the same of the organization as a whole: its own policy
        # may not be "none" for its subdomains either.
        if enforcing and organizational != from_domain:
            top = record if at_organizational else self.record(f"_dmarc.{organizational}", "dmarc1")
            enforcing = bool(top) and top.get("p", "").lower() in ENFORCING and top.get("sp", top.get("p", "")).lower() in ENFORCING
        return ("pass" if passed else "fail"), policy, enforcing, organizational

    def bimi(self, from_domain, organizational):
        """The domain's ``default._bimi`` record (else its organization's) as
        ``{"domain", "location", "authority"}``, or None."""
        for domain in dict.fromkeys([from_domain, organizational]):
            record = self.record(f"default._bimi.{domain}", "bimi1")
            if record is None:
                continue
            location = record.get("l", "").split(",")[0].strip()
            authority = record.get("a", "").strip()
            # An empty l= is the domain declining to show a logo.
            if not location.lower().startswith("https://") or len(location) > 1000:
                return None
            if not authority.lower().startswith("https://") or len(authority) > 1000:
                authority = ""
            return {"domain": domain, "location": location, "authority": authority}
        return None


def default_checker():
    """The checks against real DNS, or None when the libraries are missing."""
    try:
        import dkim
        import dkim.util
        import dns.exception
        import dns.resolver
        import spf
    except ImportError:
        return None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT

    def txt(name):
        try:
            answer = resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as error:
            raise TempError(str(error)) from error
        return [b"".join(item.strings).decode("utf-8", "replace") for item in answer]

    def check_spf(ip, sender, helo):
        return spf.check2(i=ip, s=sender, h=helo, timeout=SPF_TIMEOUT, querytime=SPF_TIMEOUT)[0]

    return SenderCheck(txt=txt, spf=check_spf, dkim=dkim, suffixes=PublicSuffixList.load())
