"""SPF / DKIM / DMARC authentication checks.

All lookups go through dnspython with short timeouts and degrade gracefully:
if DNS is unreachable (offline sandbox, firewalled network, NXDOMAIN), every
check returns status "unavailable" instead of raising. These are *defensive*
read-only DNS queries - no packets are crafted or sent beyond normal
resolver traffic.
"""
import re
from dataclasses import dataclass, field

try:
    import dns.resolver
    import dns.exception
    _DNS_OK = True
except ImportError:  # pragma: no cover - dnspython is a hard requirement
    _DNS_OK = False

_DKIM_SIG_RE = re.compile(r"\bs\s*=\s*([^;\s]+)", re.IGNORECASE)
_DKIM_DOMAIN_RE = re.compile(r"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)


@dataclass
class AuthCheck:
    mechanism: str            # spf | dkim | dmarc
    status: str               # pass | fail | softfail | none | unavailable | neutral
    detail: str = ""
    record: str = ""


def _txt_records(name: str, timeout: float = 4.0) -> list[str]:
    """Return TXT records for name, or [] on any DNS failure."""
    if not _DNS_OK:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(name, "TXT")
        out = []
        for r in answers:
            txt = b"".join(r.strings).decode("utf-8", errors="replace")
            out.append(txt)
        return out
    except (dns.exception.DNSException, OSError):
        return []


def _probe_any() -> bool:
    if not _DNS_OK:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 3.0
        resolver.resolve("example.com", "A")
        return True
    except (dns.exception.DNSException, OSError):
        return False


def check_spf(domain: str) -> AuthCheck:
    """Simplified SPF posture check for the sender domain.

    A full SPF evaluation needs the connecting IP; without it we report the
    domain's published posture (record present? hardfail vs softfail vs none).
    """
    if not domain:
        return AuthCheck("spf", "none", "no sender domain to check")
    records = [t for t in _txt_records(domain) if t.lower().startswith("v=spf1")]
    if not records:
        if not _probe_any():
            return AuthCheck("spf", "unavailable", "DNS unreachable - check skipped")
        return AuthCheck("spf", "none",
                         f"no SPF record published for {domain} - spoofing is trivial")
    rec = records[0]
    if rec.strip().endswith("-all"):
        return AuthCheck("spf", "pass",
                         f"domain publishes a hardfail SPF policy ({domain})", rec)
    if "~all" in rec:
        return AuthCheck("spf", "softfail",
                         f"domain publishes a softfail SPF policy ({domain}) - spoofed mail may still arrive", rec)
    return AuthCheck("spf", "neutral",
                     f"SPF record exists for {domain} but ends without -all/~all", rec)


def check_dkim(dkim_header: str) -> AuthCheck:
    """Check a DKIM-Signature header: selector/domain extraction + key lookup.

    Full cryptographic verification needs canonicalization of the exact signed
    bytes; this check confirms the signature header is well-formed and that
    the referenced public key is actually published in DNS.
    """
    if not dkim_header:
        return AuthCheck("dkim", "none", "no DKIM-Signature header present")
    sel = _DKIM_SIG_RE.search(dkim_header)
    dom = _DKIM_DOMAIN_RE.search(dkim_header)
    if not sel or not dom:
        return AuthCheck("dkim", "fail",
                         "DKIM-Signature header is malformed (missing s= or d= tag)")
    selector, domain = sel.group(1).strip(), dom.group(1).strip().lower()
    key_name = f"{selector}._domainkey.{domain}"
    records = [t for t in _txt_records(key_name) if "p=" in t]
    if not records:
        if not _probe_any():
            return AuthCheck("dkim", "unavailable", "DNS unreachable - key lookup skipped")
        return AuthCheck("dkim", "fail",
                         f"DKIM key {key_name} not published - signature cannot be trusted")
    return AuthCheck("dkim", "pass",
                     f"DKIM key published at {key_name}; signature header well-formed",
                     records[0][:120])


def check_dmarc(domain: str) -> AuthCheck:
    if not domain:
        return AuthCheck("dmarc", "none", "no sender domain to check")
    records = [t for t in _txt_records(f"_dmarc.{domain}")
               if t.lower().startswith("v=dmarc1")]
    if not records:
        if not _probe_any():
            return AuthCheck("dmarc", "unavailable", "DNS unreachable - check skipped")
        return AuthCheck("dmarc", "none",
                         f"no DMARC record for {domain} - domain owner requests no handling of spoofed mail")
    rec = records[0]
    m = re.search(r"\bp\s*=\s*([^;\s]+)", rec, re.IGNORECASE)
    policy = (m.group(1).lower() if m else "none")
    if policy == "reject":
        return AuthCheck("dmarc", "pass",
                         f"DMARC policy is p=reject for {domain} - spoofed mail should be dropped", rec)
    if policy == "quarantine":
        return AuthCheck("dmarc", "softfail",
                         f"DMARC policy is p=quarantine for {domain}", rec)
    return AuthCheck("dmarc", "none",
                     f"DMARC policy is p=none for {domain} - monitoring only, spoofing unmitigated", rec)


def check_all(domain: str, dkim_header: str) -> dict:
    spf = check_spf(domain)
    dkim = check_dkim(dkim_header)
    dmarc = check_dmarc(domain)
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc}
