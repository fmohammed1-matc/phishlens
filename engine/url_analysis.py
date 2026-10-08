"""URL extraction and analysis from email bodies.

Flags the URL tricks most common in phishing:
  - IP-literal hosts (http://192.0.2.44/login)
  - punycode / xn-- labels
  - known URL shorteners (hides the real destination)
  - suspicious TLDs abused for phishing
  - display-text vs href mismatch in HTML ("paypal.com" shown, evil link behind)
  - '@' tricks and excessive subdomains
"""
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc", "shorturl.at",
    "rb.gy", "s.id", "lnkd.in",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",          # free TLDs, heavily abused
    "xyz", "top", "click", "link", "zip", "mov",
    "country", "stream", "download", "review",
}


@dataclass
class UrlFinding:
    url: str
    host: str = ""
    flags: list = field(default_factory=list)   # e.g. ["ip_literal", "shortener"]
    display_text: str = ""                       # anchor text, if from HTML
    note: str = ""


class _AnchorParser(HTMLParser):
    """Collect (href, visible text) pairs from <a> tags."""
    def __init__(self):
        super().__init__()
        self.anchors = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text).strip()))
            self._href = None


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _tld_of(host: str) -> str:
    parts = host.strip(".").split(".")
    return parts[-1] if parts else ""


def _looks_like_domain(text: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{1,60}[a-z0-9])?\.[a-z]{2,}",
                             text.lower().strip()))


def analyze_url(url: str, display_text: str = "") -> UrlFinding:
    finding = UrlFinding(url=url, display_text=display_text)
    host = _host_of(url)
    finding.host = host
    if not host:
        finding.flags.append("unparseable")
        return finding

    if IPV4_RE.match(host) or host.startswith("["):
        finding.flags.append("ip_literal")
        finding.note = "host is a raw IP address instead of a domain name"
    if "xn--" in host:
        finding.flags.append("punycode")
        finding.note = "host uses punycode (possible IDN homograph)"
    if host in SHORTENERS or host.endswith(tuple("." + s for s in SHORTENERS)):
        finding.flags.append("shortener")
        finding.note = "URL shortener hides the true destination"
    if _tld_of(host) in SUSPICIOUS_TLDS:
        finding.flags.append("suspicious_tld")
        finding.note = f"TLD .{_tld_of(host)} is frequently abused for phishing"
    if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
        # userinfo@host trick: http://paypal.com@evil.example/
        finding.flags.append("at_trick")
        finding.note = "'@' in authority - the real host is after the @"
    if host.count(".") >= 4:
        finding.flags.append("deep_subdomains")
        finding.note = "excessive subdomains often bury the real domain"

    # Display-text vs href mismatch: anchor shows paypal.com, links elsewhere.
    if display_text:
        shown_host = display_text.lower().split("/")[0].strip().rstrip(".")
        if _looks_like_domain(shown_host):
            if shown_host != host and not host.endswith("." + shown_host):
                finding.flags.append("display_mismatch")
                finding.note = (f"link text shows '{shown_host}' but points to "
                                f"'{host}'")

    return finding


def extract_urls(text: str, html: str) -> list[UrlFinding]:
    """Extract and analyze every URL in the plain-text and HTML bodies."""
    findings: list[UrlFinding] = []
    seen = set()

    for m in URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;)")
        if url not in seen:
            seen.add(url)
            findings.append(analyze_url(url))

    if html:
        parser = _AnchorParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        for href, shown in parser.anchors:
            if not href.lower().startswith("http"):
                continue
            key = (href, shown)
            if key in seen:
                continue
            seen.add(key)
            findings.append(analyze_url(href, display_text=shown))
        # Bare URLs inside HTML that are not anchors.
        for m in URL_RE.finditer(html):
            url = m.group(0).rstrip(".,;)")
            if url not in seen:
                seen.add(url)
                findings.append(analyze_url(url))

    return findings
