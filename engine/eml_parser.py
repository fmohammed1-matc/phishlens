"""Parse .eml files and reconstruct the Received hop chain.

All parsing uses the Python standard library only. The Received headers in an
email are listed newest-first; this module reorders them oldest-first (the
actual path the message travelled) and computes per-hop transit delays.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, getaddresses

_RECEIVED_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
_RECEIVED_BY = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
_RECEIVED_WITH = re.compile(r"\bwith\s+([^\s;()]+)", re.IGNORECASE)
_RECEIVED_ID = re.compile(r"\bid\s+([^\s;()]+)", re.IGNORECASE)
_RECEIVED_FOR = re.compile(r"\bfor\s+<?([^<>;\s]+)>?", re.IGNORECASE)
_IP_LITERAL = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\]?")

LONG_DELAY_SECONDS = 24 * 3600  # > 24h between hops is suspicious


@dataclass
class Hop:
    index: int                      # 0 = first hop (oldest)
    raw: str
    from_host: str = ""
    by_host: str = ""
    with_proto: str = ""
    msg_id: str = ""
    for_addr: str = ""
    timestamp: datetime | None = None
    delay_seconds: float | None = None   # time from previous hop handing off
    anomalies: list = field(default_factory=list)


@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    from_name: str = ""
    to_addrs: list = field(default_factory=list)
    reply_to: str = ""
    return_path: str = ""
    date: datetime | None = None
    message_id: str = ""
    hops: list = field(default_factory=list)   # oldest -> newest
    raw_headers: str = ""
    body_text: str = ""
    body_html: str = ""


def _clean_host(token: str) -> str:
    token = token.strip().strip("()")
    m = _IP_LITERAL.fullmatch(token)
    return token


def _parse_received(raw: str, index: int) -> Hop:
    hop = Hop(index=index, raw=" ".join(raw.split()))
    m = _RECEIVED_FROM.search(hop.raw)
    if m:
        hop.from_host = _clean_host(m.group(1))
    m = _RECEIVED_BY.search(hop.raw)
    if m:
        hop.by_host = _clean_host(m.group(1))
    m = _RECEIVED_WITH.search(hop.raw)
    if m:
        hop.with_proto = m.group(1)
    m = _RECEIVED_ID.search(hop.raw)
    if m:
        hop.msg_id = m.group(1)
    m = _RECEIVED_FOR.search(hop.raw)
    if m:
        hop.for_addr = m.group(1).rstrip(";")

    # Timestamp is after the final semicolon.
    if ";" in hop.raw:
        date_part = hop.raw.rsplit(";", 1)[-1].strip()
        try:
            ts = parsedate_to_datetime(date_part)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            hop.timestamp = ts
        except (TypeError, ValueError):
            hop.timestamp = None
    return hop


def _flag_hop_anomalies(hops: list) -> None:
    for i, hop in enumerate(hops):
        if not hop.from_host or hop.from_host.lower() == "unknown":
            hop.anomalies.append("unidentified_sender_host")
        if i > 0:
            prev, cur = hops[i - 1], hop
            if prev.timestamp and cur.timestamp:
                delta = (cur.timestamp - prev.timestamp).total_seconds()
                hop.delay_seconds = delta
                if delta < 0:
                    hop.anomalies.append("negative_transit_delay")
                elif delta > LONG_DELAY_SECONDS:
                    hop.anomalies.append("excessive_transit_delay")


def _extract_bodies(msg) -> tuple[str, str]:
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                continue
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                decoded = payload.decode("utf-8", errors="replace")
            if ctype == "text/plain":
                text += decoded + "\n"
            elif ctype == "text/html":
                html += decoded + "\n"
    else:
        try:
            payload = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
        except Exception:
            decoded = ""
        if msg.get_content_type() == "text/html":
            html = decoded
        else:
            text = decoded
    return text, html


def parse_eml(data: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail."""
    msg = BytesParser(policy=policy.default).parsebytes(data)
    parsed = ParsedEmail()

    parsed.subject = str(msg.get("Subject", ""))
    from_addrs = getaddresses([str(msg.get("From", ""))])
    if from_addrs:
        parsed.from_name, parsed.from_addr = from_addrs[0][0], from_addrs[0][1]
    parsed.to_addrs = [a[1] for a in getaddresses(msg.get_all("To", []))]
    reply = getaddresses([str(msg.get("Reply-To", ""))])
    parsed.reply_to = reply[0][1] if reply else ""
    parsed.return_path = str(msg.get("Return-Path", "")).strip("<> ")
    parsed.message_id = str(msg.get("Message-ID", ""))

    date_hdr = msg.get("Date")
    if date_hdr:
        try:
            parsed.date = parsedate_to_datetime(str(date_hdr))
        except (TypeError, ValueError):
            parsed.date = None

    # Raw headers for the viewer (folded form).
    parsed.raw_headers = "\n".join(
        f"{k}: {v}" for k, v in msg.raw_items()
    )

    # Received headers arrive newest-first; reverse to oldest-first.
    raw_received = msg.get_all("Received", [])
    hops = [_parse_received(r, i) for i, r in enumerate(reversed(raw_received))]
    for i, hop in enumerate(hops):
        hop.index = i
    _flag_hop_anomalies(hops)
    parsed.hops = hops

    parsed.body_text, parsed.body_html = _extract_bodies(msg)
    return parsed


def sender_domain(parsed: ParsedEmail) -> str:
    addr = parsed.from_addr or ""
    return addr.split("@")[-1].lower().strip(">.") if "@" in addr else ""


def return_path_domain(parsed: ParsedEmail) -> str:
    rp = parsed.return_path or ""
    return rp.split("@")[-1].lower().strip(">.") if "@" in rp else ""
