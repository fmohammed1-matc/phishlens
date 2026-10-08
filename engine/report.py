"""Report orchestrator: analyze an .eml end-to-end and emit a JSON-ready dict."""
import json
from dataclasses import asdict

from . import eml_parser
from . import dns_checks
from . import domain_analysis
from . import url_analysis
from . import verdict as verdict_mod


def _hop_dict(hop) -> dict:
    return {
        "index": hop.index,
        "from_host": hop.from_host,
        "by_host": hop.by_host,
        "with_proto": hop.with_proto,
        "timestamp": hop.timestamp.isoformat() if hop.timestamp else None,
        "delay_seconds": hop.delay_seconds,
        "anomalies": hop.anomalies,
    }


def analyze_bytes(data: bytes) -> dict:
    parsed = eml_parser.parse_eml(data)
    from_domain = eml_parser.sender_domain(parsed)
    rp_domain = eml_parser.return_path_domain(parsed)

    dkim_header = ""
    for line in parsed.raw_headers.splitlines():
        if line.lower().startswith("dkim-signature:"):
            dkim_header = line.split(":", 1)[1]
            break

    auth = dns_checks.check_all(from_domain, dkim_header)
    dom_finding = domain_analysis.analyze_domain(from_domain)
    urls = url_analysis.extract_urls(parsed.body_text, parsed.body_html)

    header_flags = []
    if from_domain and rp_domain and from_domain != rp_domain:
        header_flags.append("from_returnpath_mismatch")
    if parsed.reply_to:
        reply_dom = parsed.reply_to.split("@")[-1].lower() if "@" in parsed.reply_to else ""
        if reply_dom and reply_dom != from_domain:
            header_flags.append("replyto_mismatch")
    if not parsed.hops:
        header_flags.append("no_received")

    v = verdict_mod.score_findings({
        "auth": auth,
        "domain_finding": dom_finding,
        "url_findings": urls,
        "hops": parsed.hops,
        "header_flags": header_flags,
    })

    return {
        "meta": {
            "subject": parsed.subject,
            "from": f"{parsed.from_name} <{parsed.from_addr}>" if parsed.from_name else parsed.from_addr,
            "from_domain": from_domain,
            "to": parsed.to_addrs,
            "reply_to": parsed.reply_to,
            "return_path": parsed.return_path,
            "date": parsed.date.isoformat() if parsed.date else None,
            "message_id": parsed.message_id,
        },
        "received_chain": [_hop_dict(h) for h in parsed.hops],
        "authentication": {
            name: {"status": c.status, "detail": c.detail}
            for name, c in auth.items()
        },
        "domain_analysis": {
            "domain": dom_finding.domain,
            "kind": dom_finding.kind,
            "impersonated_brand": dom_finding.impersonated_brand,
            "severity": dom_finding.severity,
            "detail": dom_finding.detail,
        },
        "urls": [
            {"url": u.url, "host": u.host, "flags": u.flags,
             "display_text": u.display_text, "note": u.note}
            for u in urls
        ],
        "header_flags": header_flags,
        "verdict": {"score": v.score, "label": v.label, "reasons": v.reasons},
        "raw_headers": parsed.raw_headers,
    }


def analyze_file(path: str) -> dict:
    with open(path, "rb") as f:
        return analyze_bytes(f.read())


def main() -> None:  # pragma: no cover
    import sys
    if len(sys.argv) != 2:
        print("usage: python -m engine.report <file.eml>")
        sys.exit(1)
    print(json.dumps(analyze_file(sys.argv[1]), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
