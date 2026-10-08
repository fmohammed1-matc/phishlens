"""Verdict engine: turn every finding into a 0-100 risk score plus reasons.

Scoring is additive with per-category caps so one noisy signal cannot max out
the score alone. Reasons are human-readable strings shown in the dashboard.
"""
from dataclasses import dataclass, field


@dataclass
class Verdict:
    score: int                      # 0-100
    label: str                      # Clean | Low | Suspicious | High | Critical
    reasons: list = field(default_factory=list)


def _label(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Suspicious"
    if score >= 20:
        return "Low"
    return "Clean"


def score_findings(ctx: dict) -> Verdict:
    """ctx keys: auth, domain_finding, url_findings, hops, header_flags."""
    score = 0
    reasons: list[str] = []

    def add(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(reason)

    auth = ctx.get("auth", {})
    spf = auth.get("spf")
    dkim = auth.get("dkim")
    dmarc = auth.get("dmarc")

    if spf:
        if spf.status == "none":
            add(8, f"Sender domain publishes no SPF record - spoofing is trivial ({spf.detail[:80]})")
        elif spf.status == "softfail":
            add(12, "SPF policy is softfail (~all): spoofed mail may still be delivered")
        elif spf.status == "unavailable":
            add(2, "SPF check skipped (DNS unreachable)")
    if dkim:
        if dkim.status == "none":
            add(6, "No DKIM signature: message integrity cannot be verified")
        elif dkim.status == "fail":
            add(14, f"DKIM problem: {dkim.detail[:90]}")
        elif dkim.status == "unavailable":
            add(2, "DKIM check skipped (DNS unreachable)")
    if dmarc:
        if dmarc.status == "none":
            add(8, "No DMARC policy: domain owner does not reject spoofed mail")
        elif dmarc.status == "pass":
            score = max(0, score - 5)
            reasons.append("DMARC p=reject published: domain actively rejects spoofing (good sign)")
        elif dmarc.status == "unavailable":
            add(2, "DMARC check skipped (DNS unreachable)")

    dom = ctx.get("domain_finding")
    if dom:
        if dom.kind == "homoglyph":
            add(30, f"CRITICAL: sender domain uses lookalike characters impersonating '{dom.impersonated_brand}' (IDN homograph attack)")
        elif dom.kind == "typosquat":
            pts = 22 if dom.severity == "critical" else 14
            add(pts, f"Sender domain looks like a typosquat of '{dom.impersonated_brand}' ({dom.detail[:80]})")

    url_pts = 0
    for u in ctx.get("url_findings", []):
        for flag in u.flags:
            if flag == "ip_literal":
                url_pts += 12
                reasons.append(f"Suspicious URL uses a raw IP host: {u.url[:70]}")
            elif flag == "display_mismatch":
                url_pts += 18
                reasons.append(f"Deceptive link: text shows '{u.display_text}' but leads to '{u.host}'")
            elif flag == "punycode":
                url_pts += 10
                reasons.append(f"URL uses punycode encoding (possible homograph): {u.host}")
            elif flag == "at_trick":
                url_pts += 12
                reasons.append(f"URL contains '@' trick hiding the real host: {u.url[:70]}")
            elif flag == "shortener":
                url_pts += 5
                reasons.append(f"URL shortener hides destination: {u.host}")
            elif flag == "suspicious_tld":
                url_pts += 6
                reasons.append(f"URL uses abuse-prone TLD: {u.host}")
            elif flag == "deep_subdomains":
                url_pts += 4
                reasons.append(f"URL buries the real domain in subdomains: {u.host}")
    score += min(url_pts, 35)
    if url_pts > 35:
        reasons.append("Multiple malicious URL indicators (capped contribution)")

    for hop in ctx.get("hops", []):
        if "negative_transit_delay" in hop.anomalies:
            add(10, f"Hop {hop.index + 1} ({hop.by_host or 'unknown'}): timestamp goes backwards - header may be forged")
        if "excessive_transit_delay" in hop.anomalies:
            add(5, f"Hop {hop.index + 1}: message sat in transit over 24h (unusual)")
        if "unidentified_sender_host" in hop.anomalies:
            add(4, f"Hop {hop.index + 1}: sender host unidentified ('unknown')")

    for flag in ctx.get("header_flags", []):
        if flag == "from_returnpath_mismatch":
            add(15, "From address domain does not match Return-Path domain (classic spoofing sign)")
        elif flag == "replyto_mismatch":
            add(15, "Reply-To address differs from From address (replies go to the attacker)")
        elif flag == "no_received":
            add(5, "No Received headers at all (unusual for real mail)")

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No suspicious indicators found across headers, authentication, domains, and URLs")
    return Verdict(score=score, label=_label(score), reasons=reasons)
