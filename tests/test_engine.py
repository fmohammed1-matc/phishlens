"""PhishLens engine tests - parsing, homoglyph detection, verdict scoring."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine import eml_parser, domain_analysis, url_analysis, verdict as verdict_mod
from engine.report import analyze_file


@pytest.fixture()
def demo_dir():
    return ROOT / "demo"


# ---------- parsing ----------

def test_parse_clean_sample(demo_dir):
    parsed = eml_parser.parse_eml((demo_dir / "clean.eml").read_bytes())
    assert parsed.from_addr == "team@github.com"
    assert parsed.subject == "Your weekly digest"
    assert len(parsed.hops) == 2
    # oldest hop first
    assert parsed.hops[0].from_host == "sender.github.com"
    assert parsed.hops[1].by_host == "mx.example.com"
    assert all(h.timestamp is not None for h in parsed.hops)


def test_received_chain_order_and_delay(demo_dir):
    parsed = eml_parser.parse_eml((demo_dir / "clean.eml").read_bytes())
    assert parsed.hops[1].delay_seconds == pytest.approx(4.0)
    assert parsed.hops[1].anomalies == []


def test_negative_delay_flagged(demo_dir):
    parsed = eml_parser.parse_eml((demo_dir / "phish_homoglyph.eml").read_bytes())
    bad = [h for h in parsed.hops if "negative_transit_delay" in h.anomalies]
    assert len(bad) == 1


def test_unknown_host_flagged(demo_dir):
    parsed = eml_parser.parse_eml((demo_dir / "phish_spoof.eml").read_bytes())
    assert "unidentified_sender_host" in parsed.hops[0].anomalies


def test_header_mismatch_helpers(demo_dir):
    parsed = eml_parser.parse_eml((demo_dir / "phish_spoof.eml").read_bytes())
    assert eml_parser.sender_domain(parsed) == "paypai.com"
    assert eml_parser.return_path_domain(parsed) == "secure-mailer.ru"


# ---------- domain analysis ----------

def test_homoglyph_detection():
    # Cyrillic a + Cyrillic er -> renders as "apple"
    finding = domain_analysis.analyze_domain("а" + "р" + "р" + "le.com")
    assert finding.kind == "homoglyph"
    assert finding.impersonated_brand == "apple"
    assert finding.severity == "critical"


def test_typosquat_detection():
    finding = domain_analysis.analyze_domain("paypaI.com")  # capital i
    assert finding.kind == "typosquat"
    assert finding.impersonated_brand == "paypal"


def test_typosquat_distance_two():
    finding = domain_analysis.analyze_domain("microsfot.com")
    assert finding.kind == "typosquat"
    assert finding.impersonated_brand == "microsoft"


def test_clean_domain():
    finding = domain_analysis.analyze_domain("github.com")
    assert finding.kind == "clean"


def test_levenshtein_sanity():
    assert domain_analysis.levenshtein("paypal", "paypaI") == 1
    assert domain_analysis.levenshtein("abc", "abc") == 0
    assert domain_analysis.levenshtein("", "abc") == 3


# ---------- url analysis ----------

def test_ip_literal_flagged():
    f = url_analysis.analyze_url("http://45.155.204.9/login")
    assert "ip_literal" in f.flags


def test_display_mismatch_flagged():
    f = url_analysis.analyze_url("http://45.155.204.9/login",
                                 display_text="www.paypal.com/verify")
    assert "display_mismatch" in f.flags


def test_shortener_and_punycode():
    assert "shortener" in url_analysis.analyze_url("https://bit.ly/abc").flags
    assert "punycode" in url_analysis.analyze_url("http://xn--pple-43d.com/").flags


def test_suspicious_tld():
    f = url_analysis.analyze_url("https://verify-user.tk/auth")
    assert "suspicious_tld" in f.flags


def test_clean_url():
    f = url_analysis.analyze_url("https://github.com/notifications")
    assert f.flags == []


# ---------- verdict ----------

def _ctx(**kw):
    base = {"auth": {}, "domain_finding": None, "url_findings": [],
            "hops": [], "header_flags": []}
    base.update(kw)
    return base


def test_verdict_clean_when_nothing_found():
    v = verdict_mod.score_findings(_ctx())
    assert v.score == 0
    assert v.label == "Clean"


def test_verdict_critical_on_homoglyph():
    dom = domain_analysis.DomainFinding("xn--x.com", "homoglyph",
                                        impersonated_brand="apple",
                                        severity="critical")
    v = verdict_mod.score_findings(_ctx(domain_finding=dom))
    assert v.score >= 30
    assert any("homograph" in r for r in v.reasons)


def test_verdict_score_capped_at_100():
    from engine.eml_parser import Hop
    dom = domain_analysis.DomainFinding("x", "homoglyph",
                                        impersonated_brand="paypal",
                                        severity="critical")
    urls = [url_analysis.analyze_url("http://1.2.3.4/a")] * 10
    bad_hops = [Hop(index=i, raw="",
                    anomalies=["negative_transit_delay"]) for i in range(3)]
    v = verdict_mod.score_findings(_ctx(
        domain_finding=dom, url_findings=urls, hops=bad_hops,
        header_flags=["from_returnpath_mismatch", "replyto_mismatch"]))
    assert v.score == 100
    assert v.label == "Critical"


def test_verdict_labels():
    from engine.verdict import _label
    assert _label(0) == "Clean"
    assert _label(25) == "Low"
    assert _label(45) == "Suspicious"
    assert _label(65) == "High"
    assert _label(95) == "Critical"


# ---------- end-to-end ----------

def test_end_to_end_clean_scores_low(demo_dir):
    r = analyze_file(str(demo_dir / "clean.eml"))
    assert r["verdict"]["score"] < 20
    assert r["verdict"]["label"] in ("Clean", "Low")


def test_end_to_end_spoof_is_critical(demo_dir):
    r = analyze_file(str(demo_dir / "phish_spoof.eml"))
    assert r["verdict"]["score"] >= 80
    assert r["verdict"]["label"] == "Critical"
    assert "from_returnpath_mismatch" in r["header_flags"]
    assert "replyto_mismatch" in r["header_flags"]
    assert r["domain_analysis"]["kind"] == "typosquat"


def test_end_to_end_homoglyph_flagged(demo_dir):
    r = analyze_file(str(demo_dir / "phish_homoglyph.eml"))
    assert r["domain_analysis"]["kind"] == "homoglyph"
    assert r["verdict"]["score"] >= 40
