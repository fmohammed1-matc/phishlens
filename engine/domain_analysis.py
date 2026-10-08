"""Sender-domain analysis: homoglyph / confusable detection and typosquatting.

Compares the sender's domain against a built-in list of frequently impersonated
brands using two techniques:

1. Homoglyph (confusable) detection - maps non-ASCII lookalike characters
   (Cyrillic, Greek, etc.) to their ASCII "skeleton" and checks whether the
   skeleton matches a known brand.
2. Typosquat scoring - Levenshtein edit distance against each brand; a small
   non-zero distance on a similarly-sized domain is a classic typosquat.
"""
from dataclasses import dataclass

# Frequently impersonated brands (second-level labels only).
KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "facebook",
    "instagram", "linkedin", "netflix", "chase", "wellsfargo",
    "bankofamerica", "citibank", "usbank", "dhl", "fedex", "ups",
    "usps", "irs", "dropbox", "adobe", "ebay", "coinbase", "binance",
    "outlook", "office365", "icloud", "whatsapp", "telegram",
]

# Unicode confusables -> ASCII skeleton. Covers the Cyrillic/Greek lookalikes
# most abused in IDN homograph attacks.
CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "ё": "e", "і": "i", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "к": "k", "м": "m", "н": "h",
    "т": "t", "в": "b", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ԍ": "g",
    "ӏ": "l", "ѕ": "s", "ԑ": "e", "ո": "n", "ս": "u", "հ": "h",
    # Greek
    "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "χ": "x", "α": "a", "η": "n", "μ": "u", "ω": "w",
    # Latin lookalikes / misc
    "ı": "i", "ł": "l", "ø": "o", "ß": "b", "ñ": "n",
    "а́": "a",
}


@dataclass
class DomainFinding:
    domain: str
    kind: str          # "homoglyph" | "typosquat" | "clean"
    impersonated_brand: str = ""
    detail: str = ""
    severity: str = "info"   # info | warning | critical


def skeleton(domain: str) -> str:
    """Map confusable characters to ASCII; lowercase the rest."""
    return "".join(CONFUSABLES.get(ch, ch.lower()) for ch in domain)


def has_non_ascii(domain: str) -> bool:
    return any(ord(ch) > 127 for ch in domain)


def levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming edit distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _sld(domain: str) -> str:
    """Second-level label, e.g. 'paypaI.com' -> 'paypai'."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def analyze_domain(domain: str) -> DomainFinding:
    """Analyze a sender domain for brand impersonation."""
    if not domain:
        return DomainFinding(domain, "clean", detail="no domain to analyze")
    label = _sld(domain)

    # 1. Homoglyph check: does the ASCII skeleton match a brand exactly
    #    while the raw domain contains non-ASCII characters?
    skel = skeleton(label)
    if has_non_ascii(label) and skel in KNOWN_BRANDS:
        return DomainFinding(
            domain, "homoglyph", impersonated_brand=skel, severity="critical",
            detail=(f"domain uses non-ASCII lookalike characters that render as "
                    f"'{skel}' - classic IDN homograph attack impersonating {skel}"),
        )

    # 2. Typosquat check: small edit distance to a brand, similar length.
    best, best_dist = "", 99
    for brand in KNOWN_BRANDS:
        if abs(len(label) - len(brand)) > 2:
            continue
        d = levenshtein(label, brand)
        if d < best_dist:
            best, best_dist = brand, d
    if best and 1 <= best_dist <= 2 and len(label) >= 4:
        sev = "critical" if best_dist == 1 else "warning"
        return DomainFinding(
            domain, "typosquat", impersonated_brand=best, severity=sev,
            detail=(f"domain '{label}' is {best_dist} edit(s) away from '{best}' - "
                    f"likely typosquat"),
        )
    return DomainFinding(domain, "clean",
                         detail="no brand impersonation detected")
