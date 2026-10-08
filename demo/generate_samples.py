"""Generate synthetic .eml samples for PhishLens demos and tests.

Creates three samples in this directory:
  clean.eml          - legitimate newsletter-style email, consistent headers
  phish_spoof.eml    - typosquat sender (paypaI.com), Return-Path/Reply-To
                       mismatch, deceptive link, IP-literal URL
  phish_homoglyph.eml - Cyrillic homograph of apple.com, shortener URL,
                        forged Received timestamps

All people, domains (besides real impersonated brands used illustratively),
and content are fictional and for defensive training/detection testing only.
"""
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).parent


def _base(*, from_addr, from_name, to, subject, date, received, **extra):
    msg = EmailMessage()
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = date
    for name, value in extra.get("headers", {}).items():
        msg[name] = value
    # Received headers are stored newest-first in real mail, so append them
    # in that order (received[0] is the newest hop). Raw folded lines are
    # appended directly so they look exactly like real-world mail.
    for hop in received:
        msg._headers.append(("Received", hop))
    return msg


HOP = ("from {frm} ({frm} [{ip}])\n"
       " by {by} with ESMTPS id {id}\n"
       " for <{to}>; {date}")


def make_clean() -> EmailMessage:
    msg = _base(
        from_addr="team@github.com", from_name="GitHub",
        to="fahad@example.com", subject="Your weekly digest",
        date="Tue, 06 Oct 2026 09:15:00 -0500",
        headers={
            "Message-ID": "<digest-20261006@github.com>",
            "Return-Path": "<bounce@github.com>",
            "DKIM-Signature": ("v=1; a=rsa-sha256; d=github.com; s=pf2024; "
                               "bh=abc123; b=def456"),
        },
        received=[
            HOP.format(frm="out-1.smtp.github.com", ip="192.30.252.200",
                       by="mx.example.com", id="AAA111",
                       to="fahad@example.com",
                       date="Tue, 06 Oct 2026 09:15:02 -0500"),
            HOP.format(frm="sender.github.com", ip="192.30.252.10",
                       by="out-1.smtp.github.com", id="BBB222",
                       to="fahad@example.com",
                       date="Tue, 06 Oct 2026 09:14:58 -0500"),
        ],
    )
    msg.set_content(
        "Hi Fahad,\n\nHere is your weekly digest. View it online:\n"
        "https://github.com/notifications\n\nThanks,\nThe GitHub Team\n"
    )
    return msg


def make_phish_spoof() -> EmailMessage:
    # paypaI.com -> capital i, 1 edit from paypal -> typosquat
    msg = _base(
        from_addr="security@paypaI.com", from_name="PayPal Security",
        to="fahad@example.com", subject="Action required: verify your account",
        date="Tue, 06 Oct 2026 14:02:11 -0500",
        headers={
            "Message-ID": "<urgent-99182@paypaI.com>",
            "Return-Path": "<noreply@secure-mailer.ru>",
            "Reply-To": "support@paypaI-helpdesk.com",
        },
        received=[
            HOP.format(frm="unknown", ip="185.220.101.4",
                       by="mx.example.com", id="ZZZ999",
                       to="fahad@example.com",
                       date="Tue, 06 Oct 2026 14:02:15 -0500"),
        ],
    )
    msg.set_content(
        "Dear customer,\n\nWe detected unusual activity. Verify now:\n"
        "https://www.paypal.com.signin.verify-user.tk/auth\n"
        "or use our backup link http://45.155.204.9/login\n\n"
        "PayPal Security\n"
    )
    msg.add_alternative(
        """<html><body><p>Dear customer,</p>
        <p>We detected unusual activity. <a href="http://45.155.204.9/login">"""
        """www.paypal.com/verify</a></p></body></html>""",
        subtype="html",
    )
    return msg


def make_phish_homoglyph() -> EmailMessage:
    # Cyrillic "а" (U+0430) + "р" (U+0440) render as "a" + "p" -> looks like "apple"
    cyr_apple = "а" + "р" + "р" + "le.com"
    msg = _base(
        from_addr=f"no-reply@{cyr_apple}", from_name="Apple ID",
        to="fahad@example.com", subject="Your Apple ID was used to sign in",
        date="Wed, 07 Oct 2026 03:11:44 -0500",
        headers={
            "Message-ID": "<alert-5512@xn--pple-43d.com>",
            "Return-Path": f"<bounce@{cyr_apple}>",
        },
        received=[
            # Note the forged earlier timestamp on the second hop (goes backwards).
            HOP.format(frm="relay.evil.example", ip="91.203.67.77",
                       by="mx.example.com", id="QQQ777",
                       to="fahad@example.com",
                       date="Wed, 07 Oct 2026 03:12:01 -0500"),
            HOP.format(frm="mta.evil.example", ip="91.203.67.10",
                       by="relay.evil.example", id="QQQ776",
                       to="fahad@example.com",
                       date="Wed, 07 Oct 2026 04:45:00 -0500"),
        ],
    )
    msg.set_content(
        "Your Apple ID was used to sign in on a new device.\n"
        "If this was not you, secure your account here:\n"
        "https://bit.ly/3xAppleSecure\n"
    )
    return msg


def main() -> None:
    samples = {
        "clean.eml": make_clean(),
        "phish_spoof.eml": make_phish_spoof(),
        "phish_homoglyph.eml": make_phish_homoglyph(),
    }
    for name, msg in samples.items():
        path = OUT / name
        path.write_bytes(msg.as_bytes())
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
