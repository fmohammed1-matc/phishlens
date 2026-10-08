# PhishLens — Phishing Email Header Forensics Toolkit

A defensive blue-team toolkit that dissects suspicious emails: it reconstructs
the `Received` hop chain, verifies SPF/DKIM/DMARC, hunts homoglyph and
typosquat sender domains, analyzes embedded URLs, and produces a 0–100 risk
verdict with human-readable reasons — all behind a cinematic 3D dashboard.

## What it does

- **Header forensics** — parses `.eml` (stdlib `email`), rebuilds the Received
  chain oldest→newest, computes per-hop transit delays, flags forged
  timestamps (negative/excessive delays) and unidentified sender hosts
- **Authentication checks** — SPF posture, DKIM signature + key lookup, DMARC
  policy via `dnspython`; degrades gracefully when DNS is unreachable
- **Domain analysis** — Cyrillic/Greek homoglyph (IDN homograph) detection via
  confusable-character skeletons, plus Levenshtein typosquat scoring against
  30 frequently-impersonated brands
- **URL analysis** — flags IP-literal hosts, punycode, URL shorteners,
  abuse-prone TLDs, `@` tricks, deep subdomains, and display-text vs href
  mismatches in HTML bodies
- **Verdict engine** — weighted 0–100 risk score (Clean / Low / Suspicious /
  High / Critical) with a plain-language reason for every point
- **3D dashboard** — FastAPI backend + Three.js frontend: the hop chain as an
  animated 3D node path (anomalous hops pulse red), animated risk dial,
  auth badges, indicators, URL table, and raw-header viewer with suspicious
  lines highlighted

## Architecture

```
phishlens/
├── engine/            # detection core (no web deps)
│   ├── eml_parser.py      # .eml parsing, Received-chain reconstruction
│   ├── dns_checks.py      # SPF / DKIM / DMARC via dnspython
│   ├── domain_analysis.py # homoglyph + typosquat detection
│   ├── url_analysis.py    # URL indicator extraction
│   ├── verdict.py         # 0-100 weighted scoring
│   └── report.py          # analyze_file()/analyze_bytes() -> JSON dict
├── dashboard/
│   ├── main.py        # FastAPI: upload .eml, demo samples, health
│   └── static/        # index.html, style.css, app.js (Three.js via CDN)
├── demo/
│   ├── generate_samples.py  # builds the synthetic .eml samples below
│   ├── clean.eml
│   ├── phish_spoof.eml
│   └── phish_homoglyph.eml
└── tests/             # pytest suite
```

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# CLI analysis of any .eml file
python -m engine.report demo/phish_spoof.eml | head -40

# regenerate demo samples
python demo/generate_samples.py

# run the dashboard
uvicorn dashboard.main:app --port 8000
# -> http://127.0.0.1:8000  (upload an .eml or try the one-click demos)

# run tests
pytest -q
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | dashboard UI |
| GET | `/api/health` | liveness check |
| GET | `/api/demos` | list bundled `.eml` samples |
| GET | `/api/demo/{name}` | analyze a bundled sample |
| POST | `/api/analyze` | multipart upload of a `.eml` file → JSON report |

## A note on ethical, defensive use

PhishLens is built **only** for defense: triaging suspicious mail, SOC training,
and detection engineering. It crafts no payloads, sends no mail, and runs no
exploits. Do not use it (or anything else) to create or send phishing emails —
test only with synthetic samples like the ones in `demo/`, or with messages
you are explicitly authorized to analyze.

## License

MIT — see [LICENSE](LICENSE).
