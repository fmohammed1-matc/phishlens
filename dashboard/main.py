"""PhishLens dashboard backend - FastAPI serving the 3D forensics UI."""
import sys
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.report import analyze_bytes, analyze_file  # noqa: E402

app = FastAPI(title="PhishLens", version="0.1.0")

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEMO_DIR = ROOT / "demo"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "phishlens"}


@app.get("/api/demos")
def demos():
    out = []
    for p in sorted(DEMO_DIR.glob("*.eml")):
        out.append({"name": p.stem, "file": p.name})
    return {"demos": out}


@app.get("/api/demo/{name}")
def analyze_demo(name: str):
    safe = "".join(c for c in name if c.isalnum() or c in ("_", "-"))
    path = DEMO_DIR / f"{safe}.eml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="demo sample not found")
    return analyze_file(str(path))


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="please upload a .eml file")
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="file too large (max 5 MB)")
    if not data.strip():
        raise HTTPException(status_code=400, detail="empty file")
    try:
        report = analyze_bytes(data)
    except Exception as exc:  # malformed input -> 422, not a crash
        raise HTTPException(status_code=422, detail=f"could not parse .eml: {exc}")
    report["meta"]["filename"] = file.filename
    return report
