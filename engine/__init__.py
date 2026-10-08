"""PhishLens engine package - defensive phishing email forensics."""
from .report import analyze_file, analyze_bytes

__all__ = ["analyze_file", "analyze_bytes"]
__version__ = "0.1.0"
