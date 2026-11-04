"""gate.py: the single privacy gate every string passes through.

Layer 1: the prototype's transparent regex + validator rules (pii_detector.py).
Layer 2 (optional): Microsoft Presidio NER for names, places and free-form addresses.
"""
from __future__ import annotations

from dataclasses import dataclass

from pii_detector import PIIMatch, detect_pii, redact, risk_score

try:  # pip install presidio-analyzer && python -m spacy download en_core_web_lg
    from presidio_analyzer import AnalyzerEngine
    _presidio = AnalyzerEngine()
except Exception:  # missing package or model: regex-only mode
    _presidio = None

PRESIDIO_MAP = {"PERSON": ("NAME", "Full Name", "medium"),
                "LOCATION": ("ADDRESS", "Home Address", "high"),
                "US_SSN": ("SSN", "Social Security Number", "critical"),
                "CREDIT_CARD": ("CREDIT_CARD", "Credit / Debit Card Number", "critical"),
                "US_BANK_NUMBER": ("BANK_ACCOUNT", "Bank Account / Routing Number", "critical"),
                "PHONE_NUMBER": ("PHONE", "Phone Number", "medium"),
                "EMAIL_ADDRESS": ("EMAIL", "Email Address", "medium")}


@dataclass
class GateResult:
    original: str
    matches: list[PIIMatch]
    redacted: str
    risk: int

    @property
    def types(self) -> list[str]:
        return sorted({m.pii_type for m in self.matches})


def scan(text: str, min_score: float = 0.6) -> GateResult:
    matches = detect_pii(text)
    if _presidio:
        for r in _presidio.analyze(text=text, language="en"):
            if r.entity_type not in PRESIDIO_MAP or r.score < min_score:
                continue
            if any(not (r.end <= m.start or r.start >= m.end) for m in matches):
                continue  # regex already covers this span
            t, label, sev = PRESIDIO_MAP[r.entity_type]
            matches.append(PIIMatch(t, label, text[r.start:r.end], r.start, r.end, sev, f"{t}-ner{r.start}"))
        matches.sort(key=lambda m: m.start)
    return GateResult(text, matches, redact(text, matches), risk_score(matches))


def ensure_clean(text: str) -> str:
    """Use on anything about to be stored, cached, logged or displayed: masks any PII left."""
    return scan(text).redacted
