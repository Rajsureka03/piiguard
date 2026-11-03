"""
pii_detector.py
Rule-based detector for personally identifiable information (PII).

Each detector returns PIIMatch objects with the exact character span, so the
UI can highlight and redact item-by-item. Rules are deliberately transparent
(regex + checksums) so study participants and reviewers can see *why*
something was flagged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class PIIMatch:
    pii_type: str        # key into the knowledge base, e.g. "SSN"
    label: str           # human-readable label shown in the UI
    value: str           # the exact text that matched
    start: int
    end: int
    severity: str        # "critical" | "high" | "medium"
    id: str = field(default="")

    def masked(self) -> str:
        """Show only the last few characters, e.g. ***-**-2323."""
        v = self.value
        if len(v) <= 4:
            return "*" * len(v)
        return re.sub(r"[A-Za-z0-9]", "*", v[:-4]) + v[-4:]


def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _aba_ok(number: str) -> bool:
    d = [int(c) for c in number]
    if len(d) != 9:
        return False
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0


def _ssn_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


# (pii_type, label, severity, regex, optional validator)
_RULES = [
    ("SSN", "Social Security Number", "critical",
     re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"), _ssn_ok),
    ("SSN", "Social Security Number", "critical",
     re.compile(r"(?:SSN|social security)\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*(\d{9})\b", re.I), _ssn_ok),
    ("ITIN_EIN", "Tax ID (ITIN / EIN)", "critical",
     re.compile(r"\b9\d{2}[- ]\d{2}[- ]\d{4}\b|\b\d{2}-\d{7}\b"), None),
    ("CREDIT_CARD", "Credit / Debit Card Number", "critical",
     re.compile(r"\b(?:\d[ -]?){13,19}\b"), _luhn_ok),
    ("BANK_ACCOUNT", "Bank Account / Routing Number", "critical",
     re.compile(r"(?:account|acct|routing|aba)\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*(\d{6,17})", re.I), None),
    ("PASSPORT", "Passport Number", "critical",
     re.compile(r"passport\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*([A-Z0-9]{6,9})\b", re.I), None),
    ("DRIVERS_LICENSE", "Driver's License Number", "high",
     re.compile(r"(?:driver'?s?\s*licen[sc]e|DL)\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*([A-Z0-9-]{5,15})\b", re.I), None),
    ("PASSWORD", "Password / PIN", "critical",
     re.compile(r"(?:password|passcode|pin)\s*(?:is|:|=)\s*(\S+)", re.I), None),
    ("DOB", "Date of Birth", "high",
     re.compile(r"(?:born\s+(?:on\s+)?|birth\s*(?:day|date)?\s*(?:is|:)?\s*|DOB\s*:?\s*)"
                r"(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|[A-Z][a-z]+\.? \d{1,2},? \d{4})", re.I), None),
    ("EMAIL", "Email Address", "medium",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("PHONE", "Phone Number", "medium",
     re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"), None),
    ("ADDRESS", "Home Address", "high",
     re.compile(r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s){1,4}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|"
                r"Ln|Lane|Ct|Court|Way|Pl|Place|Pkwy|Parkway|Cir|Circle)\b\.?(?:,?\s*(?:Apt|Unit|#)\s*\w+)?"), None),
    ("NAME", "Full Name", "medium",
     re.compile(r"(?:my name is|i am|i'm|this is|name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})", re.I), None),
    ("MEDICAL", "Medical / Insurance ID", "high",
     re.compile(r"(?:medical record|MRN|member id|insurance id|policy number|medicare)\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*([A-Z0-9-]{5,15})", re.I), None),
]

_NAME_STOPWORDS = {"Here", "Not", "Going", "Trying", "Looking", "Wondering", "Just", "So", "Very", "A", "The",
                   "Sure", "Asking", "Working", "Filing", "Confused", "Sorry", "Happy", "Hi", "Hello"}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


def detect_pii(text: str) -> list[PIIMatch]:
    """Return non-overlapping PII matches, highest-severity first on overlap."""
    found: list[PIIMatch] = []
    for pii_type, label, severity, pattern, validator in _RULES:
        for m in pattern.finditer(text):
            group = 1 if m.lastindex else 0
            value = m.group(group)
            start, end = m.span(group)
            if validator and not validator(value):
                continue
            if "[" in value or "REDACTED" in value:  # never re-flag our own redaction tokens
                continue
            if pii_type == "NAME":
                first = value.split()[0].capitalize()
                if first in _NAME_STOPWORDS or not value[0].isupper():
                    continue
            found.append(PIIMatch(pii_type, label, value.strip(), start, start + len(value.strip()), severity))

    # Resolve overlaps: keep the most severe, then the longest.
    found.sort(key=lambda p: (SEVERITY_ORDER[p.severity], -(p.end - p.start)))
    kept: list[PIIMatch] = []
    for p in found:
        if all(p.end <= k.start or p.start >= k.end for k in kept):
            kept.append(p)
    kept.sort(key=lambda p: p.start)
    for i, p in enumerate(kept):
        p.id = f"{p.pii_type}-{i}"
    return kept


def redact(text: str, matches: list[PIIMatch], ids_to_redact: set[str] | None = None) -> str:
    """Replace the chosen matches with [LABEL REDACTED] tokens."""
    out = text
    for p in sorted(matches, key=lambda p: p.start, reverse=True):
        if ids_to_redact is None or p.id in ids_to_redact:
            out = out[:p.start] + f"[{p.pii_type} REDACTED]" + out[p.end:]
    return out


def risk_score(matches: list[PIIMatch]) -> int:
    """0–100 score used for the risk meter in the UI."""
    weights = {"critical": 40, "high": 20, "medium": 10}
    return min(100, sum(weights[p.severity] for p in matches))


if __name__ == "__main__":
    demo = "Hi my name is Joy! Here is my SSN 123-21-2323. What is my SSN Number? Card 4111 1111 1111 1111"
    for m in detect_pii(demo):
        print(m.pii_type, "|", m.value, "|", m.masked())
    print(redact(demo, detect_pii(demo)))
