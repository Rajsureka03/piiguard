"""ingest.py: split the knowledge base into field-level chunks with typed metadata."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from langchain_core.documents import Document

KB_DIR = Path(__file__).parent / "knowledge_base"
KB_VERSION = 3
FIELDS = {"Why it matters": "why", "Consequences": "consequences",
          "LLM-specific risk": "llm_risk", "Safer alternative": "alternative",
          "Aggregation risk": "aggregation", "Scam risk": "scams", "Good habit": "habit"}
SEVERITY = {"SSN": "critical", "ITIN_EIN": "critical", "CREDIT_CARD": "critical", "BANK_ACCOUNT": "critical",
            "PASSWORD": "critical", "PASSPORT": "critical", "DRIVERS_LICENSE": "high", "DOB": "high",
            "ADDRESS": "high", "MEDICAL": "high", "PHONE": "medium", "EMAIL": "medium", "NAME": "medium",
            "GENERAL": "medium"}
TOPICS = {"SSN": ["taxes", "identity_theft"], "ITIN_EIN": ["taxes"], "CREDIT_CARD": ["banking"],
          "BANK_ACCOUNT": ["banking"], "DOB": ["identity_theft"], "MEDICAL": ["health_insurance"],
          "GENERAL": ["retirement", "scams"]}


def load_chunks() -> list[Document]:
    docs = []
    for path in sorted(KB_DIR.glob("*.md")):
        for block in re.split(r"^# ", path.read_text(encoding="utf-8"), flags=re.M):
            if not block.strip():
                continue
            pii_type, _, body = block.partition("\n")
            pii_type = pii_type.strip()
            title = re.search(r"^Title:\s*(.+)$", body, re.M)
            for label, field in FIELDS.items():
                m = re.search(rf"^{re.escape(label)}:\s*(.+)$", body, re.M)
                if not m:
                    continue
                text = f"{title.group(1) if title else pii_type}. {label}: {m.group(1).strip()}"
                meta = {
                    "chunk_id": f"{pii_type}:{field}:v{KB_VERSION}",
                    "pii_type": pii_type, "field": field,
                    "severity": SEVERITY.get(pii_type, "medium"),
                    "reading_level": "plain", "source": path.name, "kb_version": KB_VERSION,
                    "content_hash": "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:16],
                }
                for t in TOPICS.get(pii_type, []):          # flattened list field
                    meta[f"topic_{t}"] = True
                docs.append(Document(page_content=text, metadata=meta))
    return docs


if __name__ == "__main__":
    chunks = load_chunks()
    print(len(chunks), "chunks")
    print(chunks[0].metadata)
