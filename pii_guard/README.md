# PII Guard: Private Chat prototype

A Gradio + LangChain prototype that catches personally identifiable information (PII) **before** it reaches an LLM, explains why it's risky, and tests whether users understand the implications.

## Run it

```bash
pip install -r requirements.txt
python app.py              # open http://127.0.0.1:7860
```

It runs fully offline by default. For real Claude replies:

1. Copy `.env.example` to `.env` (same folder as `app.py`).
2. Paste your key from console.anthropic.com: `ANTHROPIC_API_KEY=sk-ant-...`
3. Restart the app. The sidebar should say **Model: live: Anthropic (...)**.

If it still says offline, the chat and the terminal both explain why (no key found, package missing, etc.).
Never commit `.env` to GitHub.

## What it does (maps to the Figma flow)

| Figma frame | In the app |
|---|---|
| Homepage / Welcome | Sidebar (New chat, Search, Projects, Artifacts) + Welcome chat |
| Typing "How should I file tax?" | Live hint under the chat when PII is typed |
| Active Warning: Security Breach | Pink warning card: each item, severity, masked value, consequence, safer alternative, and a 0–100 exposure meter |
| ✓ / ✗ redact toggles | Checkbox per item (all pre-checked) → **Send redacted / Edit my message / Send anyway** |
| "Send redacted information to AI" | Chat shows the redacted message and exactly what the model received |

Plus:
- **Awareness Quiz** tab: 6 scenario questions (incl. a 401(k) scam caller), graded with explanations from the knowledge base.
- **Ask why (RAG)**: free-text questions answered by retrieving from the knowledge base.
- **Private mode toggle**: turn it off for a control condition. Messages go through and the user gets an after-the-fact notice instead (useful for A/B comparisons in usability testing).
- **Session log export (CSV)**: timestamp, action (redacted / edited / sent anyway / unprotected), PII types and risk score. No raw PII is logged.

Safety by design: even "Send anyway" never forwards detected PII to the API; the user is told it *would* have been exposed in a normal chatbot.

## Files

- `pii_detector.py`: regex + checksum detection (SSN, tax ID, credit card with Luhn check, bank/routing, passport, driver's license, password/PIN, DOB, email, phone, address, name, medical/insurance ID), redaction, and risk score
- `knowledge_base/pii_harms.md`: one section per PII type (why it matters, consequences, LLM-specific risk, safer alternative). Edit or add sections here; no code changes needed
- `rag.py`: LangChain documents → BM25 retriever (or Chroma + HuggingFace embeddings with `USE_EMBEDDINGS=1`), optional LLM chain
- `app.py`: the Gradio UI

## Known limits / next steps

- Name detection only catches phrasing like "my name is…" / "I'm…". For stronger detection, swap in Microsoft Presidio or a spaCy NER model behind `detect_pii()`.
- Patterns are US-centric (SSN, ABA routing).
- The UI uses Gradio's light theme. The Figma's dark "Private Chat" look can be added via CSS in `app.py`.
