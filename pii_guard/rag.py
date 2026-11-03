"""
rag.py
LangChain retrieval layer over the PII-harms knowledge base.

- Each "# TYPE" section of knowledge_base/*.md becomes a LangChain Document
  tagged with metadata {"pii_type": TYPE}.
- Retrieval uses BM25 by default (no API key, no model download).
- If you set USE_EMBEDDINGS=1 and have langchain-huggingface + chromadb
  installed, it switches to a Chroma vector store instead.
- An optional chat LLM (Anthropic or OpenAI via LangChain) writes the
  personalised explanation and answers the user's actual question.
  Without an API key the app still runs using the retrieved text directly.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from langchain_core.documents import Document

KB_DIR = Path(__file__).parent / "knowledge_base"


# ---------------------------------------------------------------- loading
def load_documents() -> list[Document]:
    docs: list[Document] = []
    for path in sorted(KB_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for block in re.split(r"^# ", text, flags=re.M):
            block = block.strip()
            if not block:
                continue
            pii_type, _, body = block.partition("\n")
            docs.append(Document(page_content=body.strip(),
                                 metadata={"pii_type": pii_type.strip(), "source": path.name}))
    return docs


def _field(doc: Document, name: str) -> str:
    m = re.search(rf"^{name}:\s*(.+)$", doc.page_content, flags=re.M)
    return m.group(1).strip() if m else ""


# -------------------------------------------------------------- retriever
class PIIKnowledgeBase:
    def __init__(self) -> None:
        self.docs = load_documents()
        self.by_type = {d.metadata["pii_type"]: d for d in self.docs}
        self.retriever = self._build_retriever()

    def _build_retriever(self):
        if os.getenv("USE_EMBEDDINGS") == "1":
            try:
                from langchain_community.vectorstores import Chroma
                from langchain_huggingface import HuggingFaceEmbeddings
                emb = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
                return Chroma.from_documents(self.docs, emb).as_retriever(search_kwargs={"k": 3})
            except Exception as exc:  # fall back quietly
                print(f"[rag] embeddings unavailable ({exc}); using BM25")
        from langchain_community.retrievers import BM25Retriever
        r = BM25Retriever.from_documents(self.docs)
        r.k = 3
        return r

    # Exact lookup for a detected type (deterministic, used for the warning card)
    def explain(self, pii_type: str) -> dict:
        doc = self.by_type.get(pii_type, self.by_type["GENERAL"])
        return {
            "title": _field(doc, "Title"),
            "why": _field(doc, "Why it matters"),
            "consequences": _field(doc, "Consequences"),
            "llm_risk": _field(doc, "LLM-specific risk") or _field(self.by_type["GENERAL"], "Why it matters"),
            "alternative": _field(doc, "Safer alternative") or _field(self.by_type["GENERAL"], "Good habit"),
        }

    # Free-text semantic/keyword search (used for "Ask why" questions)
    def search(self, query: str) -> list[Document]:
        return self.retriever.invoke(query)


# -------------------------------------------------------------------- LLM
def _load_env() -> None:
    """Load keys from a .env file next to this script, if one exists."""
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path, override=True)
        except ImportError:  # minimal fallback parser
            for line in env_path.read_text().splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1)
                    os.environ[k.strip()] = v.strip()
    # Strip stray quotes/spaces, a common copy-paste problem.
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        if os.getenv(k):
            os.environ[k] = os.environ[k].strip().strip('"').strip("'")


def get_llm():
    """Return (chat model or None, human-readable status)."""
    _load_env()
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            return None, ("Found ANTHROPIC_API_KEY, but the `langchain-anthropic` package isn't installed "
                          "for this Python. Stop the app and run: `python3 -m pip install langchain-anthropic`")
        model = os.getenv("LLM_MODEL", "claude-haiku-5-5")
        return ChatAnthropic(model=model, max_tokens=1024), f"live: Anthropic ({model})"
    if os.getenv("OPENAI_API_KEY"):
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            return None, ("Found OPENAI_API_KEY, but `langchain-openai` isn't installed. "
                          "Run: `python3 -m pip install langchain-openai`")
        model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        return ChatOpenAI(model=model, temperature=0.3), f"live: OpenAI ({model})"
    return None, ("No API key found when the app started. Put `ANTHROPIC_API_KEY=sk-ant-...` in a `.env` "
                  "file in the pii_guard folder, then restart the app.")


EDUCATOR_PROMPT = """You are a privacy educator inside a chat app. The user just asked a question.
Context from the PII-harms knowledge base:
{context}

User question: {question}

Answer in 3-5 plain-language sentences. Ground your answer in the context. Do not ask for, repeat,
or guess any personal information."""

ASSISTANT_PROMPT = """You are a helpful assistant. The user's message has had personal information
replaced with tokens like [SSN REDACTED]. Never ask the user to provide the redacted information;
if it seems needed, explain how they can find or use it themselves without sharing it.

User: {message}"""


def _text_of(message) -> str:
    """Keep only the answer text. Newer Claude models also return 'thinking' blocks."""
    content = message.content
    if isinstance(content, str):
        return content
    parts = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(p for p in parts if p).strip() or "(The model returned no text.)"


class Answerer:
    def __init__(self, kb: PIIKnowledgeBase) -> None:
        self.kb = kb
        self.llm, self.status = get_llm()
        print(f"[PII Guard] Model status: {self.status}")

    @property
    def mode(self) -> str:
        return "live LLM" if self.llm else "offline demo"

    def _call(self, template: str, **kwargs) -> str | None:
        from langchain_core.prompts import ChatPromptTemplate
        try:
            return _text_of((ChatPromptTemplate.from_template(template) | self.llm).invoke(kwargs))
        except Exception as exc:  # bad key, no credits, wrong model name, no internet...
            msg = str(exc)
            hint = ("Check the key is correct and active at console.anthropic.com." if "401" in msg or "auth" in msg.lower()
                    else "Your account may need credits (console.anthropic.com → Billing)." if "credit" in msg.lower()
                    else "The model name may be wrong; try setting LLM_MODEL in .env." if "404" in msg or "not_found" in msg
                    else "The request settings were rejected by the API; please share this message so the code can be fixed."
                    if "400" in msg or "invalid_request" in msg
                    else "Check your internet connection.")
            return f"⚠️ **The AI call failed:** {msg[:300]}\n\n{hint}"

    def why(self, question: str) -> str:
        """RAG answer to 'why is this risky?' style questions."""
        docs = self.kb.search(question)
        context = "\n\n".join(d.page_content for d in docs)
        if self.llm:
            return self._call(EDUCATOR_PROMPT, context=context, question=question)
        top = docs[0] if docs else self.kb.by_type["GENERAL"]
        return (f"**{_field(top, 'Title')}**: {_field(top, 'Why it matters')}\n\n"
                f"{_field(top, 'Consequences') or _field(top, 'Aggregation risk')}\n\n"
                f"_Retrieved from: {', '.join(d.metadata['pii_type'] for d in docs)}_")

    def reply(self, safe_message: str) -> str:
        """Reply to the (already redacted) chat message."""
        if self.llm:
            return self._call(ASSISTANT_PROMPT, message=safe_message)
        return (f"*(Offline demo mode. Why: {self.status})*\n\n"
                f"This is exactly what the AI model received:\n\n> {safe_message}\n\n"
                "Notice that it can still help with your question without your personal details.")
