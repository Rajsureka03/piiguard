"""agent.py: prompt building, tools and a streamed, gated tool-calling loop."""
from __future__ import annotations

import os
import time
from typing import Iterator

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

from gate import GateResult, ensure_clean
from memory import MemoryStore, profile_summary
from retrieval import BY_ID, format_context, retrieve

STATIC_PROMPT = open(os.path.join(os.path.dirname(__file__), "system_prompt_static.txt")).read()
DYNAMIC_TEMPLATE = """<personalization_data>
{profile_summary}
</personalization_data>
<session>
{session_summary}
Already explained this session (do not repeat in full): {already_explained}
</session>
<this_turn>
Detected and handled before you saw the message: {detected_types}
Study condition: {study_condition}
</this_turn>
<retrieved_context>
{retrieved_context}
</retrieved_context>"""

QUIZ_BANK = {
    "SSN": ("A caller says they're from your 401(k) provider and asks you to confirm your SSN. What do you do?",
            "Hang up and call the number on your official statement. Never confirm an SSN to an unexpected caller."),
    "DOB": ("Your birthday is public on social media. Is it safe to share with an AI chatbot?",
            "No. Combined with a name and address it helps build a full identity profile."),
    "PASSWORD": ("How can you check if a password is strong without sharing it?",
                 "Describe a made-up example with the same structure, or use your password manager's checker."),
}


def make_tools(memory: MemoryStore, user_id: str):
    @tool
    def lookup_pii_risk(pii_type: str, field: str = "consequences") -> str:
        """Fetch a knowledge-base section. field: why | consequences | llm_risk | alternative."""
        d = BY_ID.get(f"{pii_type}:{field}:v3")
        return f"[{d.metadata['chunk_id']}] {d.page_content}" if d else "No section found."

    @tool
    def suggest_safe_rewrite(question: str) -> str:
        """Return the user's question with any personal data removed and placeholders explained."""
        clean = ensure_clean(question)
        return f"Safe version: {clean}\nPlaceholders like [SSN REDACTED] can simply be deleted; the question still works."

    @tool
    def generate_quiz_item(pii_type: str) -> str:
        """Return one practice question and its answer for a PII type."""
        q, a = QUIZ_BANK.get(pii_type, QUIZ_BANK["SSN"])
        return f"Question: {q}\nAnswer: {a}"

    @tool
    def record_learning_signal(signal: str, pii_type: str) -> str:
        """Record that the user showed understanding or confusion. signal: understood | confused."""
        memory.record_signal(user_id, signal, pii_type)
        return "recorded"

    return [lookup_pii_risk, suggest_safe_rewrite, generate_quiz_item, record_learning_signal]


def build_messages(gate: GateResult, action: str, profile: dict, session: dict) -> tuple[list, list[str]]:
    docs = retrieve(gate.redacted, gate.types, profile, set(session["already_explained"]))
    detected = (", ".join(f"{t} ({action})" for t in gate.types)) or "none"
    dynamic = DYNAMIC_TEMPLATE.format(
        profile_summary=profile_summary(profile),
        session_summary=session.get("summary") or "(new session)",
        already_explained=", ".join(session["already_explained"]) or "none",
        detected_types=detected,
        study_condition=profile["consent"]["study_condition"],
        retrieved_context=format_context(docs))
    system = SystemMessage(content=[
        {"type": "text", "text": STATIC_PROMPT, "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": ensure_clean(dynamic)}])
    history = session["turns"][-8:]                      # redacted turns only
    return [system, *history, HumanMessage(content=gate.redacted)], [d.metadata["chunk_id"] for d in docs]


def _safe_prefix(text: str) -> str:
    """Hold back a trailing token with digits: it may be the start of a number split across chunks."""
    cut = max(text.rfind(" "), text.rfind("\n"))
    tail = text[cut + 1:]
    return text if not any(c.isdigit() for c in tail) else text[:cut + 1]


def stream_reply(llm, gate: GateResult, action: str, user_id: str, session_id: str, session: dict,
                 memory: MemoryStore, max_tool_rounds: int = 3) -> Iterator[str]:
    """Yields the reply so far, already passed through the output gate."""
    t0 = time.perf_counter()
    profile = memory.get_profile(user_id)
    tools = make_tools(memory, user_id)
    by_name = {t.name: t for t in tools}
    model = llm.bind_tools(tools)
    messages, chunk_ids = build_messages(gate, action, profile, session)
    shown = ""
    for _ in range(max_tool_rounds + 1):
        full = None
        for chunk in model.stream(messages):
            full = chunk if full is None else full + chunk
            if chunk.text:
                shown += chunk.text
                yield ensure_clean(_safe_prefix(shown))    # mask the whole buffer; hold back partial numbers
        messages.append(full)
        if not getattr(full, "tool_calls", None):
            break
        for call in full.tool_calls:
            fn = by_name.get(call["name"])
            result = fn.invoke(call["args"]) if fn else "Unknown tool."
            messages.append(ToolMessage(content=ensure_clean(str(result)), tool_call_id=call["id"]))
    final = ensure_clean(shown)
    yield final
    session["turns"] += [HumanMessage(content=gate.redacted), AIMessage(content=final)]
    session["already_explained"] = sorted(set(session["already_explained"]) | set(chunk_ids))
    if profile["consent"]["research_logging"]:
        redacted_types = gate.types if action in ("sent_redacted",) else []
        memory.log_turn(user_id, session_id, action, gate.types, redacted_types, gate.risk,
                        profile["consent"]["study_condition"], int((time.perf_counter() - t0) * 1000), chunk_ids)
    if final != shown:
        print("[output-gate] masked PII in a model reply")   # also log a leak_incident event in production


def get_llm():
    from langchain_anthropic import ChatAnthropic
    return ChatAnthropic(model=os.getenv("LLM_MODEL", "claude-haiku-5-5"), max_tokens=1024, streaming=True)
