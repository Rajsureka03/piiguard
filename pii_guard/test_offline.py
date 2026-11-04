"""Offline checks: ingestion, gate, retrieval, memory, prompt building, and the streamed tool loop
with a scripted fake model (no API key needed)."""
import os

from langchain_core.messages import AIMessageChunk

os.environ.pop("USE_EMBEDDINGS", None)
from ingest import load_chunks
from gate import scan
from retrieval import retrieve
from memory import MemoryStore
import agent

chunks = load_chunks()
assert len(chunks) > 40, len(chunks)

g = scan("Hi my name is Joy! Here is my SSN 123-21-2323. What is my SSN number used for?")
assert g.types == ["NAME", "SSN"] and "123-21-2323" not in g.redacted
print("gate:", g.redacted)

mem = MemoryStore(":memory:")
p = mem.get_profile("u_test")
p["consent"].update(personalization=True, research_logging=True)
p["explicit"]["topics_of_interest"] = ["taxes"]
mem.save_profile(p)
try:
    bad = dict(p); bad["explicit"] = dict(p["explicit"], note="my SSN is 123-45-6789")
    mem.save_profile(bad); raise SystemExit("profile PII check failed")
except AssertionError:
    print("memory: refused to store PII  OK")

docs = retrieve(g.redacted, g.types, p, set())
ids = [d.metadata["chunk_id"] for d in docs]
assert ids[0].startswith("SSN:"), ids
print("retrieval:", ids)


class ScriptedLLM:
    """Round 1: calls a tool and leaks a fake SSN split across chunks. Round 2: final answer."""
    def __init__(self): self.round = 0
    def bind_tools(self, tools): return self
    def stream(self, messages):
        self.round += 1
        if self.round == 1:
            yield AIMessageChunk(content="Checking. Example: 123-45-")
            yield AIMessageChunk(content="6789 ", tool_call_chunks=[
                {"name": "lookup_pii_risk", "args": '{"pii_type": "SSN"}', "id": "t1", "index": 0}])
        else:
            yield AIMessageChunk(content=" Your SSN is used for taxes and employment [SSN:why:v3].")


session = {"turns": [], "already_explained": [], "summary": ""}
outs = list(agent.stream_reply(ScriptedLLM(), g, "sent_redacted", "u_test", "s1", session, mem))
final = outs[-1]
assert not any("123-45" in o for o in outs), [o for o in outs if "123-45" in o]
assert "6789" not in final and "[SSN REDACTED]" in final, final
print("stream final:", final)
assert session["already_explained"], "dedupe state not updated"
row = mem.db.execute("SELECT action, pii_types, redacted, kb_chunks FROM learning_events").fetchone()
print("event row:", row)
prof = mem.get_profile("u_test")
print("profile implicit:", prof["implicit"]["pii_type_counts"], prof["implicit"]["action_rates"])
assert "123-21-2323" not in str(mem.db.execute("SELECT * FROM learning_events").fetchall())
print("ALL OFFLINE CHECKS PASSED")
