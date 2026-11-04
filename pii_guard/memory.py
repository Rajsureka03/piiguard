"""memory.py: pseudonymous profile + event log. Stores categories and counts, never values."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from gate import ensure_clean

ALLOWED_ACTIONS = {"sent_clean", "sent_redacted", "edited", "sent_anyway", "sent_unprotected"}
ALLOWED_SIGNALS = {"understood", "confused"}


class MemoryStore:
    def __init__(self, path: str = "pii_guard.db"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS profiles (user_id TEXT PRIMARY KEY, profile TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS learning_events (
          event_id INTEGER PRIMARY KEY, user_id TEXT NOT NULL, session_id TEXT NOT NULL,
          ts TEXT NOT NULL, event_type TEXT NOT NULL, action TEXT, pii_types TEXT, redacted TEXT,
          risk_score INTEGER, condition TEXT, latency_ms INTEGER, kb_chunks TEXT);
        CREATE INDEX IF NOT EXISTS idx_events_user ON learning_events(user_id, ts);""")

    # ---------- profile
    def get_profile(self, user_id: str) -> dict:
        row = self.db.execute("SELECT profile FROM profiles WHERE user_id=?", (user_id,)).fetchone()
        if row:
            return json.loads(row[0])
        return {"user_id": user_id, "schema_version": 1,
                "consent": {"personalization": False, "research_logging": False, "study_condition": "proactive"},
                "explicit": {"reading_level": "plain", "explanation_style": "brief", "language": "en",
                             "topics_of_interest": []},
                "implicit": {"messages": 0, "pii_type_counts": {}, "action_rates": {}, "mastery": {}},
                "derived": {"weak_topics": [], "recurring_types": []}}

    def save_profile(self, profile: dict) -> None:
        profile["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        blob = json.dumps(profile)
        assert ensure_clean(blob) == blob, "refusing to store a profile containing PII"
        self.db.execute("INSERT OR REPLACE INTO profiles VALUES (?, ?)", (profile["user_id"], blob))
        self.db.commit()

    # ---------- events
    def log_turn(self, user_id, session_id, action, pii_types, redacted, risk, condition, latency_ms, chunks):
        if action not in ALLOWED_ACTIONS:
            raise ValueError(action)
        self.db.execute(
            "INSERT INTO learning_events (user_id, session_id, ts, event_type, action, pii_types, redacted,"
            " risk_score, condition, latency_ms, kb_chunks) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (user_id, session_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), "turn", action,
             ";".join(pii_types), ";".join(redacted), risk, condition, latency_ms, ";".join(chunks)))
        self.db.commit()
        self._recompute(user_id)

    def record_signal(self, user_id: str, signal: str, pii_type: str) -> None:
        if signal not in ALLOWED_SIGNALS:
            raise ValueError(signal)
        p = self.get_profile(user_id)
        m = p["implicit"]["mastery"].get(pii_type, 0.5)
        p["implicit"]["mastery"][pii_type] = round(min(1, m + 0.1) if signal == "understood" else max(0, m - 0.1), 2)
        self._derive(p)
        self.save_profile(p)

    # ---------- aggregation (rules, not the LLM)
    def _recompute(self, user_id: str) -> None:
        p = self.get_profile(user_id)
        rows = self.db.execute("SELECT action, pii_types FROM learning_events WHERE user_id=? AND event_type='turn'",
                               (user_id,)).fetchall()
        counts, actions = {}, {}
        for action, types in rows:
            actions[action] = actions.get(action, 0) + 1
            for t in filter(None, (types or "").split(";")):
                counts[t] = counts.get(t, 0) + 1
        intercepted = sum(actions.get(a, 0) for a in ("sent_redacted", "edited", "sent_anyway")) or 1
        p["implicit"].update(messages=len(rows), pii_type_counts=counts, action_rates={
            a: round(actions.get(a, 0) / intercepted, 2) for a in ("sent_redacted", "edited", "sent_anyway")})
        self._derive(p)
        self.save_profile(p)

    @staticmethod
    def _derive(p: dict) -> None:
        p["derived"] = {
            "weak_topics": sorted(t for t, v in p["implicit"]["mastery"].items() if v < 0.5),
            "recurring_types": sorted(t for t, c in p["implicit"]["pii_type_counts"].items() if c >= 2)}


def profile_summary(p: dict) -> str:
    """3-5 short lines for the prompt. Empty when the user has not consented."""
    if not p["consent"]["personalization"]:
        return "No personalization (user has not opted in). Use plain language, brief style."
    e, d = p["explicit"], p["derived"]
    lines = [f"reading_level: {e['reading_level']}; explanation_style: {e['explanation_style']}"]
    if e["topics_of_interest"]:
        lines.append("topics_of_interest: " + ", ".join(e["topics_of_interest"]))
    if d["weak_topics"]:
        lines.append("weak_topics: " + ", ".join(d["weak_topics"]))
    if d["recurring_types"]:
        lines.append("recurring_types: " + ", ".join(d["recurring_types"]))
    return "\n".join(lines)
