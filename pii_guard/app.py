"""
app.py: PII Guard, a Gradio prototype that intercepts personal information
before it reaches an LLM, explains the harm using LangChain RAG, and tests
whether users understand the implications.

Run:  python app.py      then open http://127.0.0.1:7860
"""

from __future__ import annotations

import csv
import html
import tempfile
from datetime import datetime

import gradio as gr

from pii_detector import detect_pii, redact, risk_score, PIIMatch
from rag import PIIKnowledgeBase, Answerer

kb = PIIKnowledgeBase()
answerer = Answerer(kb)

SEV_COLOR = {"critical": "#c62828", "high": "#ef6c00", "medium": "#9e7c00"}


# ------------------------------------------------------------ html helpers
def warning_card(matches: list[PIIMatch]) -> str:
    rows = []
    for m in matches:
        info = kb.explain(m.pii_type)
        rows.append(f"""
        <div class="pii-row">
          <div class="pii-head">
            <span class="pii-label">{html.escape(m.label)}</span>
            <span class="pii-sev" style="background:{SEV_COLOR[m.severity]}">{m.severity}</span>
            <code>{html.escape(m.masked())}</code>
          </div>
          <div class="pii-cons"><b>Consequence:</b> {html.escape(info['consequences'])}</div>
          <div class="pii-alt"><b>Safer way:</b> {html.escape(info['alternative'])}</div>
        </div>""")
    score = risk_score(matches)
    return f"""
    <div class="warn-card">
      <div class="warn-title">⚠️ Warning: Security Breach</div>
      <div class="warn-sub">Your message contains <b>{len(matches)}</b> piece(s) of personal information.
        Once sent to an AI model, it may be logged, reviewed, or exposed in a breach, and you can't take it back.</div>
      <div class="meter"><div class="meter-fill" style="width:{score}%"></div></div>
      <div class="meter-label">Exposure risk: {score}/100</div>
      {''.join(rows)}
    </div>"""


def typing_hint(text: str) -> str:
    matches = detect_pii(text or "")
    if not matches:
        return ""
    kinds = ", ".join(sorted({m.label for m in matches}))
    return f"<div class='hint'>🔒 Sensitive info detected while typing: {html.escape(kinds)}</div>"


def log_event(log: list, action: str, matches: list[PIIMatch], redacted_ids=None) -> list:
    log = list(log)
    log.append({
        "time": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "pii_types": ";".join(m.pii_type for m in matches),
        "redacted": ";".join(m.pii_type for m in matches if redacted_ids is None or m.id in redacted_ids),
        "risk_score": risk_score(matches),
    })
    return log


def stats_md(log: list) -> str:
    if not log:
        return "_No messages yet._"
    caught = sum(1 for e in log if e["pii_types"])
    redacted = sum(1 for e in log if e["action"] == "sent_redacted")
    anyway = sum(1 for e in log if e["action"] == "sent_anyway")
    edited = sum(1 for e in log if e["action"] == "edited")
    return (f"**Messages:** {len(log)}  \n**Contained PII:** {caught}  \n"
            f"**Redacted:** {redacted} · **Edited:** {edited} · **Sent anyway:** {anyway}")


# ---------------------------------------------------------------- handlers
HIDE = gr.Column(visible=False)


def chat_view(history, show=True):
    return gr.Chatbot(value=history, visible=show)


def on_submit(msg, history, protect, log):
    msg = (msg or "").strip()
    if not msg:
        return chat_view(history), gr.skip(), None, HIDE, "", gr.CheckboxGroup(), log, stats_md(log)
    matches = detect_pii(msg)

    if matches and protect:
        choices = [(f"{m.label}: {m.masked()}", m.id) for m in matches]
        pending = {"msg": msg, "matches": matches}
        return (chat_view(history, False), gr.skip(), pending, gr.Column(visible=True), warning_card(matches),
                gr.CheckboxGroup(choices=choices, value=[m.id for m in matches]),
                log, stats_md(log))

    # Unprotected (control condition) or clean message.
    safe = redact(msg, matches)  # the prototype never forwards real PII to an API
    history = history + [{"role": "user", "content": msg},
                         {"role": "assistant", "content": answerer.reply(safe)}]
    if matches:
        kinds = ", ".join(m.label for m in matches)
        history.append({"role": "assistant", "content":
            f"⚠️ **After-the-fact notice:** protection was off, so in a real chatbot your "
            f"**{kinds}** would now be on someone else's servers. Turn on Private mode to catch this before sending."})
    log = log_event(log, "sent_unprotected" if matches else "sent_clean", matches, set())
    return chat_view(history), "", None, HIDE, "", gr.CheckboxGroup(), log, stats_md(log)


def send_redacted(selected, pending, history, log):
    if not pending:
        return chat_view(history), gr.skip(), None, HIDE, log, stats_md(log)
    ids = set(selected or [])
    safe = redact(pending["msg"], pending["matches"], ids)
    history = history + [{"role": "user", "content": safe},
                         {"role": "assistant", "content": answerer.reply(redact(safe, detect_pii(safe)))}]
    log = log_event(log, "sent_redacted", pending["matches"], ids)
    return chat_view(history), "", None, HIDE, log, stats_md(log)


def send_anyway(pending, history, log):
    if not pending:
        return chat_view(history), gr.skip(), None, HIDE, log, stats_md(log)
    m = pending["matches"]
    kinds = ", ".join(x.label for x in m)
    history = history + [
        {"role": "user", "content": pending["msg"]},
        {"role": "assistant", "content": answerer.reply(redact(pending["msg"], m))},
        {"role": "assistant", "content":
            f"🛑 **You chose to share: {kinds}.** In an ordinary AI chat this would now be stored outside your control. "
            "(This study prototype still strips it before calling the model, so nothing real was exposed.)"},
    ]
    log = log_event(log, "sent_anyway", m, set())
    return chat_view(history), "", None, HIDE, log, stats_md(log)


def edit_message(pending, history, log):
    if pending:
        log = log_event(log, "edited", pending["matches"], set())
    return chat_view(history), None, HIDE, log, stats_md(log)


def ask_why(question):
    q = (question or "").strip() or "Why is it risky to share personal information with AI chatbots?"
    if detect_pii(q):
        return "Please ask without including personal details. Try: *Why is sharing my SSN risky?*"
    return answerer.why(q)


def export_log(log):
    if not log:
        return gr.File(visible=False)
    f = tempfile.NamedTemporaryFile("w", suffix="_pii_session_log.csv", delete=False, newline="")
    w = csv.DictWriter(f, fieldnames=list(log[0].keys()))
    w.writeheader()
    w.writerows(log)
    f.close()
    return gr.File(value=f.name, visible=True)


def new_chat():
    return chat_view([]), "", None, HIDE


# -------------------------------------------------------------------- quiz
QUIZ = [
    ("A caller says they're from your 401(k) provider. You ask the AI: \"Hi, I'm Dana Brooks, born 03/14/1958. "
     "They want me to confirm SSN 412-55-8890. Can you help me reply?\" What's the safest move?",
     ["Send it as is: the AI needs the details to help",
      "Redact only the SSN",
      "Remove the SSN, birth date and name, and don't confirm your SSN to an unexpected caller",
      "Add your account number so the AI can verify the caller"], 2, "SSN"),
    ("Which single detail is the most dangerous to type into a chatbot?",
     ["Your city", "Your email address", "Your Social Security Number", "Your favorite color"], 2, "SSN"),
    ("\"My birthday is already on Facebook, so sharing it with an AI is harmless.\"",
     ["True: it's already public", "False: small details combine into a full identity profile"], 1, "DOB"),
    ("You want help understanding a strange charge on your card. What should you share?",
     ["The full card number and CVV", "The last four digits, merchant and amount",
      "Your online banking password", "A photo of the front and back of the card"], 1, "CREDIT_CARD"),
    ("Where can text you type into an AI chatbot end up?",
     ["Only on my screen", "Possibly in logs, human review, model training, or a data breach",
      "It's deleted the moment I close the tab", "Only with my bank"], 1, "GENERAL"),
    ("You want to know if your password is strong enough. What's the safest prompt?",
     ["Paste your real password", "Describe a made-up example with the same structure",
      "Share the password plus the site it's for", "Share it, then delete the chat"], 1, "PASSWORD"),
]


def grade(*answers):
    score, lines = 0, []
    for i, ((q, opts, correct, ptype), a) in enumerate(zip(QUIZ, answers), 1):
        info = kb.explain(ptype)
        ok = a == opts[correct]
        score += ok
        mark = "✅" if ok else ("❌" if a else "⬜")
        lines.append(f"{mark} **Q{i}.** Correct answer: *{opts[correct]}*  \n"
                     f"&nbsp;&nbsp;&nbsp;Why: {info['why']} {info['llm_risk'] if ptype != 'GENERAL' else ''}")
    level = ("Privacy pro 🛡️" if score == len(QUIZ) else
             "Getting there" if score >= len(QUIZ) - 2 else "Worth a second look")
    return f"### Score: {score}/{len(QUIZ)} · {level}\n\n" + "\n\n".join(lines)


# ---------------------------------------------------------------------- UI
CSS = """
.sidebar button {justify-content:flex-start !important;}
.warn-panel {background:#ffd4d8 !important;border:2px solid #c62828 !important;border-radius:16px !important;
  padding:14px !important;min-height:380px;}
.warn-panel, .warn-panel * {color:#000 !important;}
.warn-panel .pii-sev {color:#fff !important;}
.warn-panel [data-testid="block-info"] {background:#fff !important;border:1px solid #c62828;}
.warn-panel .block, .warn-panel .form, .warn-panel fieldset, .warn-panel .html-container, .warn-panel .prose
  {background:transparent !important;border:none !important;box-shadow:none !important;}
.warn-panel label {background:#fff !important;border:1px solid #c62828 !important;}
.warn-panel button {background:#fff !important;border:1px solid #000 !important;font-weight:600;}
.warn-panel button.primary {background:#ffffff !important;border:2px solid #c62828 !important;}
.warn-panel button.stop {background:#ffb3b9 !important;}
.warn-card {background:transparent;border-radius:14px;padding:4px 6px;}
.warn-title {font-weight:800;font-size:1.25rem;margin-bottom:4px;}
.warn-sub {font-size:.9rem;margin-bottom:10px;}
.meter {height:8px;background:#fff;border-radius:6px;overflow:hidden;}
.meter-fill {height:100%;background:linear-gradient(90deg,#ef6c00,#c62828);}
.meter-label {font-size:.75rem;margin:4px 0 10px;opacity:.8;}
.pii-row {border-top:1px solid #e08890;padding:8px 0;font-size:.88rem;}
.pii-head {display:flex;gap:8px;align-items:center;margin-bottom:3px;}
.pii-label {font-weight:600;}
.pii-sev {color:#fff;border-radius:8px;padding:0 7px;font-size:.7rem;text-transform:uppercase;}
.pii-alt {}
.hint {font-size:.8rem;color:#ef6c00;padding:2px 4px;}
.welcome h1 {text-align:center;font-weight:400;}
"""

with gr.Blocks(title="PII Guard: Private Chat") as demo:
    pending = gr.State(None)
    log = gr.State([])

    with gr.Row(equal_height=False):
        # ---- sidebar (mirrors the Figma nav)
        with gr.Column(scale=1, min_width=180, elem_classes="sidebar"):
            gr.Markdown("### AI")
            new_btn = gr.Button("＋ New chat", variant="secondary", size="sm")
            gr.Button("Search", size="sm")
            gr.Button("Projects", size="sm")
            gr.Button("Artifacts", size="sm")
            protect = gr.Checkbox(value=True, label="🔒 Private mode (warn before sending)")
            gr.Markdown("#### Session")
            stats = gr.Markdown("_No messages yet._")
            export_btn = gr.Button("Export session log (CSV)", size="sm")
            export_file = gr.File(label="Session log", visible=False)
            gr.Markdown(f"<small>Model: {answerer.status}</small>")

        # ---- main area
        with gr.Column(scale=4):
            with gr.Tabs():
                with gr.Tab("Private Chat"):
                    gr.Markdown("# Welcome", elem_classes="welcome")
                    chat = gr.Chatbot(height=380, label="Chat", show_label=False,
                                      placeholder="Ask anything, like *How should I file my taxes?*")
                    with gr.Column(visible=False, elem_classes="warn-panel") as warn_group:
                        warn_html = gr.HTML()
                        redact_pick = gr.CheckboxGroup(label="Redact these items (✓ = remove before sending)")
                        with gr.Row():
                            redact_btn = gr.Button("Send redacted", variant="primary")
                            edit_btn = gr.Button("Edit my message")
                            anyway_btn = gr.Button("Send anyway", variant="stop")
                    hint = gr.HTML()
                    with gr.Row():
                        msg = gr.Textbox(placeholder="How should I file tax?", show_label=False,
                                         scale=8, lines=1, max_lines=6)
                        send = gr.Button("↑", variant="primary", scale=1, min_width=60)
                    gr.Examples(examples=[
                        ["Hi my name is Joy! Here is my SSN 123-21-2323. What is my SSN number used for?"],
                        ["How should I file tax?"],
                        ["My routing number is 061000104 and account number: 123456789012. How do I set up direct deposit?"],
                        ["I live at 1420 Peachtree Street, call me at (404) 555-0182. Is my password: Sunny2024! strong?"],
                    ], inputs=msg, label="Try a prompt")

                    with gr.Accordion("❓ Ask why something is risky (RAG)", open=False):
                        why_q = gr.Textbox(placeholder="e.g. Why is sharing my date of birth risky?", show_label=False)
                        why_btn = gr.Button("Explain", size="sm")
                        why_out = gr.Markdown()

                with gr.Tab("Awareness Quiz"):
                    gr.Markdown("### Test yourself: would you share this with an AI?")
                    radios = [gr.Radio(choices=o, label=f"Q{i}. {q}") for i, (q, o, _, _) in enumerate(QUIZ, 1)]
                    grade_btn = gr.Button("Check my answers", variant="primary")
                    result = gr.Markdown()

    # ---- wiring
    submit_outputs = [chat, msg, pending, warn_group, warn_html, redact_pick, log, stats]
    msg.submit(on_submit, [msg, chat, protect, log], submit_outputs)
    send.click(on_submit, [msg, chat, protect, log], submit_outputs)
    msg.change(typing_hint, msg, hint, show_progress="hidden")
    redact_btn.click(send_redacted, [redact_pick, pending, chat, log], [chat, msg, pending, warn_group, log, stats])
    anyway_btn.click(send_anyway, [pending, chat, log], [chat, msg, pending, warn_group, log, stats])
    edit_btn.click(edit_message, [pending, chat, log], [chat, pending, warn_group, log, stats])
    new_btn.click(new_chat, None, [chat, msg, pending, warn_group])
    why_btn.click(ask_why, why_q, why_out)
    why_q.submit(ask_why, why_q, why_out)
    grade_btn.click(grade, radios, result)
    export_btn.click(export_log, log, export_file)


if __name__ == "__main__":
    demo.launch(css=CSS, theme=gr.themes.Soft(), show_error=True)
