"""
app.py: PII Guard: Private Chat
A Gradio prototype that intercepts personal information before it reaches an
LLM, explains the harm using LangChain RAG, and tests whether users understand
the implications.

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

SEV_COLOR = {"critical": "#e0245e", "high": "#f57c00", "medium": "#b08900"}


# ================================================================ html views
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
      <div class="warn-top">
        <div class="warn-title">⚠️ Warning: Security Breach</div>
        <div class="threat">EXPOSURE RISK <b>{score}</b>/100</div>
      </div>
      <div class="warn-sub">Your message contains <b>{len(matches)}</b> piece(s) of personal information.
        Once sent to an AI model it may be logged, reviewed, or exposed in a breach, and you can't take it back.</div>
      <div class="meter"><div class="meter-fill" style="width:{score}%"></div></div>
      {''.join(rows)}
    </div>"""


def typing_hint(text: str) -> str:
    matches = detect_pii(text or "")
    if not matches:
        return ""
    kinds = ", ".join(sorted({m.label for m in matches}))
    return f"<div class='hint'>🔒 Sensitive info detected while typing: {html.escape(kinds)}</div>"


# ================================================================ logging
def log_event(log, action, matches, redacted_ids=None):
    log = list(log)
    log.append({
        "time": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "pii_types": ";".join(m.pii_type for m in matches),
        "redacted": ";".join(m.pii_type for m in matches if redacted_ids is None or m.id in redacted_ids),
        "risk_score": risk_score(matches),
    })
    return log


def stats_html(log: list) -> str:
    caught = sum(1 for e in log if e["pii_types"])
    count = lambda a: sum(1 for e in log if e["action"] == a)
    return (f"<div class='status stats'><b>Session</b><br>Messages: {len(log)} · With PII: {caught}<br>"
            f"Redacted: {count('sent_redacted')} · Edited: {count('edited')} · Sent anyway: {count('sent_anyway')}</div>")


def export_log(log):
    if not log:
        gr.Warning("No activity to export yet.")
        return gr.File(visible=False)
    f = tempfile.NamedTemporaryFile("w", suffix="_pii_session_log.csv", delete=False, newline="")
    w = csv.DictWriter(f, fieldnames=list(log[0].keys()))
    w.writeheader()
    w.writerows(log)
    f.close()
    return gr.File(value=f.name, visible=True)


# ================================================================ handlers
HIDE = gr.Column(visible=False)


def chat_view(history, show=True):
    return gr.Chatbot(value=history, visible=show)


def on_submit(msg, history, protect, log):
    msg = (msg or "").strip()
    if not msg:
        return chat_view(history), gr.skip(), None, HIDE, "", gr.CheckboxGroup(), log, stats_html(log)
    matches = detect_pii(msg)

    if matches and protect:
        choices = [(f"{m.label}: {m.masked()}", m.id) for m in matches]
        return (chat_view(history, False), gr.skip(), {"msg": msg, "matches": matches},
                gr.Column(visible=True), warning_card(matches),
                gr.CheckboxGroup(choices=choices, value=[m.id for m in matches]), log, stats_html(log))

    safe = redact(msg, matches)  # the prototype never forwards real PII to an API
    history = history + [{"role": "user", "content": msg},
                         {"role": "assistant", "content": answerer.reply(safe)}]
    if matches:  # control condition: protection off
        kinds = ", ".join(m.label for m in matches)
        history.append({"role": "assistant", "content":
            f"⚠️ **After-the-fact notice:** protection was off, so in a real chatbot your **{kinds}** "
            "would now be on someone else's servers. Turn on Private mode to catch this before sending."})
    log = log_event(log, "sent_unprotected" if matches else "sent_clean", matches, set())
    return chat_view(history), "", None, HIDE, "", gr.CheckboxGroup(), log, stats_html(log)


def send_redacted(selected, pending, history, log):
    if not pending:
        return chat_view(history), gr.skip(), None, HIDE, log, stats_html(log)
    ids = set(selected or [])
    safe = redact(pending["msg"], pending["matches"], ids)
    history = history + [{"role": "user", "content": safe},
                         {"role": "assistant", "content": answerer.reply(redact(safe, detect_pii(safe)))}]
    log = log_event(log, "sent_redacted", pending["matches"], ids)
    return chat_view(history), "", None, HIDE, log, stats_html(log)


def send_anyway(pending, history, log):
    if not pending:
        return chat_view(history), gr.skip(), None, HIDE, log, stats_html(log)
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
    return chat_view(history), "", None, HIDE, log, stats_html(log)


def edit_message(pending, history, log):
    if pending:
        log = log_event(log, "edited", pending["matches"], set())
    return chat_view(history), None, HIDE, log, stats_html(log)


def ask_why(question):
    q = (question or "").strip() or "Why is it risky to share personal information with AI chatbots?"
    if detect_pii(q):
        return "Please ask without including personal details. Try: *Why is sharing my SSN risky?*"
    return answerer.why(q)


def new_chat():
    return chat_view([]), "", None, HIDE


# ================================================================ quiz
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
                     f"&nbsp;&nbsp;&nbsp;Why: {info['why']}")
    level = ("Privacy pro 🛡️" if score == len(QUIZ) else
             "Getting there" if score >= len(QUIZ) - 2 else "Worth a second look")
    header = f"<div class='quiz-score'><span>{score}/{len(QUIZ)}</span><b>{level}</b></div>"
    return header + "\n\n" + "\n\n".join(lines)


# ================================================================ styling
CSS = """
:root, .dark {
  --qa-bg1:#171128; --qa-bg2:#0f2129; --qa-glass:rgba(255,255,255,.07);
  --qa-line:rgba(255,255,255,.14); --qa-grad:linear-gradient(135deg,#6a58c9 0%,#8f5fbf 50%,#3e9aa6 100%);
}
body, gradio-app, gradio-app > div, .gradio-container, .main, .wrap.app {background:radial-gradient(1200px 700px at 10% -10%,#2b1d52 0%,transparent 60%),
  radial-gradient(900px 600px at 110% 20%,#16424f 0%,transparent 55%),
  linear-gradient(160deg,var(--qa-bg1),var(--qa-bg2)) !important; background-attachment:fixed !important;}
.gradio-container {max-width:1280px !important; color:#eef0ff;}
.gradio-container .block, .gradio-container .form {background:var(--qa-glass) !important;
  border:1px solid var(--qa-line) !important; border-radius:20px !important; backdrop-filter:blur(14px);}
.gradio-container textarea, .gradio-container input[type=text] {background:rgba(0,0,0,.25) !important;
  border-radius:16px !important; color:#fff !important;}
footer {display:none !important;}
.gradio-container .block.bare {background:transparent !important;border:none !important;
  padding:0 !important;box-shadow:none !important;backdrop-filter:none !important;}
.status {font-size:.8rem;padding:8px 10px;border-radius:12px;background:rgba(255,255,255,.06);border:1px solid var(--qa-line);color:#eef0ff;}

/* HUD */
.hud {display:flex;align-items:center;padding:14px 18px;
  border-radius:24px;background:linear-gradient(135deg,rgba(123,92,255,.35),rgba(24,216,224,.18));
  border:1px solid var(--qa-line);box-shadow:0 10px 40px rgba(0,0,0,.35);}
.hud-brand {display:flex;align-items:center;gap:10px;font-weight:900;font-size:1.5rem;letter-spacing:.06em;color:#fff;line-height:1.05;}
.hud-brand .dot {display:inline-block;width:38px;height:38px;border-radius:50%;flex:none;
  border:5px solid #fff;background:var(--qa-grad);box-shadow:0 0 8px rgba(143,95,191,.45);}
.hud-brand .sub {font-size:.7rem;letter-spacing:.5em;opacity:.8;font-weight:700;}


/* sidebar */
.sidebar button {justify-content:flex-start !important;border-radius:14px !important;
  background:rgba(255,255,255,.06) !important;color:#eef0ff !important;border:1px solid var(--qa-line) !important;}
.sidebar .newchat {background:var(--qa-grad) !important;border:none !important;color:#fff !important;font-weight:700;}
.sidebar-title {font-weight:900;font-size:1.25rem;color:#fff;letter-spacing:.05em;}

/* chat */
.welcome h1 {font-weight:800;font-size:2rem;margin:4px 0 0;color:#fff;}
.welcome p {opacity:.75;color:#dfe3ff;margin:2px 0 6px;}
/* Muted iMessage-style bubbles: blue = user, green = AI (white text passes WCAG AA on both) */
.chat-panel .message-row .message, .chat-panel .message.user, .chat-panel .message.bot,
.chat-panel .user .message-content, .chat-panel .bot .message-content
  {color:#fff !important;border:none !important;border-radius:20px !important;box-shadow:none !important;}
.chat-panel .user .message, .chat-panel .message.user, .chat-panel .user-row .message,
.chat-panel .user .message-content {background:#2F6FD0 !important;}
.chat-panel .bot .message, .chat-panel .message.bot, .chat-panel .bot-row .message,
.chat-panel .bot .message-content {background:#287F4D !important;}
.chat-panel .message *, .chat-panel .message-content * {color:#fff !important;}
.chat-panel .message code, .chat-panel .message blockquote {background:rgba(255,255,255,.18) !important;border-color:rgba(255,255,255,.4) !important;}
.chat-panel .user .message, .chat-panel .message.user {border-bottom-right-radius:6px !important;}
.chat-panel .bot .message, .chat-panel .message.bot {border-bottom-left-radius:6px !important;}
.send-btn {border-radius:50% !important;min-width:58px !important;max-width:58px;height:58px;font-size:1.4rem !important;
  background:var(--qa-grad) !important;border:none !important;box-shadow:0 0 12px rgba(143,95,191,.35);color:#fff !important;}
.hint {font-size:.8rem;color:#ffc145;padding:2px 6px;}

/* security-breach alert: black text on red/pink */
.warn-panel {background:linear-gradient(160deg,#ffe0e4,#ffc3cb) !important;border:2px solid #e0245e !important;
  border-radius:24px !important;padding:16px !important;min-height:380px;box-shadow:0 0 22px rgba(224,36,94,.25);}
.warn-panel, .warn-panel * {color:#000 !important;}
.warn-panel .pii-sev {color:#fff !important;}
.warn-panel .block, .warn-panel .form, .warn-panel fieldset, .warn-panel .html-container, .warn-panel .prose
  {background:transparent !important;border:none !important;box-shadow:none !important;backdrop-filter:none;}
.warn-panel [data-testid="block-info"] {background:#fff !important;border:1px solid #e0245e;border-radius:10px;padding:2px 8px;}
.warn-panel label {background:#fff !important;border:1px solid #e0245e !important;border-radius:12px !important;}
.warn-panel button {background:#fff !important;border:1px solid #000 !important;font-weight:700;border-radius:14px !important;}
.warn-panel button.primary {border:2px solid #e0245e !important;}
.warn-panel button.stop {background:#ffb3bd !important;}
.warn-top {display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;}
.warn-title {font-weight:900;font-size:1.35rem;}
.threat {font-size:.75rem;letter-spacing:.08em;background:#fff;border:1px solid #e0245e;border-radius:999px;padding:3px 10px;}
.warn-sub {font-size:.9rem;margin:6px 0 10px;}
.meter {height:10px;background:#fff;border-radius:8px;overflow:hidden;margin-bottom:8px;}
.meter-fill {height:100%;background:linear-gradient(90deg,#f57c00,#e0245e);}
.pii-row {border-top:1px solid #f08a9e;padding:9px 0;font-size:.88rem;}
.pii-head {display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:3px;}
.pii-label {font-weight:700;}
.pii-sev {border-radius:8px;padding:0 7px;font-size:.7rem;text-transform:uppercase;}

/* quiz */
.quiz-score {display:flex;gap:14px;align-items:center;padding:14px 18px;border-radius:20px;background:var(--qa-grad);color:#fff;}
.quiz-score span {font-size:2rem;font-weight:900;}
.quiz-score small {margin-left:auto;opacity:.9;}
"""

FORCE_DARK = """() => {
  document.body.classList.add('dark');
  const bg = "radial-gradient(1200px 700px at 10% -10%, #2b1d52 0%, transparent 60%)," +
             "radial-gradient(900px 600px at 110% 20%, #16424f 0%, transparent 55%)," +
             "linear-gradient(160deg, #171128, #0f2129)";
  for (const el of [document.body, document.querySelector('gradio-app')]) {
    if (el) { el.style.background = bg; el.style.backgroundAttachment = 'fixed'; }
  }
}"""


# ================================================================ layout
with gr.Blocks(title="PII Guard: Private Chat") as demo:
    pending = gr.State(None)
    log = gr.State([])

    gr.HTML("<div class='hud'><div class='hud-brand'><span class='dot'></span>"
            "<div>PII GUARD<br><span class='sub'>PRIVATE CHAT</span></div></div></div>", elem_classes="bare")

    with gr.Row(equal_height=False):
        # ---- sidebar
        with gr.Column(scale=1, min_width=200, elem_classes="sidebar"):
            gr.HTML("<div class='sidebar-title'>AI</div>", elem_classes="bare")
            new_btn = gr.Button("＋  New chat", size="sm", elem_classes="newchat")
            gr.Button("🔍  Search", size="sm")
            gr.Button("📁  Projects", size="sm")
            gr.Button("🧩  Artifacts", size="sm")
            protect = gr.Checkbox(value=True, label="🔒 Private mode (warn before sending)")
            gr.HTML(f"<div class='status' title='{html.escape(answerer.status)}'>"
                    f"{'🟢 Live: Claude' if answerer.llm else '⚪ Offline demo (no API key)'}</div>", elem_classes="bare")
            stats = gr.HTML(stats_html([]), elem_classes="bare")
            export_btn = gr.Button("⬇  Export session log (CSV)", size="sm")
            export_file = gr.File(label="Session log", visible=False)

        # ---- main area
        with gr.Column(scale=4):
            with gr.Tabs():
                with gr.Tab("💬 Private Chat"):
                    gr.HTML("<div class='welcome'><h1>Welcome</h1>"
                            "<p>Ask anything. PII Guard checks your message before it reaches the AI.</p></div>",
                            elem_classes="bare")
                    chat = gr.Chatbot(height=420, show_label=False, elem_classes="chat-panel",
                                      placeholder="Ask anything, like *How should I file my taxes?*")
                    with gr.Column(visible=False, elem_classes="warn-panel") as warn_group:
                        warn_html = gr.HTML()
                        redact_pick = gr.CheckboxGroup(label="Redact these items (✓ = remove before sending)")
                        with gr.Row():
                            redact_btn = gr.Button("✂️ Send redacted", variant="primary")
                            edit_btn = gr.Button("✏️ Edit my message")
                            anyway_btn = gr.Button("⚠️ Send anyway", variant="stop")
                    hint = gr.HTML(elem_classes="bare")
                    with gr.Row(equal_height=True):
                        msg = gr.Textbox(placeholder="How should I file tax?", show_label=False,
                                         scale=8, lines=1, max_lines=6)
                        send = gr.Button("➤", scale=0, elem_classes="send-btn")
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

                with gr.Tab("🧠 Awareness Quiz"):
                    gr.HTML("<div class='welcome'><h1>Awareness quiz</h1>"
                            "<p>Would you share this with an AI?</p></div>", elem_classes="bare")
                    radios = [gr.Radio(choices=o, label=f"Q{i}. {q}") for i, (q, o, _, _) in enumerate(QUIZ, 1)]
                    grade_btn = gr.Button("Check my answers", variant="primary")
                    result = gr.Markdown()

    # ---- wiring
    submit_out = [chat, msg, pending, warn_group, warn_html, redact_pick, log, stats]
    msg.submit(on_submit, [msg, chat, protect, log], submit_out)
    send.click(on_submit, [msg, chat, protect, log], submit_out)
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
    demo.launch(css=CSS, js=FORCE_DARK, theme=gr.themes.Soft(primary_hue="violet"), show_error=True)
