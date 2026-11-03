"""
setup_key.py: creates the .env file for you.

Run:  python3 setup_key.py
Paste your Anthropic API key when asked (it stays hidden while you paste),
press Enter, and the .env file is created next to app.py.
"""

from getpass import getpass
from pathlib import Path

env_path = Path(__file__).parent / ".env"

print("Paste your Anthropic API key and press Enter.")
print("(Nothing will appear while you paste. That's normal; it's hidden for privacy.)")
key = getpass("API key: ").strip().strip('"').strip("'")

if not key:
    print("No key entered. Nothing was saved. Run `python3 setup_key.py` again.")
elif not key.startswith("sk-ant-"):
    print("That doesn't look like an Anthropic key (they start with 'sk-ant-'). Nothing was saved.")
    print("Copy it again from console.anthropic.com > API Keys, then rerun this script.")
else:
    env_path.write_text(f"ANTHROPIC_API_KEY={key}\n", encoding="utf-8")
    print(f"Saved! Created {env_path}")
    print("Now start the app with:  python3 app.py")
