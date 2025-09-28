#!/bin/zsh
set -e

# --- Project location ---
cd /Users/carlfeldman/Hacker_Tools/recon-gpt

# --- Make sure Homebrew + PD tools are on PATH when launched from Finder ---
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

# --- Python venv (create if missing) ---
if [ ! -d ".venv" ]; then
  /usr/bin/python3 -m venv .venv
fi
source .venv/bin/activate

# --- Install deps (quietly) if Streamlit isn’t present ---
if ! command -v streamlit >/dev/null 2>&1; then
  if [ -f requirements.txt ]; then
    pip install -r requirements.txt
  else
    pip install streamlit openai typer python-dotenv pandas rich
  fi
fi

# --- Launch the app ---
exec streamlit run app.py
