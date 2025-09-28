#!/bin/zsh
set -e

cd /Users/carlfeldman/Hacker_Tools/recon-gpt
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

# Ensure venv
if [ ! -d ".venv" ]; then
  /usr/bin/python3 -m venv .venv
fi
source .venv/bin/activate

# Deps (quiet if already installed)
pip install -q -r requirements.txt || true

# Run one passive cycle
python -m src.passive
