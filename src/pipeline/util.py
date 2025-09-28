import os
import shutil
import subprocess
import sys
from pathlib import Path

# --- append to your existing src/pipeline/util.py ---

import subprocess
from pathlib import Path

def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the CompletedProcess, raising if check=True and exit!=0."""
    return subprocess.run(cmd, text=True, capture_output=True, check=check)

def append_unique_lines(src_file: str | Path, dst_file: str | Path):
    """Append unique, non-empty lines from src_file to dst_file."""
    src = Path(src_file)
    dst = Path(dst_file)
    dst.parent.mkdir(parents=True, exist_ok=True)
    have = set()
    if dst.exists():
        have = {l.strip() for l in dst.read_text().splitlines() if l.strip()}
    if src.exists():
        new = [l.strip() for l in src.read_text().splitlines() if l.strip() and l.strip() not in have]
        if new:
            with dst.open("a") as f:
                for line in new:
                    f.write(line + "\n")


def _run_ok(args):
    return subprocess.run(args, capture_output=True, text=True, check=True)

def resolve_binary(
    name: str,
    must_contain: str | None = None,
    candidates: list[str] | None = None,
) -> str:
    """
    Return a path to an executable. Preference order:
      1) ${NAME}_BIN env var (e.g., HTTPX_BIN=/opt/homebrew/bin/httpx)
      2) explicit candidates (e.g., ['/opt/homebrew/bin/httpx', '/usr/local/bin/httpx'])
      3) shutil.which(name)
    If must_contain is provided, the tool's `-version` output must include it.
    """
    tried: list[tuple[str, str]] = []

    search: list[str] = []
    env_override = os.getenv(f"{name.upper()}_BIN")
    if env_override:
        search.append(env_override)
    if candidates:
        search.extend(candidates)
    found = shutil.which(name)
    if found:
        search.append(found)

    for cand in [c for c in search if c]:
        try:
            proc = _run_ok([cand, "-version"])
            text = (proc.stdout + proc.stderr).lower()
            if (must_contain is None) or (must_contain.lower() in text):
                return cand
            tried.append((cand, f"version output did not contain '{must_contain}'"))
        except Exception as e:
            tried.append((cand, str(e)))

    details = "\n".join(f" - {p}: {err}" for p, err in tried) or " (no candidates tried)"
    sys.exit(f"[fatal] Could not find a valid '{name}'. Tried:\n{details}")

def resolve_nuclei(candidates: list[str] | None = None) -> str:
    """
    Pick a nuclei binary that supports JSON output flags across versions
    (-jsonl, -jsonl-export, or -json-export).
    """
    tried: list[tuple[str, str]] = []
    search: list[str] = []
    env_override = os.getenv("NUCLEI_BIN")
    if env_override:
        search.append(env_override)
    if candidates:
        search.extend(candidates)
    found = shutil.which("nuclei")
    if found:
        search.append(found)

    for cand in [c for c in search if c]:
        try:
            out = _run_ok([cand, "-h"])
            helptext = (out.stdout + out.stderr).lower()
            if any(flag in helptext for flag in ("-jsonl", "-jsonl-export", "-json-export")):
                return cand
            tried.append((cand, "missing json flags (-jsonl/-jsonl-export/-json-export)"))
        except Exception as e:
            tried.append((cand, str(e)))

    details = "\n".join(f" - {p}: {err}" for p, err in tried) or " (no candidates tried)"
    sys.exit(f"[fatal] No nuclei with JSON support found. Tried:\n{details}")

def require_nonempty_file(path: str, label: str) -> str:
    """
    Ensure a file exists and contains non-whitespace content.
    """
    p = Path(path)
    if not p.exists():
        sys.exit(f"[fatal] Expected {label} at {path} but it does not exist.")
    try:
        content = p.read_text()
    except Exception as e:
        sys.exit(f"[fatal] Could not read {label} at {path}: {e}")
    if not content.strip():
        sys.exit(f"[fatal] {label} is empty: {path}")
    return str(p)

from pathlib import Path
import subprocess

def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)

def append_unique_lines(src_file: str | Path, dst_file: str | Path):
    src = Path(src_file); dst = Path(dst_file)
    dst.parent.mkdir(parents=True, exist_ok=True)
    have = set()
    if dst.exists():
        have = {l.strip() for l in dst.read_text().splitlines() if l.strip()}
    if src.exists():
        new = [l.strip() for l in src.read_text().splitlines() if l.strip() and l.strip() not in have]
        if new:
            with dst.open("a", encoding="utf-8") as f:
                for line in new:
                    f.write(line + "\n")

# --- feature sniffers for CLI flags ---

import subprocess

def httpx_help(httpx_bin: str) -> str:
    try:
        out = subprocess.run([httpx_bin, "-h"], text=True, capture_output=True, check=False)
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""

def flag_supported(help_text: str, *aliases: str) -> str | None:
    """
    Return the first alias that appears in help_text (e.g., '-l' or '-list').
    """
    ht = help_text.lower()
    for a in aliases:
        if a.lower() in ht:
            return a
    return None

