from pathlib import Path
from .util import resolve_binary, run_cmd

def run_gowitness(urls_file: str, out_dir: str):
    gow = resolve_binary("gowitness", candidates=["/opt/homebrew/bin/gowitness","/usr/local/bin/gowitness"])
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    cmd = [gow, "file", "-f", urls_file, "--destination", out_dir]
    run_cmd(cmd, check=False)
