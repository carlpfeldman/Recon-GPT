from pathlib import Path
from .util import resolve_nuclei, run_cmd

def nuclei_import(input_path: str, input_mode: str, out_jsonl_file: str):
    nuclei = resolve_nuclei(candidates=["/opt/homebrew/bin/nuclei","/usr/local/bin/nuclei"])
    Path(out_jsonl_file).parent.mkdir(parents=True, exist_ok=True)
    cmd = [nuclei, "-l", input_path, "-im", input_mode, "-jsonl-export", out_jsonl_file, "-silent"]
    run_cmd(cmd, check=False)
