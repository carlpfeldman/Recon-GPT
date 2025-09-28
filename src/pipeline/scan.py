import subprocess
from pathlib import Path
from .util import resolve_nuclei

def run_nuclei(
    in_urls_file: str,
    out_jsonl_file: str,
    templates: str | None = None,     # path to templates dir or a glob
    tags: str | None = None,          # comma-separated template tags
    severity: str | None = None,      # e.g. "critical,high" (no spaces)
    concurrency: int = 50,            # -c
    rate_limit: int = 200,            # -rl (requests/sec)
    timeout: int = 7,
    retries: int = 1,
):
    """
    Run nuclei on URLs list and export JSONL to out_jsonl_file.
    Compatible with nuclei versions that support -jsonl-export.
    """
    nuclei_bin = resolve_nuclei(candidates=["/opt/homebrew/bin/nuclei", "/usr/local/bin/nuclei"])
    out_path = Path(out_jsonl_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        nuclei_bin,
        "-l", in_urls_file,
        "-jsonl-export", str(out_path),
        "-c", str(concurrency),
        "-rl", str(rate_limit),
        "-timeout", str(timeout),
        "-retries", str(retries),
        "-silent",
    ]
    if templates:
        cmd += ["-t", templates]
    if tags:
        cmd += ["-tags", tags]
    if severity:
        cmd += ["-severity", severity]

    subprocess.run(cmd, check=False)

    if not out_path.exists():
        out_path.write_text("")  # ensure file exists even if zero findings
    return str(out_path)
