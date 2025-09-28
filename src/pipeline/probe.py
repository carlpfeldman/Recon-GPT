# src/pipeline/probe.py
import json
import subprocess
from pathlib import Path
from .util import resolve_binary, httpx_help, flag_supported

def run_httpx(
    in_file: str,
    out_json_file: str,
    out_urls_file: str,
    threads: int = 50,
    rate: int = 100,
    timeout: int = 7,
    retries: int = 2,
    follow_redirects: bool = True,
):
    httpx_bin = resolve_binary(
        "httpx",
        must_contain="projectdiscovery",
        candidates=["/opt/homebrew/bin/httpx", "/usr/local/bin/httpx"],
    )

    helptext = httpx_help(httpx_bin)

    # Pick input flag: '-l' or '-list'
    in_flag = flag_supported(helptext, "-l", "-list") or "-l"

    # Output mode: JSON if supported, else plain text
    json_flag = flag_supported(helptext, "-json")
    json_mode = json_flag is not None

    # Common details: status, title, tech
    status_flag = flag_supported(helptext, "-status-code", "-sc") or "-status-code"
    title_flag  = flag_supported(helptext, "-title") or "-title"
    tech_flag   = flag_supported(helptext, "-tech-detect", "-td") or "-tech-detect"

    # Nice-to-haves
    silent_flag = flag_supported(helptext, "-silent")
    nocolor_flag = flag_supported(helptext, "-no-color")
    follow_flag = flag_supported(helptext, "-follow-redirects")

    out_json = Path(out_json_file)
    out_urls = Path(out_urls_file)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        httpx_bin,
        in_flag, in_file,
        status_flag,
        title_flag,
        tech_flag,
        "-threads", str(threads),
        "-rate", str(rate),
        "-timeout", str(timeout),
        "-retries", str(retries),
    ]
    if json_mode:
        cmd.append(json_flag)
    if silent_flag:
        cmd.append(silent_flag)
    if nocolor_flag:
        cmd.append(nocolor_flag)
    if follow_redirects and follow_flag:
        cmd.append(follow_flag)

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if proc.returncode != 0:
        # Don’t crash the pipeline; record the stderr so you can see what happened.
        out_json.write_text("")
        out_urls.write_text("")
        err = (proc.stderr or "").strip()
        if err:
            print(f"[warn] httpx exited {proc.returncode}:\n{err}")
        else:
            print(f"[warn] httpx exited {proc.returncode} with no stderr.")
        return str(out_json), str(out_urls)

    urls = []

    if json_mode:
        # Write raw JSONL and extract URLs
        with out_json.open("w", encoding="utf-8") as jf:
            for line in proc.stdout.splitlines():
                s = line.strip()
                if not s:
                    continue
                jf.write(s + "\n")
                try:
                    obj = json.loads(s)
                    u = obj.get("url")
                    if u:
                        urls.append(u)
                except json.JSONDecodeError:
                    pass
    else:
        # No JSON support: parse plain lines; last token is usually the URL
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        # Create a minimal JSONL ourselves so downstream code keeps working
        with out_json.open("w", encoding="utf-8") as jf:
            for ln in lines:
                parts = ln.split()
                url = ""
                # find first token that looks like a URL
                for p in parts[::-1]:
                    if p.startswith("http://") or p.startswith("https://"):
                        url = p
                        break
                if not url and parts:
                    url = parts[-1]
                if url:
                    urls.append(url)
                    jf.write(json.dumps({"url": url, "raw": ln}) + "\n")

    out_urls.write_text("\n".join(sorted(set(urls))) + ("\n" if urls else ""))
    return str(out_json), str(out_urls)
