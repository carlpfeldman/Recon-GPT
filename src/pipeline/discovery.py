from pathlib import Path
import json
from .util import resolve_binary, run_cmd, append_unique_lines

def run_katana(target_url: str, out_file: str, depth: int = 2, headless: bool = False):
    katana = resolve_binary("katana", candidates=["/opt/homebrew/bin/katana","/usr/local/bin/katana"])
    cmd = [katana, "-u", target_url, "-silent", "-jc", "-d", str(depth)]
    if headless:
        cmd += ["-hl"]
    out = run_cmd(cmd, check=False)
    Path(out_file).write_text(out.stdout)

def run_gau(domain: str, out_file: str):
    gau = resolve_binary("gau", candidates=["/opt/homebrew/bin/gau","/usr/local/bin/gau", str(Path.home()/".local/bin/gau")])
    out = run_cmd([gau, domain], check=False)
    Path(out_file).write_text(out.stdout)

def run_ferox(url: str, wordlist: str, out_file: str):
    ferox = resolve_binary("feroxbuster", candidates=["/opt/homebrew/bin/feroxbuster","/usr/local/bin/feroxbuster"])
    cmd = [ferox, "-u", url, "-w", wordlist, "-q"]
    out = run_cmd(cmd, check=False)
    urls = []
    for line in out.stdout.splitlines():
        parts = line.strip().split()
        if parts:
            urls.append(parts[-1])
    Path(out_file).write_text("\n".join(urls) + ("\n" if urls else ""))

def run_ffuf(url_template: str, wordlist: str, out_json: str, out_urls: str):
    ffuf = resolve_binary("ffuf", candidates=["/opt/homebrew/bin/ffuf","/usr/local/bin/ffuf"])
    cmd = [ffuf, "-w", wordlist, "-u", url_template, "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", out_json]
    run_cmd(cmd, check=False)
    urls = []
    p = Path(out_json)
    if p.exists() and p.stat().st_size:
        try:
            data = json.loads(p.read_text())
            for r in data.get("results", []):
                u = r.get("url")
                if u:
                    urls.append(u)
        except Exception:
            pass
    Path(out_urls).write_text("\n".join(sorted(set(urls))) + ("\n" if urls else ""))

def merge_into_urls(temp_file: str, urls_file: str):
    append_unique_lines(temp_file, urls_file)
