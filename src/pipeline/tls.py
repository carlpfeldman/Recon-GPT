from pathlib import Path
from .util import resolve_binary, run_cmd, append_unique_lines

def run_tlsx(hosts_file: str, out_names_file: str):
    tlsx = resolve_binary("tlsx", candidates=["/opt/homebrew/bin/tlsx","/usr/local/bin/tlsx"])
    cmd = [tlsx, "-l", hosts_file, "-san", "-cn", "-silent", "-resp-only"]
    out = run_cmd(cmd, check=False)
    names = []
    for line in out.stdout.splitlines():
        for part in line.split(","):
            s = part.strip()
            if s:
                names.append(s)
    Path(out_names_file).write_text("\n".join(sorted(set(names))) + ("\n" if names else ""))

def merge_names_into_subs(names_file: str, subs_file: str):
    append_unique_lines(names_file, subs_file)
