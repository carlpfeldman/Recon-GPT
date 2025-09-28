import subprocess
import pathlib

def run_dnsx(in_file: str, out_file: str):
    """
    Run dnsx to resolve subs from in_file.
    We keep ONLY the domain/host (first token), one per line, for httpx.
    """
    out_path = pathlib.Path(out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # dnsx prints lines like: sub.example.com A 1.2.3.4
    # We'll capture stdout and keep just the first column.
    proc = subprocess.run(
        ["dnsx", "-a", "-resp", "-l", in_file, "-silent"],
        capture_output=True,
        text=True,
        check=True,
    )
    hosts = []
    for line in proc.stdout.splitlines():
        # keep the first whitespace-separated token (the hostname)
        host = line.strip().split()[0] if line.strip() else ""
        if host:
            hosts.append(host)

    out_path.write_text("\n".join(sorted(set(hosts))) + ("\n" if hosts else ""))
    return str(out_path)
