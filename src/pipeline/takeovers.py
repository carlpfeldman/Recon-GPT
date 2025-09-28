from .util import resolve_binary, run_cmd

def run_subjack(hosts_file: str, out_file: str, fingerprints: str | None = None):
    subjack = resolve_binary("subjack", candidates=["/opt/homebrew/bin/subjack","/usr/local/bin/subjack"])
    cmd = [subjack, "-w", hosts_file, "-o", out_file, "-ssl"]
    if fingerprints:
        cmd += ["-c", fingerprints]
    run_cmd(cmd, check=False)
