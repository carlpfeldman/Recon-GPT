from pathlib import Path
from .util import resolve_binary, run_cmd

WEB_PORTS = {80,81,88,443,444,591,593,832,981,1010,1311,2082,2083,2086,2087,2095,2096,2480,3000,3001,3002,3003,3128,3333,4000,4001,4100,4443,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8082,8083,8088,8090,8091,8096,8100,8181,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,10000}

def run_naabu(hosts_file: str, out_ports_file: str, top_ports: int = 1000, rate: int = 2000):
    naabu = resolve_binary("naabu", candidates=["/opt/homebrew/bin/naabu","/usr/local/bin/naabu"])
    cmd = [naabu, "-list", hosts_file, "-top-ports", str(top_ports), "-rate", str(rate), "-silent"]
    out = run_cmd(cmd, check=False)
    Path(out_ports_file).write_text(out.stdout)

def synth_http_urls(ports_file: str, out_urls_file: str):
    urls = []
    p = Path(ports_file)
    if not p.exists():
        Path(out_urls_file).write_text("")
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        host, port = line.split(":", 1)
        try:
            port_i = int(port)
        except ValueError:
            continue
        if port_i in WEB_PORTS:
            scheme = "https" if port_i in {443, 8443, 9443} else "http"
            urls.append(f"{scheme}://{host}:{port_i}")
    Path(out_urls_file).write_text("\n".join(sorted(set(urls))) + ("\n" if urls else ""))
