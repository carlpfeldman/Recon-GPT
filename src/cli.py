from __future__ import annotations

import typer
from pathlib import Path
from datetime import datetime

from src.pipeline import enumerate as enum_mod
from src.pipeline import resolve, probe, scan, summarise

app = typer.Typer(help="Recon-GPT pipeline CLI")


def _validate_amass_mode(mode: str) -> str:
    m = (mode or "").strip().lower()
    if m not in {"passive", "active", "both"}:
        raise typer.BadParameter("amass-mode must be one of: passive, active, both")
    return m


@app.command()
def main(
    domain: str,
    run_id: str = typer.Option(None, "--run-id", help="Custom run ID"),
    # discovery toggles (future placeholders)
    katana_depth: int = typer.Option(0, "--katana-depth", help="Katana crawl depth (0=off)"),
    fast_discovery: bool = typer.Option(False, "--fast-discovery", help="Enable fast discovery mode (katana/gau)"),
    gau_enable: bool = typer.Option(False, "--gau-enable", help="Enable GAU for archived URLs"),
    do_ports: bool = typer.Option(False, "--do-ports", help="Run Naabu for port scanning"),
    do_tls: bool = typer.Option(False, "--do-tls", help="Expand via TLS certs"),
    do_screens: bool = typer.Option(False, "--do-screens", help="Run screenshots with gowitness"),
    do_takeovers: bool = typer.Option(False, "--do-takeovers", help="Check subdomain takeovers"),
    # httpx tuning
    httpx_threads: int = typer.Option(50, "--httpx-threads", help="httpx concurrency threads"),
    httpx_rate: int = typer.Option(100, "--httpx-rate", help="httpx rate limit (RPS)"),
    # nuclei tuning
    nuclei_concurrency: int = typer.Option(50, "--nuclei-concurrency", help="nuclei concurrency"),
    nuclei_rate: int = typer.Option(200, "--nuclei-rate", help="nuclei rate limit"),
    nuclei_severity: str = typer.Option("", "--nuclei-severity", help="Filter nuclei by severity (e.g. critical,high)"),
    nuclei_tags: str = typer.Option("", "--nuclei-tags", help="Filter nuclei by tags (e.g. cve,exposures)"),
    # seed URL
    force_url: str = typer.Option("", "--force-url", help="Force-add specific URL if discovery yields none"),
    # enumeration sources & options
    use_subfinder: bool = typer.Option(True, "--use-subfinder/--no-subfinder", help="Enable Subfinder enumeration"),
    use_amass: bool = typer.Option(False, "--use-amass/--no-amass", help="Enable Amass enumeration"),
    amass_mode: str = typer.Option("passive", "--amass-mode", help="Amass mode: passive, active, both"),
    write_attribution: bool = typer.Option(True, "--write-attribution/--no-write-attribution", help="Write sub_attribution.csv"),
):
    """
    Run a recon scan on a DOMAIN and save results into data/runs/<TIMESTAMP>_<DOMAIN>/
    """
    amass_mode = _validate_amass_mode(amass_mode)

    # 1) Prepare run dir
    ts = run_id or datetime.now().strftime("%Y-%m-%d_%H%M%S")
    safe_domain = domain.replace("/", "_")
    run_dir = Path("data") / "runs" / f"{ts}_{safe_domain}"
    run_dir.mkdir(parents=True, exist_ok=True)

    typer.echo(f"[+] Run directory: {run_dir}")

    # 2) Stage file paths
    sub_file = run_dir / f"{safe_domain}_subs.txt"          # final combined
    subfinder_out = run_dir / "subfinder.txt"               # raw per-tool
    amass_passive_out = run_dir / "amass_passive.txt"
    amass_active_out  = run_dir / "amass_active.txt"
    attr_csv = run_dir / "sub_attribution.csv"

    live_file = run_dir / f"{safe_domain}_live.txt"
    urls_file = run_dir / f"{safe_domain}_urls.txt"
    http_file = run_dir / f"{safe_domain}_http.jsonl"
    nuclei_file = run_dir / f"{safe_domain}_nuclei.jsonl"

    # 3) Enumeration
    named_inputs = []

    if use_subfinder:
        typer.echo(f"[+] Subfinder: {domain}")
        try:
            n = enum_mod.run_subfinder(domain, subfinder_out)
            typer.echo(f"[i] subfinder -> {n} unique subdomains")
            named_inputs.append(("subfinder", subfinder_out))
        except Exception as e:
            typer.echo(f"[warn] subfinder failed: {e}")

    if use_amass:
        if amass_mode in {"passive", "both"}:
            typer.echo(f"[+] Amass (passive): {domain}")
            try:
                n = enum_mod.run_amass(domain, amass_passive_out, passive=True)
                typer.echo(f"[i] amass(passive) -> {n} unique subdomains")
                named_inputs.append(("amass_passive", amass_passive_out))
            except Exception as e:
                typer.echo(f"[warn] amass passive failed: {e}")
        if amass_mode in {"active", "both"}:
            typer.echo(f"[+] Amass (active): {domain}")
            try:
                n = enum_mod.run_amass(domain, amass_active_out, passive=False)
                typer.echo(f"[i] amass(active) -> {n} unique subdomains")
                named_inputs.append(("amass_active", amass_active_out))
            except Exception as e:
                typer.echo(f"[warn] amass active failed: {e}")

    if not named_inputs:
        sub_file.write_text("", encoding="utf-8")
        if write_attribution:
            attr_csv.write_text("subdomain,sources\n", encoding="utf-8")
        typer.echo("[i] No enumeration sources enabled or they failed; continuing with empty subs.")
    else:
        if write_attribution:
            total = enum_mod.combine_subdomains_with_attribution(named_inputs, sub_file, attr_csv)
            typer.echo(f"[i] combined subdomains -> {total} unique (attribution written)")
        else:
            total = enum_mod.combine_subdomains([p for _, p in named_inputs], sub_file)
            typer.echo(f"[i] combined subdomains -> {total} unique")

    # 4) Resolve
    typer.echo("[+] DNSX: resolving hosts")
    try:
        resolve.run_dnsx(sub_file, live_file)
    except Exception as e:
        typer.echo(f"[warn] dnsx failed: {e}")

    # 5) Probe
    typer.echo("[+] HTTPX: probing")
    try:
        probe.run_httpx(live_file, http_file, urls_file,
                        threads=httpx_threads, rate=httpx_rate)
    except Exception as e:
        typer.echo(f"[warn] httpx failed: {e}")

    # 6) Scan (Nuclei)
    if urls_file.exists() and urls_file.stat().st_size > 0:
        typer.echo("[+] Nuclei: scanning")
        try:
            scan.run_nuclei(
                urls_file, nuclei_file,
                concurrency=nuclei_concurrency,
                rate=nuclei_rate,
                severity=nuclei_severity,
                tags=nuclei_tags
            )
        except Exception as e:
            typer.echo(f"[warn] nuclei failed: {e}")
    else:
        typer.echo("[i] No URLs to scan.")
        if force_url.strip():
            urls_file.write_text(force_url.strip() + "\n", encoding="utf-8")
            typer.echo(f"[i] Seeded URL from --force-url: {force_url.strip()}")
            try:
                scan.run_nuclei(
                    urls_file, nuclei_file,
                    concurrency=nuclei_concurrency,
                    rate=nuclei_rate,
                    severity=nuclei_severity,
                    tags=nuclei_tags
                )
            except Exception as e:
                typer.echo(f"[warn] nuclei failed after seeding: {e}")

    # 7) Summarise
    try:
        typer.echo("[+] Summarising results with GPT")
        summarise.run_summary(http_file, nuclei_file)
    except Exception as e:
        typer.echo(f"[warn] summary failed: {e}")


if __name__ == "__main__":
    app()
