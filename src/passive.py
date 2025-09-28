# src/passive.py
from __future__ import annotations

import os
import re
import shlex
import json
import time
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any

from dotenv import load_dotenv

# Load OPENAI_API_KEY / SLACK_WEBHOOK_URL / NVD_API_KEY from .env
load_dotenv()

# Delta tracker (SQLite)
from src.pipeline.delta import (
    init_db, upsert_target, list_due_targets, mark_run,
    read_lines, findings_keys, diff_new,
)

# Enrichment (NVD + CISA KEV)
from src.pipeline.enrich import enrich_run_with_known_vulns, update_kev_cache

ROOT = Path(__file__).resolve().parents[1]       # project root
RUNS_DIR = ROOT / "data" / "runs"
DATA_DIR = ROOT / "data"
TARGETS_FILE = DATA_DIR / "targets.txt"          # simple text config
LOGS_DIR = ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

KEV_STAMP = DATA_DIR / "kev.last_refresh"        # when we last refreshed KEV cache

# ---------- helpers ----------

def normalize_target(target: str) -> str:
    t = target.strip()
    if "://" in t:
        from urllib.parse import urlparse
        host = urlparse(t).netloc
    else:
        host = re.sub(r"^(?i:https?)://", "", t)
        host = host.split("/")[0]
    return host.strip("/")

def safe_name(s: str) -> str:
    s = s.replace("https://", "").replace("http://", "")
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)

def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H%M%S")

def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def _append(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(text)

def _slurp(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return default

# ---------- targets config ----------

def load_targets_from_file(path: Path) -> List[Tuple[str, int]]:
    """
    Read 'data/targets.txt' lines:
      domain[,interval_minutes]
    Examples:
      example.com
      https://hackerone.com,30
    Default interval = 60 minutes.
    """
    out: List[Tuple[str, int]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split(",")]
        dom = parts[0]
        interval = 60
        if len(parts) > 1 and parts[1].isdigit():
            interval = int(parts[1])
        out.append((dom, interval))
    return out

# ---------- CLI runner ----------

def build_cli_cmd(target: str, run_id: str) -> List[str]:
    """
    Build the CLI command for a single scan.
    Tweak defaults here (nuclei tags/severity, httpx rates, etc.).
    """
    return [
        os.environ.get("PYTHON", str(Path(os.sys.executable))), "-m", "src.cli", "run", target,
        "--run-id", run_id,
        "--httpx-threads", "50",
        "--httpx-rate", "120",
        "--nuclei-concurrency", "60",
        "--nuclei-rate", "250",
        "--nuclei-severity", "critical,high",
        # Optional: uncomment to focus on CVEs
        # "--nuclei-tags", "cve",
    ]

def run_scan_and_collect(target: str) -> Tuple[Optional[Path], str]:
    """
    Trigger one scan for target via CLI, return (run_dir, stdout_log).
    """
    run_id = _ts()
    host_token = safe_name(normalize_target(target))
    run_dir = RUNS_DIR / f"{run_id}_{host_token}"
    run_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_cli_cmd(target, run_id)
    cmd_str = shlex.join(cmd)
    log_path = run_dir / "cli.log"
    _write(log_path, f"$ {cmd_str}\n\n")

    env = os.environ.copy()
    # Ensure PD binaries are on PATH when launched headless
    env["PATH"] = env.get("PATH", "") + os.pathsep + "/opt/homebrew/bin:/usr/local/bin"

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            env=env,
        )
        _append(log_path, proc.stdout or "")
        if proc.stderr:
            _append(log_path, f"\n[stderr]\n{proc.stderr}")
        return run_dir, (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
    except Exception as e:
        _append(log_path, f"\n[error]\n{e}\n")
        return run_dir, f"[error] {e}"

# ---------- deltas & notifications ----------

def compute_and_save_deltas(run_dir: Path) -> dict:
    """
    Compare artifacts against SQLite 'seen' store.
    Returns a dict with lists of new items per type.
    """
    subs_file  = run_dir / "subs.txt"
    live_file  = run_dir / "live.txt"
    urls_file  = run_dir / "urls.txt"
    nuclei_jl  = run_dir / "nuclei.jsonl"

    subs = read_lines(subs_file)
    live = read_lines(live_file)
    urls = read_lines(urls_file)
    findings = findings_keys(nuclei_jl)

    new_subs = diff_new("subdomain", subs)
    new_urls = diff_new("url", urls)
    new_find = diff_new("finding", findings)

    deltas = {
        "run": run_dir.name,
        "new_subdomains": new_subs,
        "new_urls": new_urls,
        "new_findings": new_find,
        "counts": {
            "subs": len(subs),
            "live": len(live),
            "urls": len(urls),
            "findings": len(findings),
        },
    }
    _write(run_dir / "deltas.json", json.dumps(deltas, indent=2))
    # Human-readable
    lines = []
    lines.append(f"# Deltas for {run_dir.name}")
    lines.append(f"- New subdomains: {len(new_subs)}")
    lines.append(f"- New URLs: {len(new_urls)}")
    lines.append(f"- New findings: {len(new_find)}")
    if new_subs:
        lines.append("\n## New subdomains")
        lines.extend(new_subs)
    if new_urls:
        lines.append("\n## New URLs")
        lines.extend(new_urls)
    if new_find:
        lines.append("\n## New findings (template-id::matched-at keys)")
        lines.extend(new_find)
    _write(run_dir / "deltas.md", "\n".join(lines) + "\n")
    return deltas

def _count_known_vulns(known_vulns_path: Path) -> Dict[str, Any]:
    """
    Return counts: total NVD CVEs, KEV-marked CVEs, unique components.
    """
    if not known_vulns_path.exists():
        return {"components": 0, "nvd_cves": 0, "kev_cves": 0}
    try:
        data = json.loads(known_vulns_path.read_text(encoding="utf-8"))
        comps = 0
        nvd_total = 0
        kev_total = 0
        for item in data.get("results", []):
            comps += 1
            for v in item.get("nvd", []):
                nvd_total += 1
                if v.get("kev"):
                    kev_total += 1
        return {"components": comps, "nvd_cves": nvd_total, "kev_cves": kev_total}
    except Exception:
        return {"components": 0, "nvd_cves": 0, "kev_cves": 0}

def maybe_slack_notify(payload: dict):
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return
    import requests
    try:
        requests.post(webhook, json=payload, timeout=10)
    except Exception:
        pass

def notify_run_summary(deltas: dict, enrich_counts: Dict[str, Any]):
    total_new = len(deltas["new_subdomains"]) + len(deltas["new_urls"]) + len(deltas["new_findings"])
    kev = enrich_counts.get("kev_cves", 0)
    nvd = enrich_counts.get("nvd_cves", 0)
    if total_new == 0 and nvd == 0:
        return
    text_lines = [
        f"*Recon Passive Update*: `{deltas['run']}`",
        f"• New subdomains: {len(deltas['new_subdomains'])}",
        f"• New URLs: {len(deltas['new_urls'])}",
        f"• New findings: {len(deltas['new_findings'])}",
        f"• Enrichment (NVD CVEs: {nvd}, KEV: {kev})",
    ]
    maybe_slack_notify({"text": "\n".join(text_lines)})

# ---------- KEV refresh policy ----------

def maybe_refresh_kev_daily(verbose: bool = True) -> bool:
    """
    Refresh KEV cache at most once per day. Returns True if refreshed now.
    """
    now = datetime.utcnow()
    try:
        if KEV_STAMP.exists():
            last = datetime.fromtimestamp(KEV_STAMP.stat().st_mtime)
            if now - last < timedelta(days=1):
                return False
        update_kev_cache()
        KEV_STAMP.parent.mkdir(parents=True, exist_ok=True)
        KEV_STAMP.write_text(now.isoformat() + "Z", encoding="utf-8")
        if verbose:
            print("[i] KEV cache refreshed.")
        return True
    except Exception as e:
        if verbose:
            print(f"[warn] KEV refresh failed: {e}")
        return False

# ---------- one passive cycle ----------

def one_cycle(verbose: bool = True) -> int:
    """
    Single passive cycle:
      - sync targets from targets.txt into DB
      - pick due targets
      - run CLI per target
      - compute deltas (new subs/urls/findings)
      - run enrichment (NVD + KEV) and include in notification
      - update 'last_run_at'
    Returns number of targets processed.
    """
    init_db()

    # sync targets file into DB (idempotent)
    targets = load_targets_from_file(TARGETS_FILE)
    for dom, minutes in targets:
        upsert_target(dom, interval_minutes=minutes, enabled=True)

    # refresh KEV if needed (once/day)
    refreshed = maybe_refresh_kev_daily(verbose=verbose)
    if verbose and not refreshed:
        print("[i] KEV cache is fresh (skip refresh).")

    now = int(time.time())
    due = list_due_targets(now)

    if verbose:
        print(f"[i] {len(due)} target(s) due.")

    processed = 0
    for domain, interval, last in due:
        processed += 1
        run_id = _ts()
        mark_run(domain, run_id, started_at=now, finished_at=None)
        if verbose:
            print(f"[+] Running {domain} (interval={interval}m, last={last})")

        # 1) full scan via CLI
        run_dir, _ = run_scan_and_collect(domain)

        # 2) deltas
        deltas = compute_and_save_deltas(run_dir)

        # 3) enrichment (NVD + KEV)
        try:
            out_path = enrich_run_with_known_vulns(
                str(run_dir),
                nvd_api_key=os.getenv("NVD_API_KEY"),
                refresh_kev=False  # daily refresh handled above
            )
            enrich_counts = _count_known_vulns(out_path)
        except Exception as e:
            if verbose:
                print(f"[warn] Enrichment failed: {e}")
            enrich_counts = {"components": 0, "nvd_cves": 0, "kev_cves": 0}

        # 4) notify (Slack) if anything interesting
        notify_run_summary(deltas, enrich_counts)

        # 5) mark finished
        mark_run(domain, run_id, started_at=now, finished_at=int(time.time()))
        if verbose:
            print(
                f"[✓] Finished {domain} → {run_dir.name} "
                f"(new: subs={len(deltas['new_subdomains'])}, urls={len(deltas['new_urls'])}, "
                f"findings={len(deltas['new_findings'])}; "
                f"enrich: NVD={enrich_counts.get('nvd_cves',0)}, KEV={enrich_counts.get('kev_cves',0)})"
            )

    return processed

if __name__ == "__main__":
    count = one_cycle(verbose=True)
    if count == 0:
        print("[i] No targets due; nothing to do.")
