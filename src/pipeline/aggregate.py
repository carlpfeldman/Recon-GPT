# src/pipeline/aggregate.py
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Iterable, Dict, Any, List, Optional

RUNS_DIR = Path("data") / "runs"

def list_run_dirs() -> List[Path]:
    if not RUNS_DIR.exists():
        return []
    runs = [p for p in RUNS_DIR.iterdir() if p.is_dir()]
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return runs

def _load_jsonl(p: Path) -> Iterable[Dict[str, Any]]:
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except Exception:
                continue

def _norm(s: Optional[str]) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()

def _sig(rec: Dict[str, Any]) -> str:
    # signature to dedupe similar findings across runs
    host = _norm(rec.get("host") or rec.get("matched-at") or rec.get("url") or "")
    tid  = _norm(rec.get("template-id") or rec.get("templateID") or "")
    typ  = _norm(rec.get("type") or "")
    path = _norm(rec.get("matched-at") or rec.get("extracted-results") or "")
    return "|".join([host, tid, typ, path])

def gather_all_findings(
    severities: Optional[set[str]] = None,
    since_days: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Load and merge all nuclei.jsonl results across runs, with optional severity/time filters.
    """
    now = datetime.utcnow()
    min_ts = None
    if since_days and since_days > 0:
        min_ts = now - timedelta(days=since_days)

    seen = set()
    merged: List[Dict[str, Any]] = []

    for run in list_run_dirs():
        j = run / "nuclei.jsonl"
        for rec in _load_jsonl(j):
            sev = (rec.get("severity") or rec.get("info", {}).get("severity") or "").lower()
            if severities and sev and sev not in severities:
                continue
            if min_ts:
                ts = rec.get("timestamp") or rec.get("date") or ""
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
                        if dt < min_ts:
                            continue
                    except Exception:
                        pass
            sig = _sig(rec)
            if sig in seen:
                continue
            seen.add(sig)
            merged.append(rec)

    return merged
