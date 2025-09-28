# src/pipeline/summarise.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Set, List, Dict, Any, Tuple
from datetime import datetime, timedelta

# Load .env so OPENAI_API_KEY is available
from dotenv import load_dotenv
load_dotenv()

from openai import OpenAI

# Reads OPENAI_API_KEY from environment
client = OpenAI()
DEFAULT_MODEL = "gpt-4o-mini"

# ----------------------------------------------------------------------
# Utilities for nuclei.jsonl loading / filtering / chunking
# ----------------------------------------------------------------------

def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return out
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                out.append(json.loads(s))
            except Exception:
                continue
    return out

def _filter(
    findings: List[Dict[str, Any]],
    include_medium: bool,
    severities: Optional[Set[str]],
) -> List[Dict[str, Any]]:
    res: List[Dict[str, Any]] = []
    for f in findings:
        sev = (f.get("severity") or f.get("info", {}).get("severity") or "").lower()
        if not include_medium and sev == "medium":
            continue
        if severities and sev and sev not in severities:
            continue
        res.append(f)
    return res

def _chunk_records(records: List[Dict[str, Any]], max_chars: int = 80000) -> List[str]:
    """
    Convert records to JSON lines and split into ~max_chars chunks.
    """
    chunks: List[str] = []
    cur: List[str] = []
    size = 0
    for r in records:
        s = json.dumps(r, ensure_ascii=False)
        if size + len(s) + 1 > max_chars and cur:
            chunks.append("\n".join(cur))
            cur = []
            size = 0
        cur.append(s)
        size += len(s) + 1
    if cur:
        chunks.append("\n".join(cur))
    return chunks

def _prompt_header(scope_label: str) -> str:
    return (
        "You are a security triage assistant. You will receive nuclei findings from "
        f"{scope_label} in JSONL chunks.\n"
        "Output a structured, concise action plan FIRST, then a vulnerability summary.\n\n"
        "Rules:\n"
        "- Prioritize by severity: critical, high, then medium/others.\n"
        "- Group similar issues across hosts.\n"
        "- Be specific: include host/URL examples and template-ids.\n"
        "- Recommend concrete next steps (patch, config, WAF rule, scope clarification).\n"
        "- Note false positive risk when relevant.\n"
        "- Keep total under ~800 words.\n\n"
        "Format:\n"
        "# Action Plan (Prioritized)\n"
        "1. <short action> — <why> — <evidence>\n\n"
        "# Vulnerability Summary\n"
        "- <class> — <hosts/examples> — <template-ids> — <severity>\n"
    )

def _llm_complete(text: str, model: str = DEFAULT_MODEL) -> str:
    resp = client.chat.completions.create(
        model=model,
        temperature=0.2,
        messages=[{"role": "user", "content": text}],
    )
    return resp.choices[0].message.content.strip()

def summarise_records(
    records: List[Dict[str, Any]],
    include_medium: bool = False,
    chars_per_chunk: int = 80000,
    model: str = DEFAULT_MODEL,
    scope_label: str = "the selected run",
) -> str:
    if not records:
        return "_No findings to summarise._"

    # Normalize severity and sort
    weights = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    def sev_weight(r: Dict[str, Any]) -> int:
        sev = (r.get("severity") or r.get("info", {}).get("severity") or "").lower()
        return weights.get(sev, 0)

    recs = sorted(records, key=sev_weight, reverse=True)
    if not include_medium:
        recs = [
            r for r in recs
            if (r.get("severity") or r.get("info", {}).get("severity") or "").lower()
               in {"critical", "high"}
        ]
    if not recs:
        return "_No findings after filters._"

    chunks = _chunk_records(recs, max_chars=chars_per_chunk)
    header = _prompt_header(scope_label)
    partials: List[str] = []
    total = len(chunks)
    for i, ch in enumerate(chunks, 1):
        prompt = f"{header}\n\n# Chunk {i}/{total}\n{ch}\n\nProduce the sections now."
        partials.append(_llm_complete(prompt, model=model))

    if len(partials) == 1:
        return partials[0]

    divider = "\n\n---\n"
    joined = divider.join(partials)
    final_prompt = (
        f"{_prompt_header(scope_label + ' (final synthesis)')}\n"
        f"You are given partial analyses from previous chunks (1..{len(partials)}).\n"
        "Combine them into a single Action Plan and Vulnerability Summary without duplication.\n\n"
        f"PARTIALS:\n{joined}\n"
    )
    return _llm_complete(final_prompt, model=model)

# ----------------------------------------------------------------------
# Public: nuclei-only summary and all-runs summary
# ----------------------------------------------------------------------

def summarise(
    findings_file: str,
    include_medium: bool = False,
    chars_per_chunk: int = 80000,
    severities: Optional[Set[str]] = None,
) -> str:
    """Summarise a single nuclei.jsonl findings file."""
    records = _load_jsonl(findings_file)
    records = _filter(records, include_medium=include_medium, severities=severities)
    return summarise_records(
        records,
        include_medium=include_medium,
        chars_per_chunk=chars_per_chunk,
        scope_label="this run",
    )

def _fallback_gather_all_findings(
    runs_root: Path,
    severities: Optional[Set[str]],
    since_days: Optional[int],
) -> List[Dict[str, Any]]:
    """
    Fallback walker if src/pipeline/aggregate.py is not available.
    Collects all nuclei.jsonl from data/runs with optional time and severity filters.
    """
    cutoff = None
    if since_days and since_days > 0:
        cutoff = datetime.now() - timedelta(days=since_days)

    all_recs: List[Dict[str, Any]] = []
    if not runs_root.exists():
        return all_recs

    for run_dir in runs_root.iterdir():
        if not run_dir.is_dir():
            continue
        if cutoff and datetime.fromtimestamp(run_dir.stat().st_mtime) < cutoff:
            continue
        nuc = run_dir / "nuclei.jsonl"
        if not nuc.exists():
            continue
        recs = _load_jsonl(str(nuc))
        for r in recs:
            sev = (r.get("severity") or r.get("info", {}).get("severity") or "").lower()
            if severities and sev and sev not in severities:
                continue
            all_recs.append(r)
    return all_recs

def summarise_all_runs(
    severities: Optional[Set[str]] = None,
    since_days: Optional[int] = None,
    include_medium: bool = False,
    chars_per_chunk: int = 80000,
    model: str = DEFAULT_MODEL,
) -> str:
    """
    Aggregate nuclei findings across all runs and summarise.
    Tries src.pipeline.aggregate.gather_all_findings; falls back to local walker.
    """
    try:
        from .aggregate import gather_all_findings  # type: ignore
        recs = gather_all_findings(severities=severities, since_days=since_days)
    except Exception:
        runs_root = Path("data") / "runs"
        recs = _fallback_gather_all_findings(runs_root, severities, since_days)

    return summarise_records(
        recs,
        include_medium=include_medium,
        chars_per_chunk=chars_per_chunk,
        model=model,
        scope_label="all runs",
    )

# ----------------------------------------------------------------------
# Full-run summary: subs/live/urls/http/nuclei (even when empty)
# ----------------------------------------------------------------------

def _read_text_file(p: Path, max_lines: int = 5000) -> Tuple[str, int]:
    if not p.exists() or p.stat().st_size == 0:
        return "", 0
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        total = len(lines)
        if len(lines) > max_lines:
            lines = lines[:max_lines]
        return "\n".join(lines), total
    except Exception:
        return "", 0

def _read_jsonl_file(p: Path, max_rows: int = 10000) -> Tuple[str, int]:
    if not p.exists() or p.stat().st_size == 0:
        return "", 0
    rows: List[str] = []
    total = 0
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for _, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            total += 1
            if len(rows) < max_rows:
                rows.append(s)
    return "\n".join(rows), total

def _compose_full_context(run_dir: str) -> str:
    """
    Build a structured context from all run artifacts in run_dir.
    """
    rd = Path(run_dir)
    subs_txt  = rd / "subs.txt"
    live_txt  = rd / "live.txt"
    urls_txt  = rd / "urls.txt"
    http_json = rd / "http.jsonl"
    nuc_jsonl = rd / "nuclei.jsonl"

    subs_body, subs_total = _read_text_file(subs_txt)
    live_body, live_total = _read_text_file(live_txt)
    urls_body, urls_total = _read_text_file(urls_txt)
    http_body, http_total = _read_jsonl_file(http_json)
    nuc_body, nuc_total   = _read_jsonl_file(nuc_jsonl)

    def section(title: str, body: str, total_hint: int) -> str:
        if total_hint == 0:
            return f"## {title}\nNone.\n"
        return f"## {title} (total ~{total_hint})\n{body}\n"

    parts = [
        f"# Recon Artifacts\n(run directory: {rd.name})\n",
        section("Subdomains (subs.txt)", subs_body, subs_total),
        section("Resolved hosts (live.txt)", live_body, live_total),
        section("Discovered URLs (urls.txt)", urls_body, urls_total),
        section("HTTP probe results (http.jsonl JSONL)", http_body, http_total),
        section("Vulnerability findings (nuclei.jsonl JSONL)", nuc_body, nuc_total),
    ]
    return "\n".join(parts)

_FULL_RUN_SYSTEM_PROMPT = (
    "You are a security recon analyst. You will receive a full run context combining:\n"
    "- Subdomains\n- Resolved hosts\n- Discovered URLs\n- HTTP probe JSONL rows\n- Nuclei JSONL findings (if any)\n\n"
    "Output a concise, actionable report even if many sections are empty.\n"
    "Rules:\n"
    "- Start with a one-paragraph high-level assessment (is target active? attack surface? confidence).\n"
    "- Then an Action Plan (prioritized). Be specific with examples (hosts/URLs) when available.\n"
    "- Then a Recon Summary section listing counts per artifact and notable gaps (e.g., 'no subdomains').\n"
    "- If nuclei is empty, explicitly state 'No known vulnerabilities detected in this run.'\n"
    "- Keep the whole answer under ~800 words."
)

def summarise_full_run(
    run_dir: str,
    model: str = DEFAULT_MODEL,
    chars_per_chunk: int = 90000,
) -> str:
    """
    Summarise the ENTIRE run directory (subs/live/urls/http/nuclei).
    Safe when files are empty; uses chunking for large runs.
    """
    context = _compose_full_context(run_dir)

    # Chunk by paragraph boundaries to respect token limits
    chunks: List[str] = []
    cur: List[str] = []
    size = 0
    for para in context.split("\n\n"):
        s = para
        if size + len(s) + 2 > chars_per_chunk and cur:
            chunks.append("\n\n".join(cur))
            cur = []
            size = 0
        cur.append(s)
        size += len(s) + 2
    if cur:
        chunks.append("\n\n".join(cur))

    if len(chunks) == 1:
        prompt = (
            f"{_FULL_RUN_SYSTEM_PROMPT}\n\n"
            f"# CONTEXT\n{chunks[0]}\n\n"
            "# TASK\nProduce the report now."
        )
        return _llm_complete(prompt, model=model)

    # Multi-chunk: summarise each, then synthesize
    partials: List[str] = []
    total = len(chunks)
    for i, ch in enumerate(chunks, 1):
        prompt = (
            f"{_FULL_RUN_SYSTEM_PROMPT}\n\n"
            f"# CONTEXT CHUNK {i}/{total}\n{ch}\n\n"
            "# TASK\nSummarise this chunk into the final sections."
        )
        partials.append(_llm_complete(prompt, model=model))

    divider = "\n\n---\n"
    joined = divider.join(partials)
    final_prompt = (
        f"{_FULL_RUN_SYSTEM_PROMPT}\n\n"
        "You will receive partial analyses from previous chunks. "
        "Merge them into ONE coherent report without duplication.\n\n"
        f"PARTIALS:\n{joined}\n"
    )
    return _llm_complete(final_prompt, model=model)
