# src/pipeline/delta.py
from __future__ import annotations
import hashlib, json, sqlite3, time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple, Optional

DB_PATH = Path("data") / "seen.sqlite"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def _conn():
    return sqlite3.connect(str(DB_PATH))

def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS targets (
            domain TEXT PRIMARY KEY,
            interval_minutes INTEGER NOT NULL DEFAULT 60,
            last_run_at INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1
        );""")
        c.execute("""CREATE TABLE IF NOT EXISTS seen (
            typ TEXT NOT NULL,            -- 'subdomain' | 'url' | 'finding'
            key TEXT NOT NULL,            -- unique key (string or hash)
            first_seen_at INTEGER NOT NULL,
            PRIMARY KEY (typ, key)
        );""")
        c.execute("""CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            finished_at INTEGER
        );""")

def upsert_target(domain: str, interval_minutes: int = 60, enabled: bool = True):
    with _conn() as c:
        c.execute("""INSERT INTO targets(domain, interval_minutes, last_run_at, enabled)
                     VALUES(?,?,0,?)
                     ON CONFLICT(domain) DO UPDATE SET
                       interval_minutes=excluded.interval_minutes,
                       enabled=excluded.enabled;""",
                  (domain, interval_minutes, 1 if enabled else 0))

def list_due_targets(now_ts: int) -> List[Tuple[str, int, int]]:
    """return [(domain, interval_minutes, last_run_at)] that are due now."""
    with _conn() as c:
        rows = c.execute("SELECT domain, interval_minutes, last_run_at FROM targets WHERE enabled=1;").fetchall()
    due = []
    for d, interval, last in rows:
        if now_ts - last >= interval * 60:
            due.append((d, interval, last))
    return due

def mark_run(domain: str, run_id: str, started_at: int, finished_at: Optional[int] = None):
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO runs(run_id, domain, started_at, finished_at) VALUES(?,?,?,?);",
                  (run_id, domain, started_at, finished_at))
        if finished_at:
            c.execute("UPDATE targets SET last_run_at=? WHERE domain=?;", (finished_at, domain))

def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def diff_new(typ: str, items: Iterable[str]) -> List[str]:
    """Return only items not yet in 'seen', and record them as seen."""
    items = [i.strip() for i in items if i and i.strip()]
    now = int(time.time())
    new_items = []
    with _conn() as c:
        for it in items:
            key = it if typ != "finding" else _h(it)
            row = c.execute("SELECT 1 FROM seen WHERE typ=? AND key=?;", (typ, key)).fetchone()
            if row:
                continue
            new_items.append(it)
            c.execute("INSERT OR IGNORE INTO seen(typ, key, first_seen_at) VALUES(?,?,?);", (typ, key, now))
    return new_items

# Helpers to load artifacts from a run dir
def read_lines(path: Path, max_lines: int = 100000) -> List[str]:
    if not path.exists(): return []
    out = []
    for i, line in enumerate(path.open("r", encoding="utf-8", errors="ignore")):
        if i >= max_lines: break
        s = line.strip()
        if s: out.append(s)
    return out

def findings_keys(nuclei_jsonl: Path, max_rows: int = 50000) -> List[str]:
    """Return stable keys for findings (template-id + matched-at)."""
    if not nuclei_jsonl.exists(): return []
    out = []
    with nuclei_jsonl.open("r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_rows: break
            s = line.strip()
            if not s: continue
            try:
                obj = json.loads(s)
                tid = obj.get("template-id") or obj.get("info", {}).get("id") or ""
                mat = obj.get("matched-at") or obj.get("host") or obj.get("url") or ""
                if tid and mat:
                    out.append(f"{tid}::{mat}")
            except Exception:
                continue
    return out
