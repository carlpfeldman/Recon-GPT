# src/db.py
from __future__ import annotations
import sqlite3, json
from pathlib import Path
from typing import Iterable, Any

DB_PATH = Path("data/recon.db")
SCHEMA_PATH = Path("src/schema.sql")

def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    return con

def init_schema():
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"Schema file not found: {SCHEMA_PATH}")
    con = connect()
    con.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    con.close()

def upsert_run(run_id: str, target: str, run_path: str) -> int:
    con = connect()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO run(run_id, target, run_path)
        VALUES(?, ?, ?)
        ON CONFLICT(run_id, target) DO UPDATE SET run_path=excluded.run_path
    """, (run_id, target, run_path))
    cur.execute("SELECT id FROM run WHERE run_id=? AND target=?", (run_id, target))
    rid = cur.fetchone()[0]
    con.close()
    return rid

def mark_finished(run_db_id: int):
    con = connect()
    con.execute("UPDATE run SET finished_at=CURRENT_TIMESTAMP WHERE id=?", (run_db_id,))
    con.close()

def bulk_insert(table: str, cols: Iterable[str], rows: Iterable[Iterable[Any]]):
    rows = list(rows)
    if not rows:
        return
    con = connect()
    ph = ",".join(["?"] * len(list(cols)))
    collist = ",".join(cols)
    sql = f"INSERT OR IGNORE INTO {table} ({collist}) VALUES ({ph})"
    con.executemany(sql, rows)
    con.close()

def index_urls_into_fts():
    con = connect()
    # Insert only new rows (skip existing rowids).
    con.execute("""
        INSERT INTO url_fts(rowid, url, host)
        SELECT id, url, host FROM url
        WHERE id NOT IN (SELECT rowid FROM url_fts)
    """)
    con.execute("""
        INSERT INTO httpx_fts(rowid, url, title)
        SELECT id, url, COALESCE(title,'') FROM httpx_row
        WHERE id NOT IN (SELECT rowid FROM httpx_fts)
    """)
    con.close()
