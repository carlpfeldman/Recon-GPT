# src/store/db.py
import json, sqlite3, hashlib, time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, created_ts INTEGER, target TEXT
);
CREATE TABLE IF NOT EXISTS subs (
  run_id TEXT, host TEXT, PRIMARY KEY (run_id, host)
);
CREATE TABLE IF NOT EXISTS http (
  run_id TEXT, url TEXT, status INTEGER, title TEXT, techs TEXT, raw JSON,
  PRIMARY KEY (run_id, url)
);
CREATE TABLE IF NOT EXISTS nuclei (
  run_id TEXT, id TEXT, url TEXT, template TEXT, severity TEXT, name TEXT, matcher TEXT, raw JSON,
  PRIMARY KEY (run_id, id)
);
"""

def _conn(db_path: str):
  Path(db_path).parent.mkdir(parents=True, exist_ok=True)
  con = sqlite3.connect(db_path)
  con.execute("PRAGMA foreign_keys=ON;")
  return con

def init_db(db_path: str, run_id: str, target: str):
  con = _conn(db_path)
  with con:
    con.executescript(SCHEMA)
    con.execute("INSERT OR IGNORE INTO runs(id, created_ts, target) VALUES(?,?,?)",
                (run_id, int(time.time()), target))
  return con

def ingest_subs(con, run_id: str, subs_file: str):
  rows = []
  for line in Path(subs_file).read_text().splitlines():
    h = line.strip()
    if h: rows.append((run_id, h))
  with con:
    con.executemany("INSERT OR IGNORE INTO subs(run_id,host) VALUES(?,?)", rows)

def ingest_http(con, run_id: str, http_jsonl: str):
  rows = []
  for line in Path(http_jsonl).read_text().splitlines():
    try:
      obj = json.loads(line)
    except Exception:
      continue
    url = obj.get("url")
    status = obj.get("status_code") or obj.get("status") or None
    title = obj.get("title") or ""
    techs = ",".join(obj.get("tech", []) if isinstance(obj.get("tech"), list) else [])
    rows.append((run_id, url, status, title, techs, json.dumps(obj)))
  with con:
    con.executemany("""INSERT OR REPLACE INTO http(run_id,url,status,title,techs,raw)
                       VALUES(?,?,?,?,?,?)""", rows)

def _nid(rec):
  # stable id for nuclei record
  s = f"{rec.get('template-id','')}|{rec.get('matched-at','')}"
  return hashlib.sha1(s.encode()).hexdigest()[:16]

def ingest_nuclei(con, run_id: str, nuclei_jsonl: str):
  if not Path(nuclei_jsonl).exists(): return
  rows = []
  text = Path(nuclei_jsonl).read_text()
  if not text.strip():
    return
  # file might be JSONL or JSON array depending on flags
  lines = []
  try:
    # try JSON array
    arr = json.loads(text)
    if isinstance(arr, list):
      lines = [json.dumps(x) for x in arr]
  except Exception:
    lines = text.splitlines()
  for line in lines:
    try:
      obj = json.loads(line)
    except Exception:
      continue
    url = obj.get("matched-at") or obj.get("host") or ""
    tpl = obj.get("template-id") or obj.get("template") or ""
    sev = obj.get("severity") or ""
    name = obj.get("info", {}).get("name", "")
    matcher = obj.get("matcher-name") or obj.get("matcher") or ""
    rid = _nid(obj)
    rows.append((run_id, rid, url, tpl, sev, name, matcher, json.dumps(obj)))
  if rows:
    with con:
      con.executemany("""INSERT OR REPLACE INTO nuclei(run_id,id,url,template,severity,name,matcher,raw)
                         VALUES(?,?,?,?,?,?,?,?)""", rows)
