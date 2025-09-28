PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS run (
  id            INTEGER PRIMARY KEY,
  run_id        TEXT NOT NULL,
  target        TEXT NOT NULL,
  run_path      TEXT NOT NULL,
  started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  finished_at   DATETIME,
  notes         TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_run_runid_target ON run(run_id, target);

CREATE TABLE IF NOT EXISTS subdomain (
  id        INTEGER PRIMARY KEY,
  run_id    INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  name      TEXT NOT NULL,
  UNIQUE(run_id, name)
);
CREATE INDEX IF NOT EXISTS ix_subdomain_name ON subdomain(name);

CREATE TABLE IF NOT EXISTS live_host (
  id        INTEGER PRIMARY KEY,
  run_id    INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  host      TEXT NOT NULL,
  UNIQUE(run_id, host)
);
CREATE INDEX IF NOT EXISTS ix_live_host_host ON live_host(host);

CREATE TABLE IF NOT EXISTS url (
  id        INTEGER PRIMARY KEY,
  run_id    INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  url       TEXT NOT NULL,
  scheme    TEXT,
  host      TEXT,
  path      TEXT,
  UNIQUE(run_id, url)
);
CREATE INDEX IF NOT EXISTS ix_url_host ON url(host);

CREATE TABLE IF NOT EXISTS httpx_row (
  id           INTEGER PRIMARY KEY,
  run_id       INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  url          TEXT NOT NULL,
  status_code  INTEGER,
  title        TEXT,
  tech         TEXT,
  meta         TEXT,
  UNIQUE(run_id, url)
);
CREATE INDEX IF NOT EXISTS ix_httpx_row_status ON httpx_row(status_code);

CREATE TABLE IF NOT EXISTS nuclei_finding (
  id            INTEGER PRIMARY KEY,
  run_id        INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  template_id   TEXT NOT NULL,
  severity      TEXT,
  matched_at    TEXT,
  host          TEXT,
  info          TEXT,
  UNIQUE(run_id, template_id, matched_at)
);
CREATE INDEX IF NOT EXISTS ix_nuclei_sev ON nuclei_finding(severity);
CREATE INDEX IF NOT EXISTS ix_nuclei_tpl ON nuclei_finding(template_id);

CREATE TABLE IF NOT EXISTS known_vuln (
  id          INTEGER PRIMARY KEY,
  run_id      INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  product     TEXT,
  version     TEXT,
  cve         TEXT,
  cvss        REAL,
  kev         INTEGER DEFAULT 0,
  summary     TEXT
);
CREATE INDEX IF NOT EXISTS ix_known_vuln_cve ON known_vuln(cve);

-- Full-text indexes (optional but handy)
CREATE VIRTUAL TABLE IF NOT EXISTS url_fts USING fts5(url, host, content='url', content_rowid='id');
CREATE VIRTUAL TABLE IF NOT EXISTS httpx_fts USING fts5(url, title, content='httpx_row', content_rowid='id');
