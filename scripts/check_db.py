import sqlite3, pathlib

db_path = pathlib.Path("data/recon.db")
if not db_path.exists():
    print("❌ Database not found at", db_path)
    raise SystemExit(1)

con = sqlite3.connect(db_path)
print("✅ Database exists:", db_path.resolve())

tables = ["run", "subdomain", "live_host", "url", "httpx_row", "nuclei_finding", "known_vuln"]
for t in tables:
    try:
        count = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"{t}: {count}")
    except Exception as e:
        print(f"{t}: error ({e})")

con.close()
