# scripts/backfill_runs_to_db.py
from pathlib import Path
from urllib.parse import urlparse
import json
from src import db as odb

ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "data" / "runs"

def target_from_folder(name: str) -> str:
    # <YYYY-mm-dd_HHMMSS>_<target>
    parts = name.split("_", 2)
    return parts[2] if len(parts) >= 3 else name

def main():
    odb.init_schema()
    for rd in sorted(RUNS_DIR.iterdir()):
        if not rd.is_dir(): 
            continue
        parts = rd.name.split("_", 2)
        if len(parts) < 2:
            continue
        run_id = "_".join(parts[:2])
        target = target_from_folder(rd.name)
        run_db_id = odb.upsert_run(run_id, target, str(rd))

        # subs
        p = rd / "subs.txt"
        if p.exists():
            subs = [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
            odb.bulk_insert("subdomain", ["run_id","name"], ((run_db_id, s) for s in subs))

        # live
        p = rd / "live.txt"
        if p.exists():
            live = [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
            odb.bulk_insert("live_host", ["run_id","host"], ((run_db_id, h) for h in live))

        # urls
        p = rd / "urls.txt"
        if p.exists():
            rows=[]
            for u in p.read_text(encoding="utf-8").splitlines():
                u=u.strip()
                if not u: 
                    continue
                pr=urlparse(u)
                rows.append((run_db_id, u, pr.scheme, pr.netloc, pr.path))
            odb.bulk_insert("url", ["run_id","url","scheme","host","path"], rows)

        # http.jsonl
        p = rd / "http.jsonl"
        if p.exists():
            rows=[]
            for line in p.open("r", encoding="utf-8", errors="ignore"):
                try: obj=json.loads(line)
                except Exception: continue
                url = obj.get("url") or obj.get("input") or ""
                rows.append((run_db_id, url, obj.get("status-code"), obj.get("title"),
                             json.dumps(obj.get("tech")) if obj.get("tech") is not None else None,
                             json.dumps(obj)))
            odb.bulk_insert("httpx_row", ["run_id","url","status_code","title","tech","meta"], rows)

        # nuclei.jsonl
        p = rd / "nuclei.jsonl"
        if p.exists():
            rows=[]
            for line in p.open("r", encoding="utf-8", errors="ignore"):
                try: obj=json.loads(line)
                except Exception: continue
                info = obj.get("info") or {}
                rows.append((run_db_id, obj.get("template-id") or "",
                             (info.get("severity") or obj.get("severity") or "").lower(),
                             obj.get("matched-at") or "", obj.get("host") or "", json.dumps(info)))
            odb.bulk_insert("nuclei_finding", ["run_id","template_id","severity","matched_at","host","info"], rows)

        # known_vulns.json (optional)
        p = rd / "known_vulns.json"
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            rows=[]
            for item in data.get("results", []):
                comp=item.get("component",{})
                for v in item.get("nvd", []):
                    rows.append((run_db_id, comp.get("product"), comp.get("version"),
                                 v.get("cve"), v.get("cvss"), 1 if v.get("kev") else 0, v.get("summary","")))
            odb.bulk_insert("known_vuln", ["run_id","product","version","cve","cvss","kev","summary"], rows)

        odb.index_urls_into_fts()
        odb.mark_finished(run_db_id)

if __name__ == "__main__":
    main()
