# app.py — Recon + GPT Dashboard (DB-backed charts, enrichment, attribution)
import os, sys, shlex, json, re, subprocess, sqlite3, csv as _csv
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as _patches
from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent
RUNS_DIR = ROOT / "data" / "runs"
REPORTS_DIR = ROOT / "reports"
DB_PATH = ROOT / "data" / "recon.db"

# ================= Utilities =================

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

def list_runs() -> List[Path]:
    if not RUNS_DIR.exists(): return []
    runs = [p for p in RUNS_DIR.iterdir() if p.is_dir()]
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return runs

def tail_text(path: Path, n=2000) -> str:
    if not path.exists(): return ""
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
        return "\n".join(txt.splitlines()[-n:])
    except Exception as e:
        return f"(error reading {path}: {e})"

def jsonl_to_df(path: Path, max_rows: int = 10000) -> pd.DataFrame:
    rows = []
    if not path.exists(): return pd.DataFrame()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_rows: break
            s = line.strip()
            if not s: continue
            try: rows.append(json.loads(s))
            except Exception: pass
    return pd.DataFrame(rows) if rows else pd.DataFrame()

def count_lines(p: Path) -> int:
    if not p.exists(): return 0
    try: return sum(1 for _ in p.open("r", encoding="utf-8", errors="ignore"))
    except Exception: return 0

def human_dt(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# ============== CLI bridge ==============

def build_cmd(target: str, run_id: str, katana_depth: int, fast_discovery: bool, gau_enable: bool,
              do_ports: bool, do_tls: bool, do_screens: bool, do_takeovers: bool,
              httpx_threads: int, httpx_rate: int, nuclei_conc: int, nuclei_rate: int,
              nuclei_sev: str, nuclei_tags: str, force_url: str,
              use_subfinder: bool, use_amass: bool, amass_mode: str, write_attrib: bool):
    # IMPORTANT: matches python -m src.cli [OPTIONS] DOMAIN (no "run" subcommand)
    args = [sys.executable, "-m", "src.cli", target,
            "--run-id", run_id, "--katana-depth", str(katana_depth),
            "--httpx-threads", str(httpx_threads), "--httpx-rate", str(httpx_rate),
            "--nuclei-concurrency", str(nuclei_conc), "--nuclei-rate", str(nuclei_rate)]
    if fast_discovery: args += ["--fast-discovery"]
    if gau_enable: args += ["--gau-enable"]
    if do_ports: args += ["--do-ports"]
    if do_tls: args += ["--do-tls"]
    if do_screens: args += ["--do-screens"]
    if do_takeovers: args += ["--do-takeovers"]
    if nuclei_sev.strip(): args += ["--nuclei-severity", nuclei_sev.strip()]
    if nuclei_tags.strip(): args += ["--nuclei-tags", nuclei_tags.strip()]
    if force_url.strip(): args += ["--force-url", force_url.strip()]
    # enumeration toggles
    if use_subfinder:
        args += ["--use-subfinder"]
    else:
        args += ["--no-subfinder"]
    if use_amass:
        args += ["--use-amass", "--amass-mode", (amass_mode or "passive")]
    else:
        args += ["--no-amass"]
    if write_attrib:
        args += ["--write-attribution"]
    else:
        args += ["--no-write-attribution"]
    return args

def stream_process(cmd, cwd: Path):
    proc = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, universal_newlines=True, env=os.environ.copy())
    try:
        for line in proc.stdout:
            yield line.rstrip("\n")
    finally:
        try: proc.stdout.close()
        except Exception: pass
        proc.wait()

# ============== Attribution helpers ==============

def load_attribution(run_dir: Path) -> Tuple[Dict[str, set], Dict[str, int]]:
    """
    Reads run_dir/sub_attribution.csv -> (sourcesets, counts)
    sourcesets: dict[source_name] -> set(subdomains)
    counts:     dict[source_name] -> int
    """
    csv_path = run_dir / "sub_attribution.csv"
    if not csv_path.exists():
        return {}, {}
    sourcesets: Dict[str, set] = {}
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            sub = (row.get("subdomain") or "").strip()
            sources = (row.get("sources") or "").strip()
            if not sub or not sources:
                continue
            for s in sources.split(";"):
                s = s.strip()
                if not s:
                    continue
                sourcesets.setdefault(s, set()).add(sub)
    counts = {k: len(v) for k, v in sourcesets.items()}
    return sourcesets, counts

def draw_overlap_venn(sourcesets: Dict[str, set]):
    """
    Draws a simple 2- or 3-set 'Venn style' overlap using plain matplotlib.
    Supports keys: subfinder, amass_passive, amass_active (if present).
    """
    keys = [k for k in ["subfinder", "amass_passive", "amass_active"] if k in sourcesets and sourcesets[k]]
    if len(keys) < 2:
        st.info("Need at least two sources with results to draw overlaps.")
        return

    A = sourcesets[keys[0]]
    B = sourcesets[keys[1]]
    C = sourcesets[keys[2]] if len(keys) >= 3 else None

    fig = plt.figure()
    ax = plt.gca()
    ax.set_aspect("equal")
    ax.axis("off")

    if C is None:
        onlyA = len(A - B)
        onlyB = len(B - A)
        both = len(A & B)

        circA = _patches.Circle((0.0, 0.0), 1.2, fill=False, linewidth=2)
        circB = _patches.Circle((1.2, 0.0), 1.2, fill=False, linewidth=2)
        ax.add_patch(circA); ax.add_patch(circB)

        ax.text(-0.1, 0.0, f"{keys[0]}\nonly: {onlyA}", ha="center", va="center")
        ax.text(1.3, 0.0, f"{keys[1]}\nonly: {onlyB}", ha="center", va="center")
        ax.text(0.6, 0.0, f"overlap:\n{both}", ha="center", va="center", fontweight="bold")
        st.pyplot(fig)
        st.caption(f"{keys[0]} only: {onlyA} • overlap: {both} • {keys[1]} only: {onlyB}")
        return

    onlyA = len(A - B - C)
    onlyB = len(B - A - C)
    onlyC = len(C - A - B)
    AB = len((A & B) - C)
    AC = len((A & C) - B)
    BC = len((B & C) - A)
    ABC = len(A & B & C)

    circA = _patches.Circle((0.0, 0.0), 1.4, fill=False, linewidth=2)
    circB = _patches.Circle((1.4, 0.0), 1.4, fill=False, linewidth=2)
    circC = _patches.Circle((0.7, 1.2), 1.4, fill=False, linewidth=2)
    ax.add_patch(circA); ax.add_patch(circB); ax.add_patch(circC)

    ax.text(-0.6, -0.1, f"{keys[0]}\nonly: {onlyA}", ha="center", va="center")
    ax.text(2.0, -0.1, f"{keys[1]}\nonly: {onlyB}", ha="center", va="center")
    ax.text(0.7, 2.0, f"{keys[2]}\nonly: {onlyC}", ha="center", va="center")

    ax.text(0.7, -0.3, f"{AB}", ha="center", va="center")
    ax.text(-0.1, 0.8, f"{AC}", ha="center", va="center")
    ax.text(1.5, 0.8, f"{BC}", ha="center", va="center")
    ax.text(0.7, 0.4, f"{ABC}", ha="center", va="center", fontweight="bold")

    st.pyplot(fig)
    st.caption(f"A∩B: {AB} • A∩C: {AC} • B∩C: {BC} • A∩B∩C: {ABC}")

def attribution_context_text(counts: dict, sourcesets: dict, topn: int = 10) -> str:
    lines = []
    if counts:
        lines.append("Enumeration attribution summary:")
        total_unique = len(set().union(*sourcesets.values())) if sourcesets else 0
        lines.append(f"- Unique subdomains (combined): {total_unique}")
        for src, cnt in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"- {src}: {cnt}")
        for src, s in sourcesets.items():
            if not s: 
                continue
            examples = sorted(list(s))[:topn]
            lines.append(f"- Examples from {src} (top {min(topn, len(s))}): " + ", ".join(examples))
    else:
        lines.append("Enumeration attribution summary: none available.")
    return "\n".join(lines)

# ============== GPT summaries ==============

def run_per_run_summary_ui(run_dir: Path, chars_per_chunk=80000):
    run_dir = Path(run_dir)
    if not run_dir.exists():
        st.error(f"Run folder not found: {run_dir}")
        st.caption("The scan may have failed before creating the run directory. Check logs in the console output.")
        return

    # Build attribution context
    sourcesets, counts = load_attribution(run_dir)
    extra_ctx = attribution_context_text(counts, sourcesets, topn=8)

    from src.pipeline.summarise import summarise_full_run
    try:
        text = summarise_full_run(str(run_dir), model="gpt-4o-mini", chars_per_chunk=chars_per_chunk,
                                  extra_context=extra_ctx)
    except TypeError:
        text = summarise_full_run(str(run_dir), model="gpt-4o-mini", chars_per_chunk=chars_per_chunk)
        text = text + "\n\n## Enumeration Attribution\n" + extra_ctx

    (run_dir / "report.md").write_text(text, encoding="utf-8")
    st.subheader("Per-run GPT Summary (auto)")
    st.text_area("Summary", value=text, height=350)

def run_global_summary_ui(include_medium=False, since_days=None, severities="critical,high", chars_per_chunk=80000):
    from src.pipeline.summarise import summarise_all_runs
    sev_set = None
    if severities and severities.strip():
        sev_set = {s.strip().lower() for s in severities.split(",") if s.strip()}
    text = summarise_all_runs(severities=sev_set, since_days=since_days, include_medium=include_medium,
                              chars_per_chunk=int(chars_per_chunk))
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    outp = REPORTS_DIR / f"all_runs_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.md"
    outp.write_text(text, encoding="utf-8")
    st.success(f"Global summary written: {outp}")
    st.text_area("Global Action Plan + Vulnerability Summary (auto)", value=text, height=400)

# ============== Enrichment (NVD/KEV) ==============

def load_known_vulns(run_dir: Path) -> pd.DataFrame:
    f = run_dir / "known_vulns.json"
    if not f.exists():
        return pd.DataFrame()
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        rows = []
        for item in data.get("results", []):
            comp = item.get("component", {})
            for v in item.get("nvd", []):
                rows.append({
                    "product": comp.get("product"),
                    "version": comp.get("version"),
                    "cve": v.get("cve"),
                    "cvss": v.get("cvss"),
                    "kev": v.get("kev", False),
                    "summary": v.get("summary", "")[:200]
                })
        return pd.DataFrame(rows)
    except Exception:
        return pd.DataFrame()

def run_enrichment(run_dir: Path, refresh_kev: bool = False):
    from src.pipeline.enrich import enrich_run_with_known_vulns
    out = enrich_run_with_known_vulns(str(run_dir), nvd_api_key=os.getenv("NVD_API_KEY"), refresh_kev=refresh_kev)
    return out

# ============== File-backed dashboards ==============

def list_runs_sorted_oldest_first() -> List[Path]:
    rs = list_runs()
    return list(reversed(rs))

def build_runs_index() -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for rd in list_runs():
        sub = rd / "subs.txt"
        liv = rd / "live.txt"
        url = rd / "urls.txt"
        nuc = rd / "nuclei.jsonl"
        dt = datetime.fromtimestamp(rd.stat().st_mtime)
        rows.append({
            "run": rd.name,
            "path": str(rd),
            "dt": dt,
            "subs": count_lines(sub),
            "live": count_lines(liv),
            "urls": count_lines(url),
            "nuclei": count_lines(nuc),
        })
    return pd.DataFrame(rows).sort_values("dt")

def nuclei_severity_counts(rd: Path) -> Dict[str, int]:
    jl = rd / "nuclei.jsonl"
    df = jsonl_to_df(jl)
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if df.empty:
        return out
    sevs = []
    if "severity" in df.columns:
        sevs = df["severity"].astype(str).str.lower().tolist()
    elif "info" in df.columns:
        sevs = df["info"].apply(lambda x: (x or {}).get("severity", "") if isinstance(x, dict) else "").astype(str).str.lower().tolist()
    for s in sevs:
        if s in out:
            out[s] += 1
        elif s:
            out[s] = out.get(s, 0) + 1
    return out

def plot_severity_over_time(df_index: pd.DataFrame):
    if df_index.empty:
        st.info("No runs yet to chart."); return
    runs = list_runs_sorted_oldest_first()
    ts = []; crit, high, med, low = [], [], [], []
    for rd in runs:
        cts = nuclei_severity_counts(rd)
        ts.append(datetime.fromtimestamp(rd.stat().st_mtime))
        crit.append(cts.get("critical", 0))
        high.append(cts.get("high", 0))
        med.append(cts.get("medium", 0))
        low.append(cts.get("low", 0))
    fig = plt.figure()
    plt.plot(ts, crit, label="critical")
    plt.plot(ts, high, label="high")
    plt.plot(ts, med, label="medium")
    plt.plot(ts, low, label="low")
    plt.legend(); plt.title("Nuclei findings by severity over time")
    plt.xlabel("Run time"); plt.ylabel("Count")
    st.pyplot(fig)

def plot_asset_growth(df_index: pd.DataFrame):
    if df_index.empty:
        st.info("No runs yet to chart."); return
    fig = plt.figure()
    plt.plot(df_index["dt"], df_index["subs"], label="subdomains")
    plt.plot(df_index["dt"], df_index["live"], label="resolved hosts")
    plt.plot(df_index["dt"], df_index["urls"], label="URLs")
    plt.legend(); plt.title("Asset growth across runs")
    plt.xlabel("Run time"); plt.ylabel("Count")
    st.pyplot(fig)

# ============== DB-backed dashboards ==============

def db_connect(): return sqlite3.connect(DB_PATH)

def db_runs_index() -> pd.DataFrame:
    if not DB_PATH.exists(): return pd.DataFrame()
    con = db_connect()
    df = pd.read_sql_query("""
      SELECT
        r.id AS run_db_id,
        r.run_id,
        r.target,
        r.started_at,
        r.finished_at,
        (SELECT COUNT(*) FROM subdomain s WHERE s.run_id=r.id)   AS subs,
        (SELECT COUNT(*) FROM live_host l WHERE l.run_id=r.id)   AS live,
        (SELECT COUNT(*) FROM url u WHERE u.run_id=r.id)         AS urls,
        (SELECT COUNT(*) FROM nuclei_finding n WHERE n.run_id=r.id) AS nuclei
      FROM run r
      ORDER BY datetime(r.started_at)
    """, con)
    con.close()
    return df

def db_severity_counts_over_time() -> pd.DataFrame:
    if not DB_PATH.exists(): return pd.DataFrame()
    con = db_connect()
    df = pd.read_sql_query("""
      SELECT
        date(r.started_at) AS day,
        lower(COALESCE(n.severity,'')) AS severity,
        COUNT(*) AS cnt
      FROM run r
      LEFT JOIN nuclei_finding n ON n.run_id = r.id
      GROUP BY day, severity
      ORDER BY day
    """, con)
    con.close()
    return df

def db_top_hosts(limit=20, since_days=None, target_like=None) -> pd.DataFrame:
    if not DB_PATH.exists(): return pd.DataFrame()
    con = db_connect()
    params = {}
    where = []
    if since_days:
        where.append("r.started_at >= datetime('now', ?)")
        params["since"] = f"-{int(since_days)} day"
    if target_like:
        where.append("r.target LIKE :tlike")
        params["tlike"] = f"%{target_like}%"
    wh = ("WHERE " + " AND ".join(where)) if where else ""
    q = f"""
      SELECT nf.host, COUNT(*) AS findings
      FROM nuclei_finding nf
      JOIN run r ON r.id = nf.run_id
      {wh}
      GROUP BY nf.host
      ORDER BY findings DESC
      LIMIT {int(limit)}
    """
    df = pd.read_sql_query(q, con, params=params)
    con.close()
    return df

# ===================== UI =====================

st.set_page_config(page_title="Recon + GPT Dashboard", layout="wide")
st.title("🔎 Recon + GPT — Dashboard")

with st.sidebar:
    st.header("Target Input")
    target_in = st.text_input("Domain or URL", placeholder="example.com or https://example.com")
    force_url = st.text_input("Force URL (optional)", placeholder="https://www.example.com")

    st.divider()
    with st.expander("Enumeration Sources", expanded=True):
        use_subfinder = st.checkbox("Use Subfinder", value=True)
        use_amass     = st.checkbox("Use Amass", value=False)
        amass_mode    = st.selectbox("Amass mode", ["passive","active","both"], index=0)
        write_attrib  = st.checkbox("Write attribution CSV", value=True, help="Creates sub_attribution.csv")

    st.divider()
    with st.expander("Discovery Options", expanded=False):
        fast_discovery = st.checkbox("Fast discovery (Katana + GAU)", value=False)
        katana_depth   = st.slider("Katana depth (0=off)", 0, 5, 0)
        gau_enable     = st.checkbox("Enable GAU", value=False)
        do_ports       = st.checkbox("Naabu (ports → URLs)", value=False)
        do_tls         = st.checkbox("TLS SAN/CN expansion", value=False)
        do_screens     = st.checkbox("Screenshots (gowitness)", value=False)
        do_takeovers   = st.checkbox("Takeovers (subjack)", value=False)

    st.divider()
    with st.expander("Scanning Engine Settings", expanded=False):
        httpx_threads = st.slider("httpx threads", 10, 200, 50, 10)
        httpx_rate    = st.slider("httpx rate (RPS)", 20, 500, 100, 10)
        nuclei_conc   = st.slider("nuclei concurrency", 10, 500, 50, 10)
        nuclei_rate   = st.slider("nuclei rate (RPS)", 50, 1000, 200, 50)
        nuclei_sev    = st.text_input("nuclei severity", placeholder="critical,high")
        nuclei_tags   = st.text_input("nuclei tags", placeholder="exposures,cve")

    st.divider()
    with st.expander("Reporting", expanded=False):
        auto_mode = st.selectbox("Auto-summary after scan", ["This run", "Global", "Off"], index=0)

    st.divider()
    with st.expander("Batch Mode", expanded=False):
        batch_text = st.text_area("Targets (one per line)", height=120,
                                  placeholder="example.com\nhttps://hackerone.com\n*.monash.edu")
        run_batch = st.button("📚 Run batch sequentially", use_container_width=True)

    st.divider()
    go = st.button("🚀 Run scan", use_container_width=True)

console_tab, runs_tab, global_tab, dash_tab = st.tabs(["🖥 Live Console", "📁 Runs Browser", "🌍 Global Summary", "📊 Dashboards"])

# ---------------- Live Console ----------------
with console_tab:
    log_box = st.empty()
    done_box = st.empty()

    if go:
        if not target_in.strip():
            st.error("Please enter a target.")
        else:
            run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            raw_host = normalize_target(target_in)
            host_token = safe_name(raw_host)
            run_dir = RUNS_DIR / f"{run_id}_{host_token}"

            cmd = build_cmd(target_in, run_id, katana_depth, fast_discovery, gau_enable, do_ports, do_tls,
                            do_screens, do_takeovers, httpx_threads, httpx_rate, nuclei_conc, nuclei_rate,
                            nuclei_sev, nuclei_tags, force_url,
                            use_subfinder, use_amass, amass_mode, write_attrib)

            with st.spinner(f"Scanning {target_in} …"):
                st.caption(f"Command: `{shlex.join(cmd)}`")
                buffer: List[str] = []
                try:
                    for line in stream_process(cmd, ROOT):
                        buffer.append(line)
                        log_box.code("\n".join(buffer[-800:]), language="bash")
                except Exception as e:
                    st.error(f"Scan crashed: {e}")
                else:
                    done_box.success("✅ Scan finished")
                    if auto_mode == "This run":
                        if run_dir.exists():
                            with st.spinner("Summarising this scan with GPT…"):
                                run_per_run_summary_ui(run_dir, chars_per_chunk=80000)
                        else:
                            st.warning("Summary skipped: run folder was not created (scan likely failed early). Check the console log above.")
                    elif auto_mode == "Global":
                        with st.spinner("Generating Global GPT Summary (ALL runs)…"):
                            run_global_summary_ui(include_medium=False, since_days=None, severities="critical,high", chars_per_chunk=80000)

    if run_batch:
        targets = [t.strip() for t in batch_text.splitlines() if t.strip() and not t.strip().startswith("#")]
        if not targets:
            st.error("No targets provided in batch.")
        else:
            st.info(f"Starting batch of {len(targets)} target(s).")
            progress = st.progress(0.0, text="Batch progress")
            blog_box = st.empty()
            bdone_box = st.empty()

            last_run_dir: Optional[Path] = None

            for idx, tgt in enumerate(targets, 1):
                run_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
                raw_host = normalize_target(tgt)
                host_token = safe_name(raw_host)
                last_run_dir = RUNS_DIR / f"{run_id}_{host_token}"

                cmd = build_cmd(tgt, run_id, katana_depth, fast_discovery, gau_enable, do_ports, do_tls,
                                do_screens, do_takeovers, httpx_threads, httpx_rate, nuclei_conc, nuclei_rate,
                                nuclei_sev, nuclei_tags, force_url,
                                use_subfinder, use_amass, amass_mode, write_attrib)
                with st.spinner(f"[{idx}/{len(targets)}] Scanning {tgt} …"):
                    st.caption(f"Command: `{shlex.join(cmd)}`")
                    buffer: List[str] = []
                    try:
                        for line in stream_process(cmd, ROOT):
                            buffer.append(line)
                            blog_box.code("\n".join(buffer[-600:]), language="bash")
                    except Exception as e:
                        st.error(f"Scan crashed for {tgt}: {e}")
                progress.progress(idx/len(targets), text=f"Batch {idx}/{len(targets)} complete")
            bdone_box.success("✅ Batch finished")

            if auto_mode == "This run" and last_run_dir:
                if last_run_dir.exists():
                    with st.spinner("Summarising the last scan in the batch with GPT…"):
                        run_per_run_summary_ui(last_run_dir, chars_per_chunk=80000)
                else:
                    st.warning(f"Summary skipped: last run folder not found ({last_run_dir}). Check batch console output for errors.")
            elif auto_mode == "Global":
                with st.spinner("Generating Global GPT Summary (ALL runs)…"):
                    run_global_summary_ui(include_medium=False, since_days=None, severities="critical,high", chars_per_chunk=80000)

# ---------------- Runs Browser ----------------
with runs_tab:
    st.header("Runs")
    runs = list_runs()
    if not runs:
        st.write("No runs yet.")
    else:
        options = [p.name for p in runs]
        selected = st.selectbox("Choose a run", options, index=0, key="runs_select")
        sel_dir = runs[options.index(selected)]
        st.caption(f"Folder: `{sel_dir}`  •  modified {human_dt(sel_dir.stat().st_mtime)}")

        # metrics
        sub_path = sel_dir / "subs.txt"
        live_path = sel_dir / "live.txt"
        urls_path = sel_dir / "urls.txt"
        http_path = sel_dir / "http.jsonl"
        nuc_path = sel_dir / "nuclei.jsonl"
        cols = st.columns(5)
        with cols[0]: st.metric("Subdomains", count_lines(sub_path))
        with cols[1]: st.metric("Resolved hosts", count_lines(live_path))
        with cols[2]: st.metric("Live URLs", count_lines(urls_path))
        with cols[3]: st.metric("HTTP JSONL", count_lines(http_path))
        with cols[4]: st.metric("Nuclei findings", count_lines(nuc_path))

        # Attribution counts + overlap
        sourcesets, counts = load_attribution(sel_dir)
        with st.expander("Enumeration attribution", expanded=False):
            if not counts:
                st.info("No sub_attribution.csv found for this run (enable --write-attribution and re-scan).")
            else:
                cols_attr = st.columns(len(counts))
                for i, (src, cnt) in enumerate(sorted(counts.items(), key=lambda kv: kv[0])):
                    with cols_attr[i]:
                        st.metric(src, cnt)
                draw_overlap_venn(sourcesets)

        tabs = st.tabs(["subs.txt","live.txt","urls.txt","HTTP (jsonl)","Nuclei (jsonl)","Screenshots","Summary / Report","Enrichment"])
        with tabs[0]: st.code(tail_text(sub_path, n=3000))
        with tabs[1]: st.code(tail_text(live_path, n=3000))
        with tabs[2]: st.code(tail_text(urls_path, n=3000))
        with tabs[3]:
            df_http = jsonl_to_df(http_path)
            if df_http.empty: st.write("No HTTP rows.")
            else:
                cols_hint = [c for c in ["url","title","status-code","tech"] if c in df_http.columns]
                st.dataframe(df_http[cols_hint] if cols_hint else df_http, use_container_width=True, hide_index=True)
        with tabs[4]:
            df_nuc = jsonl_to_df(nuc_path)
            if df_nuc.empty: st.write("No nuclei findings.")
            else:
                cols_hint = [c for c in ["template-id","matched-at","host","severity","info"] if c in df_nuc.columns]
                st.dataframe(df_nuc[cols_hint] if cols_hint else df_nuc, use_container_width=True, hide_index=True)
        with tabs[5]:
            st.write("Place screenshots here if you capture them.")
        with tabs[6]:
            rep = sel_dir / "report.md"
            if rep.exists():
                st.markdown(rep.read_text(encoding="utf-8"))
            else:
                st.info("No report.md yet. Run a summary from the console tab.")
        with tabs[7]:
            st.subheader("Known Vulnerabilities (NVD + KEV)")
            c1, c2 = st.columns(2)
            with c1:
                do_enrich = st.button("Run Enrichment for this run", use_container_width=True)
            with c2:
                refresh_kev = st.checkbox("Refresh CISA KEV cache before enriching", value=False)
            if do_enrich:
                with st.spinner("Enriching with NVD + KEV…"):
                    try:
                        out = run_enrichment(sel_dir, refresh_kev=refresh_kev)
                        st.success(f"Wrote {out}")
                    except Exception as e:
                        st.error(f"Enrichment failed: {e}")
            df_known = load_known_vulns(sel_dir)
            if df_known.empty:
                st.info("No known_vulns.json yet or no matches. Click 'Run Enrichment' above.")
            else:
                df_known["kev_badge"] = df_known["kev"].map(lambda x: "✅ KEV" if x else "")
                dfv = df_known.sort_values(by=["kev","cvss"], ascending=[False, False])
                st.dataframe(dfv[["product","version","cve","cvss","kev_badge","summary"]], use_container_width=True, hide_index=True)

# ---------------- Global Summary ----------------
with global_tab:
    st.header("Global GPT Summary")
    col1, col2, col3 = st.columns(3)
    with col1:
        severities = st.text_input("Severities (comma)", value="critical,high")
    with col2:
        since_days = st.number_input("Since days (optional)", min_value=0, value=0, step=1)
    with col3:
        include_medium = st.checkbox("Include medium", value=False)
    if st.button("Generate Global Summary", use_container_width=True):
        with st.spinner("Generating global GPT summary…"):
            run_global_summary_ui(include_medium=include_medium,
                                  since_days=(int(since_days) or None),
                                  severities=severities,
                                  chars_per_chunk=80000)

# ---------------- Dashboards ----------------
with dash_tab:
    st.header("Dashboards")

    use_db = st.toggle("Use DB-backed charts (faster, scalable)", value=True, help="Reads from data/recon.db")
    c1, c2 = st.columns(2)

    if use_db and DB_PATH.exists():
        # Runs summary (DB)
        df_idx = db_runs_index()
        if df_idx.empty:
            st.info("Database is empty. Run a scan or backfill first.")
        else:
            st.subheader("Runs Summary (DB)")
            show_cols = ["run_id","target","started_at","finished_at","subs","live","urls","nuclei"]
            st.dataframe(df_idx[show_cols], use_container_width=True, hide_index=True)

        # Severity over time (DB)
        with c1:
            st.subheader("Severity over time (DB)")
            df_sev = db_severity_counts_over_time()
            if df_sev.empty:
                st.info("No severity data yet.")
            else:
                piv = df_sev.pivot_table(index="day", columns="severity", values="cnt", fill_value=0)
                piv.index = pd.to_datetime(piv.index, errors="coerce")
                fig = plt.figure()
                for col in ["critical","high","medium","low","info"]:
                    if col in piv.columns: plt.plot(piv.index, piv[col], label=col)
                for col in [c for c in piv.columns if c not in {"critical","high","medium","low","info"}]:
                    plt.plot(piv.index, piv[col], label=(col if col else "unknown"))
                plt.legend(); plt.title("Nuclei findings by severity over time (DB)")
                plt.xlabel("Day"); plt.ylabel("Count")
                st.pyplot(fig)

        # Asset growth (DB)
        with c2:
            st.subheader("Asset growth (DB)")
            if df_idx.empty:
                st.info("No runs yet to chart.")
            else:
                fig = plt.figure()
                dfi = df_idx.copy()
                dfi["dt"] = pd.to_datetime(dfi["started_at"])
                dfi = dfi.sort_values("dt")
                plt.plot(dfi["dt"], dfi["subs"], label="subdomains")
                plt.plot(dfi["dt"], dfi["live"], label="resolved hosts")
                plt.plot(dfi["dt"], dfi["urls"], label="URLs")
                plt.legend(); plt.title("Asset growth across runs (DB)")
                plt.xlabel("Run time"); plt.ylabel("Count")
                st.pyplot(fig)

        # Top noisy hosts
        st.subheader("Top hosts by findings")
        colA, colB, colC = st.columns(3)
        with colA:
            since = st.number_input("Since days", min_value=0, value=0, step=1, help="0 = all time")
        with colB:
            target_like = st.text_input("Target contains", value="", help="Filter by target string")
        with colC:
            limit = st.slider("Limit", 5, 100, 20, 5)
        df_hosts = db_top_hosts(limit=limit, since_days=(since or None), target_like=(target_like or None))
        if df_hosts.empty:
            st.info("No findings match the filters.")
        else:
            st.dataframe(df_hosts, use_container_width=True, hide_index=True)

        st.caption("Charts powered by data/recon.db.")

    else:
        # File-backed fallback
        df_idx = build_runs_index()
        with c1:
            st.subheader("Severity over time (files)")
            plot_severity_over_time(df_idx)
        with c2:
            st.subheader("Asset growth (files)")
            plot_asset_growth(df_idx)
        st.caption("Using file-backed dashboards. Enable DB mode above for faster charts.")
