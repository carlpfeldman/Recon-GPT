from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Dict


def _augment_path() -> str:
    """Extend PATH to catch Homebrew installs on macOS."""
    extra = "/opt/homebrew/bin:/usr/local/bin"
    path = os.environ.get("PATH", "")
    if extra not in path:
        path = f"{path}:{extra}" if path else extra
    return path


def _which(name: str) -> Optional[str]:
    """Locate a binary on PATH (with our extended PATH)."""
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = _augment_path()
    try:
        return shutil.which(name)
    finally:
        os.environ["PATH"] = old


def _write_unique(lines: Iterable[str], out_file: Path) -> int:
    """Write unique, sorted lines to out_file. Returns count written."""
    seen: Set[str] = set()
    for s in lines:
        s = (s or "").strip()
        if s:
            seen.add(s)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""), encoding="utf-8")
    return len(seen)


def run_subfinder(domain: str, out_file: Path) -> int:
    """
    Run ProjectDiscovery subfinder (passive discovery).
    Writes unique subdomains to out_file, returns count.
    """
    exe = _which("subfinder")
    if not exe:
        raise RuntimeError("subfinder not found on PATH. Install via: brew install subfinder")
    cmd = [exe, "-d", domain, "-silent", "-all"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"subfinder exited {proc.returncode}: {proc.stderr or proc.stdout}")
    lines = proc.stdout.splitlines()
    return _write_unique(lines, out_file)


def run_amass(domain: str, out_file: Path, passive: bool = True, timeout: Optional[int] = 900) -> int:
    """
    Run OWASP Amass in passive or active mode.
      passive -> `amass enum -passive -d <domain> -o -`
      active  -> `amass enum -d <domain> -o -`
    Writes unique subdomains to out_file, returns count.
    """
    exe = _which("amass")
    if not exe:
        raise RuntimeError("amass not found on PATH. Install via: brew install amass")
    cmd = [exe, "enum", "-d", domain, "-o", "-", "-silent"]
    if passive:
        cmd.insert(2, "-passive")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"amass exited {proc.returncode}: {proc.stderr or proc.stdout}")
    lines = proc.stdout.splitlines()
    return _write_unique(lines, out_file)


def combine_subdomains(inputs: List[Path], out_file: Path) -> int:
    """
    Combine multiple subdomain lists into a single de-duplicated file.
    Returns total unique count.
    """
    all_lines: Set[str] = set()
    for p in inputs:
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if s:
                all_lines.add(s)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(all_lines)) + ("\n" if all_lines else ""), encoding="utf-8")
    return len(all_lines)


def combine_subdomains_with_attribution(
    named_inputs: List[Tuple[str, Path]],
    out_subs_file: Path,
    out_attr_csv: Path,
) -> int:
    """
    Build combined subs AND an attribution CSV.
    named_inputs: list of (source_name, path_to_file)
    out_attr_csv columns: subdomain,sources  (sources = ';' joined source names)
    Returns total unique count.
    """
    # Map subdomain -> set(sources)
    attr: Dict[str, Set[str]] = {}
    for source_name, p in named_inputs:
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s:
                continue
            attr.setdefault(s, set()).add(source_name)

    # Write combined subs
    unique_subs = sorted(attr.keys())
    out_subs_file.parent.mkdir(parents=True, exist_ok=True)
    out_subs_file.write_text("\n".join(unique_subs) + ("\n" if unique_subs else ""), encoding="utf-8")

    # Write attribution CSV
    out_attr_csv.parent.mkdir(parents=True, exist_ok=True)
    lines = ["subdomain,sources"]
    for sub in unique_subs:
        sources = ";".join(sorted(attr[sub]))
        lines.append(f"{sub},{sources}")
    out_attr_csv.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    return len(unique_subs)
