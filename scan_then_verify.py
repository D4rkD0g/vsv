#!/usr/bin/env python3
"""
End-to-end pipeline: scan then verify

Usage:
  python3 scan_then_verify.py <target_repo_path> [--skip-scan] [--verify-workers N] [--scan-timeout SEC] [--findings-file PATH] [--limit K]

Process:
  1) Run scan.py <repo>
  2) Collect findings from verified_findings.json (preferred) or fallback to per‑vuln Markdown reports
  3) For each finding, render a per‑vuln report under <repo>/verify_inputs/<id>.md
  4) Run verify.py <repo> <that_report.md>
  5) Write summary to <repo>/verify_summary.json
"""

import argparse
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).parent.resolve()

# Directories excluded from vulnerability reporting/verification (can be read for context only)
EXCLUDED_DIR_SEGMENTS = [
    "/tests/", "/test/", "/__tests__/",
    "/examples/", "/example/", "/examples/",
    "/cookbook/", "/cookbooks/",
    "/docs/examples/",
    "/demo/", "/demos/", "/samples/",
]


def run_scan(repo: Path, timeout: int) -> int:
    print(f"[PIPELINE] Running scan: scan.py {repo}")
    scan_script = ROOT / "scan.py"
    if not scan_script.exists():
        print(f"[ERROR] scan.py not found at {scan_script}")
        return 127
    try:
        start = time.time()
        proc = subprocess.run(
            [sys.executable, str(scan_script), str(repo)],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=timeout if timeout and timeout > 0 else None,
        )
        duration = time.time() - start
        print(f"[PIPELINE] Scan finished in {duration:.1f}s, rc={proc.returncode}")
        # Tail some logs for quick visibility
        if proc.stdout:
            print(proc.stdout[-800:])
        if proc.stderr:
            print(proc.stderr[-800:])
        return proc.returncode
    except subprocess.TimeoutExpired:
        print("[ERROR] scan.py timed out")
        return 124
    except Exception as e:
        print(f"[ERROR] scan.py failed: {e}")
        return 1


def find_findings_file(repo: Path, preferred: Path | None = None) -> Path | None:
    # 1) explicit
    if preferred:
        p = preferred if preferred.is_absolute() else (repo / preferred)
        if p.exists():
            return p
    # 2) common location in repo root
    p = repo / "verified_findings.json"
    if p.exists():
        return p
    # 3) search recursively
    for candidate in repo.rglob("verified_findings.json"):
        return candidate
    # 4) SARIF fallback
    for candidate in repo.rglob("*.sarif"):
        return candidate
    return None


def load_findings(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Failed to parse JSON from {path}: {e}")
        return []

    findings: list[dict] = []
    if isinstance(data, dict):
        if isinstance(data.get("findings"), list):
            findings = list(data["findings"])  # expected shape
        elif isinstance(data.get("results"), list):
            findings = list(data["results"])   # alternative shape
        elif isinstance(data.get("runs"), list):
            # shallow SARIF adaptation
            for run in data["runs"]:
                for res in run.get("results", []):
                    findings.append(res)
    elif isinstance(data, list):
        findings = list(data)

    print(f"[PIPELINE] Loaded {len(findings)} findings from {path.name}")
    return findings


def to_text_report(finding: dict) -> str:
    title = finding.get("title") or finding.get("name") or str(finding.get("id") or "finding")
    fid = str(finding.get("id") or finding.get("dedupe_key") or "")
    loc_file = None
    if isinstance(finding.get("location"), dict):
        loc_file = finding["location"].get("file")
    file_path = finding.get("file_path") or loc_file
    start = finding.get("start_line") or (finding.get("location", {}).get("startLine") if isinstance(finding.get("location"), dict) else None)
    end = finding.get("end_line") or (finding.get("location", {}).get("endLine") if isinstance(finding.get("location"), dict) else None)
    loc = f"{file_path}:{start}-{end}" if file_path else ""

    lines = [
        f"# Vulnerability Report: {title}",
        "",
        f"- ID: {fid}",
        f"- Severity: {finding.get('severity') or finding.get('level')}",
        f"- CWE: {finding.get('cwe')}",
        f"- Type: {finding.get('type')}",
        f"- Location: {loc}",
        "",
    ]

    if finding.get("evidence_snippet"):
        lines += [
            "## Evidence",
            "",
            "```",
            str(finding.get("evidence_snippet")),
            "```",
            "",
        ]

    lines += [
        "## Raw Finding JSON",
        "",
        "```json",
        json.dumps(finding, ensure_ascii=False, indent=2),
        "```",
        "",
    ]
    return "\n".join(lines)


def write_verify_inputs(repo: Path, findings: list[dict], limit: int | None) -> list[Path]:
    out_dir = repo / "verify_inputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    reports: list[Path] = []
    for i, f in enumerate(findings, start=1):
        if limit and len(reports) >= limit:
            break
        title = f.get("title") or f.get("name") or str(f.get("id") or "finding")
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", title)[:80]
        fid = str(f.get("id") or f.get("dedupe_key") or f"auto-{i}")
        fname = f"{i:03d}_{fid}_{slug}.md"
        path = out_dir / fname
        path.write_text(to_text_report(f), encoding="utf-8")
        reports.append(path)
    print(f"[PIPELINE] Wrote {len(reports)} verify input reports to {out_dir}")
    return reports


def discover_md_reports(repo: Path) -> list[Path]:
    reports: list[Path] = []
    for p in repo.rglob("*.md"):
        nm = p.name.lower()
        if nm in ("readme.md", "security-report.md"):
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if re.search(r"(?i)(vulnerability|finding|verification|analysis_result|poc)", t):
            # Exclude reports residing under excluded directories
            if not is_path_under_excluded(repo, p):
                reports.append(p)
    print(f"[PIPELINE] Discovered {len(reports)} candidate markdown reports")
    return reports


def run_verify(repo: Path, report_md: Path, timeout: int | None) -> dict:
    verify_script = ROOT / "verify.py"
    if not verify_script.exists():
        return {"report": str(report_md), "rc": 127, "error": f"verify.py missing at {verify_script}"}
    try:
        start = time.time()
        proc = subprocess.run(
            [sys.executable, str(verify_script), str(repo), str(report_md)],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=timeout if timeout and timeout > 0 else None,
        )
        duration = time.time() - start
        print(f"[VERIFY] {report_md.name} rc={proc.returncode} t={duration:.1f}s")
        # Try to locate a produced verification.json
        verify_root = repo / "verify_results"
        vjson = None
        if verify_root.exists():
            candidates = list(verify_root.rglob("verification.json"))
            if candidates:
                candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                vjson = candidates[0]
        verified = None
        if vjson:
            try:
                vdata = json.loads(vjson.read_text(encoding="utf-8"))
                verified = vdata.get("verified")
            except Exception:
                pass
        return {"report": str(report_md), "rc": proc.returncode, "verification_json": str(vjson) if vjson else None, "verified": verified}
    except subprocess.TimeoutExpired:
        print(f"[VERIFY] timeout {report_md.name}")
        return {"report": str(report_md), "rc": 124}
    except Exception as e:
        return {"report": str(report_md), "rc": 1, "error": str(e)}


def norm_rel(repo: Path, p: Path) -> str:
    try:
        rel = p.resolve().relative_to(repo.resolve())
    except Exception:
        rel = p
    s = "/" + str(rel).replace("\\", "/").strip("/") + "/"
    return s


def is_path_under_excluded(repo: Path, p: Path) -> bool:
    s = norm_rel(repo, p)
    return any(seg in s for seg in EXCLUDED_DIR_SEGMENTS)


def finding_is_excluded(repo: Path, f: dict) -> bool:
    file_path = f.get("file_path")
    if not file_path and isinstance(f.get("location"), dict):
        file_path = f.get("location", {}).get("file")
    if not file_path:
        return False
    canonical = "/" + str(file_path).replace("\\", "/").strip("/") + "/"
    return any(seg in canonical for seg in EXCLUDED_DIR_SEGMENTS)


def main():
    ap = argparse.ArgumentParser(description="Scan then verify pipeline")
    ap.add_argument("repo", help="Target repository path")
    ap.add_argument("--skip-scan", action="store_true", help="Skip running scan.py")
    ap.add_argument("--verify-workers", type=int, default=2, help="Concurrent verify workers")
    ap.add_argument("--scan-timeout", type=int, default=3600, help="Scan timeout seconds")
    ap.add_argument("--verify-timeout", type=int, default=1800, help="Verify timeout seconds")
    ap.add_argument("--findings-file", help="Path to findings JSON (default: auto-discover)")
    ap.add_argument("--limit", type=int, help="Limit number of findings/reports to verify")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    if not repo.exists() or not repo.is_dir():
        print(f"[ERROR] repo not found: {repo}")
        sys.exit(2)

    if not args.skip_scan:
        rc = run_scan(repo, args.scan_timeout)
        if rc != 0:
            print(f"[WARN] scan.py returned rc={rc}")

    findings_file = None
    if args.findings_file:
        p = Path(args.findings_file)
        findings_file = p if p.is_absolute() else (repo / p)
    else:
        findings_file = find_findings_file(repo)

    reports: list[Path] = []
    excluded_count = 0
    if findings_file and findings_file.suffix.lower() == ".json":
        findings = load_findings(findings_file)
        if findings:
            filtered = [f for f in findings if not finding_is_excluded(repo, f)]
            excluded_count = len(findings) - len(filtered)
            if excluded_count > 0:
                print(f"[PIPELINE] Excluded {excluded_count} findings under tests/examples/cookbook/demo/sample paths")
            if filtered:
                reports = write_verify_inputs(repo, filtered, limit=args.limit)

    if not reports:
        reports = discover_md_reports(repo)
        if args.limit:
            reports = reports[: args.limit]

    if not reports:
        print("[PIPELINE] No findings or reports found.")
        sys.exit(0)

    print(f"[PIPELINE] Verifying {len(reports)} items with {args.verify_workers} workers...")
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, args.verify_workers)) as ex:
        futures = [ex.submit(run_verify, repo, r, args.verify_timeout) for r in reports]
        for f in as_completed(futures):
            results.append(f.result())

    summary = {
        "repo": str(repo),
        "count": len(results),
        "excluded_due_to_scope": excluded_count,
        "results": results,
    }
    out = repo / "verify_summary.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[PIPELINE] Summary written to {out}")


if __name__ == "__main__":
    main()
