#!/usr/bin/env python3
"""
GitHub Star Monitor
使用生产者-消费者模式，分离监控、克隆和扫描任务
"""

import os
import time
import csv
import json
import requests
import subprocess
import threading
import queue
import signal
import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Configuration
TOKEN = os.getenv("GITHUB_TOKEN")
API_VER = "2022-11-28"
CONFIG_FILE = "star_config.json"
CSV_FILE = "repos.csv"
INTERVAL = 60  # Polling interval in seconds
CLONE_DIR = "repos"  # Directory to clone repositories

# Global flags
INIT_MODE = False  # Whether to clone all historical stars

# Thread pool sizes
MAX_CLONE_WORKERS = 4  # 同时克隆的仓库数
MAX_SCAN_WORKERS = 2   # 同时扫描的仓库数 (scan 更耗资源)

# Queues
clone_queue = queue.Queue()
scan_queue = queue.Queue()

# Thread control
running = True
stats = {
    'stars_found': 0,
    'cloned_success': 0,
    'cloned_failed': 0,
    'scanned_success': 0,
    'scanned_failed': 0,
    'active_clones': 0,
    'active_scans': 0
}

# GitHub API endpoint
URL = "https://api.github.com/user/starred"
HEADERS = {
    "Accept": "application/vnd.github.star+json",
    "X-GitHub-Api-Version": API_VER
}
if TOKEN:
    HEADERS["Authorization"] = f"Bearer {TOKEN}"

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global running
    print("\n\n[INFO] Shutting down gracefully...")
    print("[INFO] Waiting for active tasks to complete...")
    running = False

def load_config():
    """Load config from file and ensure default keys."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            try:
                cfg = json.load(f)
            except Exception:
                cfg = {}
            return ensure_config(cfg)
    return ensure_config({})

def save_config(config):
    """Save ETag to config file."""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

def ensure_config(config):
    """Ensure required keys exist in config dict."""
    if not isinstance(config, dict):
        config = {}
    config.setdefault("etag", None)
    config.setdefault("last_seen_starred_at", None)
    return config

def parse_iso_time(s):
    """Parse ISO8601 time strings incl. GitHub 'Z' suffix into aware datetime."""
    if not s:
        return None
    if isinstance(s, datetime):
        return s
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None

def init_csv():
    """Initialize CSV file with headers if it doesn't exist."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "path", "clonetime", "scantime", "verifytime", "vulns"])

def load_repos_csv():
    """Load repository data from CSV file."""
    repos = {}
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                repos[row["url"]] = row
    return repos

def update_repo_csv(url, **kwargs):
    """Update repository data in CSV file."""
    repos = load_repos_csv()

    if url not in repos:
        repos[url] = {
            "url": url,
            "path": "",
            "clonetime": "",
            "scantime": "",
            "verifytime": "",
            "vulns": ""
        }

    # Update provided fields
    for key, value in kwargs.items():
        if value is not None:
            repos[url][key] = value

    # Write back to CSV
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "path", "clonetime", "scantime", "verifytime", "vulns"])
        writer.writeheader()
        writer.writerows(repos.values())

def get_latest_star_time():
    """Get the latest star time from CSV."""
    repos = load_repos_csv()
    if not repos:
        # If no repos in CSV and not in init mode, return current time
        # to avoid cloning all historical stars
        if not INIT_MODE:
            return datetime.now(timezone.utc).isoformat()
        return None

    # Find the latest clonetime
    latest_time = None
    for repo in repos.values():
        if repo.get("clonetime") and repo["clonetime"] != "unknown":
            if latest_time is None or repo["clonetime"] > latest_time:
                latest_time = repo["clonetime"]

    return latest_time

def is_repo_cloned(repo_url):
    """Check if a repository has already been cloned."""
    repos = load_repos_csv()
    return repo_url in repos

def clone_worker():
    """Clone worker thread - processes clone queue."""
    global stats

    while running:
        try:
            # Get task from queue with timeout
            task = clone_queue.get(timeout=1)
            if task is None:  # Sentinel value
                break

            repo_info = task
            stats['active_clones'] += 1

            try:
                # Clone the repository
                repo_path = clone_repository(
                    repo_info['full_name'],
                    repo_info['clone_url']
                )

                if repo_path:
                    stats['cloned_success'] += 1
                    # Add to scan queue
                    scan_queue.put({
                        'repo_path': repo_path,
                        'repo_url': f"https://github.com/{repo_info['full_name']}"
                    })
                    print(f"[CLONE] ✓ {repo_info['full_name']}")
                else:
                    stats['cloned_failed'] += 1
                    print(f"[CLONE] ✗ {repo_info['full_name']}")

            except Exception as e:
                stats['cloned_failed'] += 1
                print(f"[CLONE] ✗ {repo_info['full_name']}: {str(e)}")

            finally:
                stats['active_clones'] -= 1
                clone_queue.task_done()

        except queue.Empty:
            continue

def scan_worker():
    """Scan worker thread - processes scan queue."""
    global stats

    while running:
        try:
            # Get task from queue with timeout
            task = scan_queue.get(timeout=1)
            if task is None:  # Sentinel value
                break

            repo_path = task['repo_path']
            repo_url = task['repo_url']
            stats['active_scans'] += 1

            try:
                print(f"[SCAN] Starting: {repo_url}")
                start_time = time.time()

                # Prefer the integrated pipeline: scan_then_verify.py
                cmd = ["python3", "scan_then_verify.py", repo_path, "--verify-workers", str(MAX_SCAN_WORKERS)]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600  # 1 hour timeout
                )

                # Update times
                timestamp_now = datetime.now(timezone.utc).isoformat()
                vulns = "0"

                # Prefer reading verification summary for verified counts
                summary_file = Path(repo_path) / "verify_summary.json"
                if summary_file.exists():
                    try:
                        with open(summary_file, "r", encoding="utf-8") as f:
                            summary = json.load(f)
                        results = summary.get("results", []) if isinstance(summary, dict) else []
                        verified_count = sum(1 for r in results if isinstance(r, dict) and r.get("verified") is True)
                        # Fallback: if verified is None, count successful rc==0
                        if verified_count == 0:
                            verified_count = sum(1 for r in results if isinstance(r, dict) and r.get("rc") == 0)
                        vulns = str(verified_count)
                    except Exception:
                        pass
                else:
                    # Fallback to legacy file: verified_findings.json
                    findings_file = Path(repo_path) / "verified_findings.json"
                    if findings_file.exists():
                        try:
                            with open(findings_file, "r", encoding="utf-8") as f:
                                findings = json.load(f)
                                vulns_count = len(findings.get("findings", [])) if isinstance(findings, dict) else 0
                                vulns = str(vulns_count)
                        except Exception:
                            pass

                if result.returncode == 0:
                    stats['scanned_success'] += 1
                else:
                    stats['scanned_failed'] += 1
                    if vulns == "0":
                        vulns = "error"

                update_repo_csv(
                    repo_url,
                    scantime=timestamp_now,
                    verifytime=timestamp_now,
                    vulns=vulns
                )

                duration = time.time() - start_time
                print(f"[SCAN] ✓ {repo_url} ({duration:.1f}s, verified={vulns})")

            except subprocess.TimeoutExpired:
                stats['scanned_failed'] += 1
                print(f"[SCAN] ✗ {repo_url}: Timeout")
                update_repo_csv(repo_url, scantime="timeout")
            except Exception as e:
                stats['scanned_failed'] += 1
                print(f"[SCAN] ✗ {repo_url}: {str(e)}")
                update_repo_csv(repo_url, scantime="error")

            finally:
                stats['active_scans'] -= 1
                scan_queue.task_done()

        except queue.Empty:
            continue

def clone_repository(repo_full_name, clone_url):
    """Clone a repository to the local clone directory."""
    if not repo_full_name or not clone_url:
        return None

    # Check if already tracked in CSV
    repo_url = f"https://github.com/{repo_full_name}"
    if is_repo_cloned(repo_url):
        return None  # Skip if already cloned

    # Create clone directory if it doesn't exist
    clone_path = Path(CLONE_DIR)
    clone_path.mkdir(exist_ok=True)

    # Generate directory name: username_reponame in lowercase
    username, reponame = repo_full_name.split('/')
    dir_name = f"{username.lower()}_{reponame.lower()}"
    repo_path = clone_path / dir_name

    # Check if directory already exists
    if repo_path.exists():
        # Update CSV
        now = datetime.now(timezone.utc).isoformat()
        update_repo_csv(
            repo_url,
            path=str(repo_path),
            clonetime=now
        )
        return str(repo_path)

    try:
        # Clone with retry
        max_retries = 3
        for attempt in range(max_retries):
            try:
                print(f"[CLONE] ({attempt+1}/{max_retries}) {repo_full_name}")
                result = subprocess.run(
                    ["git", "clone", clone_url, str(repo_path)],
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minutes timeout
                )

                if result.returncode == 0:
                    # Update CSV with clone time
                    now = datetime.now(timezone.utc).isoformat()
                    update_repo_csv(
                        repo_url,
                        path=str(repo_path),
                        clonetime=now
                    )
                    return str(repo_path)
                else:
                    if attempt < max_retries - 1:
                        time.sleep(5)  # Wait before retry
                    else:
                        print(f"[ERROR] Git clone failed: {result.stderr}")
                        return None

            except subprocess.TimeoutExpired:
                if attempt < max_retries - 1:
                    time.sleep(5)
                else:
                    print(f"[ERROR] Clone timeout for {repo_full_name}")
                    return None

    except Exception as e:
        print(f"[ERROR] Exception while cloning {repo_full_name}: {str(e)}")
        return None

def fetch_all_starred_repos():
    """Fetch ALL starred repositories (for init mode)."""
    headers = dict(HEADERS)
    all_stars = []
    page = 1
    per_page = 100
    total_count = 0

    print("[INIT] Fetching all starred repositories...")

    try:
        while True:
            params = {
                "sort": "created",
                "direction": "desc",
                "per_page": per_page,
                "page": page
            }

            resp = requests.get(URL, params=params, headers=headers, timeout=30)

            if resp.status_code == 401:
                print("[ERROR] Authentication required!")
                return []
            elif resp.status_code == 403:
                print("[ERROR] Rate limit exceeded or token invalid")
                return []

            resp.raise_for_status()

            data = resp.json()
            if not data:
                break

            # Process this page
            for item in data:
                starred_at = item.get("starred_at")
                repo = item.get("repo", {})
                full_name = repo.get("full_name")

                if full_name and starred_at:
                    # Check if already in CSV
                    repo_url = f"https://github.com/{full_name}"
                    if not is_repo_cloned(repo_url):
                        all_stars.append({
                            "full_name": full_name,
                            "starred_at": starred_at,
                            "clone_url": repo.get("clone_url"),
                            "description": repo.get("description"),
                            "language": repo.get("language")
                        })

            total_count += len(data)
            print(f"[INIT] Fetched page {page}: {len(data)} stars (total: {total_count})")

            if len(data) < per_page:
                break

            page += 1
            if page > 100:  # Safety limit: 10,000 stars
                print("[WARNING] Reached maximum page limit (100)")
                break

        print(f"[INIT] Total uncloned stars found: {len(all_stars)}")
        return all_stars

    except Exception as e:
        print(f"[ERROR] Failed to fetch stars: {str(e)}")
        return []

def fetch_all_new_stars(config):
    """Fetch all new starred repositories since last check.
    Uses ETag and a persisted 'last_seen_starred_at' cursor to avoid missing events.
    """
    config = ensure_config(config)
    headers = dict(HEADERS)
    if config.get("etag"):
        headers["If-None-Match"] = config["etag"]

    all_stars = []
    page = 1
    per_page = 100

    last_seen_dt = parse_iso_time(config.get("last_seen_starred_at"))

    try:
        while True:
            params = {
                "sort": "created",
                "direction": "desc",
                "per_page": per_page,
                "page": page
            }

            resp = requests.get(URL, params=params, headers=headers, timeout=30)

            if resp.status_code == 401:
                print("[ERROR] Authentication required! Please set GITHUB_TOKEN.")
                return [], config
            elif resp.status_code == 403:
                print("[ERROR] Rate limit exceeded or token invalid")
                return [], config

            # Use ETag to short-circuit when nothing has changed
            if page == 1 and resp.status_code == 304:
                return [], config

            resp.raise_for_status()

            if page == 1 and "ETag" in resp.headers:
                config["etag"] = resp.headers["ETag"]

            data = resp.json()
            if not data:
                break

            # First-run priming: establish cursor without cloning historical stars
            if last_seen_dt is None and not INIT_MODE:
                top_star = data[0].get("starred_at")
                if top_star:
                    config["last_seen_starred_at"] = top_star
                    print(f"[MONITOR] Initialized last_seen_starred_at to {top_star} (no historical cloning).")
                return [], config

            # Process this page (sorted desc by starred time)
            for item in data:
                starred_at = item.get("starred_at")
                repo = item.get("repo", {})
                full_name = repo.get("full_name")
                if not full_name or not starred_at:
                    continue

                if last_seen_dt and parse_iso_time(starred_at) <= last_seen_dt:
                    # We've reached already-seen items; stop early
                    return all_stars, config

                repo_url = f"https://github.com/{full_name}"
                if not is_repo_cloned(repo_url):
                    all_stars.append({
                        "full_name": full_name,
                        "starred_at": starred_at,
                        "clone_url": repo.get("clone_url"),
                        "description": repo.get("description"),
                        "language": repo.get("language")
                    })

            if len(data) < per_page:
                break

            page += 1
            if page > 10:  # Safety limit
                break

        # Advance cursor if we found new stars
        if all_stars:
            max_dt = max((parse_iso_time(s["starred_at"]) for s in all_stars if s.get("starred_at")), default=last_seen_dt)
            if max_dt:
                config["last_seen_starred_at"] = max_dt.isoformat()

        return all_stars, config

    except Exception as e:
        print(f"[ERROR] Failed to fetch stars: {str(e)}")
        return [], config

def print_stats():
    """Print current statistics."""
    print(f"\n[STATS] Stars: {stats['stars_found']} | "
          f"Clone: {stats['cloned_success']}/{stats['cloned_failed']} | "
          f"Scan: {stats['scanned_success']}/{stats['scanned_failed']} | "
          f"Active: {stats['active_clones']}C/{stats['active_scans']}S | "
          f"Queue: {clone_queue.qsize()}C/{scan_queue.qsize()}S")

def monitor_loop():
    """Main monitoring loop - producer thread."""
    global stats

    print("[MONITOR] Started monitoring thread")

    # If init mode, fetch all historical stars first
    if INIT_MODE:
        print("\n" + "="*60)
        print("[INIT] Running in initialization mode")
        print("[INIT] Will fetch and clone ALL starred repositories")
        print("="*60 + "\n")

        # Fetch all starred repositories
        all_stars = fetch_all_starred_repos()

        if all_stars:
            stats['stars_found'] += len(all_stars)
            print(f"[INIT] Adding {len(all_stars)} repositories to clone queue")

            # Add all to clone queue
            for star in all_stars:
                clone_queue.put(star)

            print("[INIT] Initialization complete. Starting normal monitoring...\n")

    # Load config once and reuse it across iterations
    config = load_config()

    # Normal monitoring loop
    while running:
        try:
            print(f"\n[MONITOR] Checking for new stars at {datetime.now(timezone.utc).isoformat()}")

            # Fetch new stars (only if not in init mode or init is complete)
            new_stars, config = fetch_all_new_stars(config)

            if new_stars:
                stats['stars_found'] += len(new_stars)
                print(f"[MONITOR] Found {len(new_stars)} new stars")

                # Add to clone queue
                for star in new_stars:
                    clone_queue.put(star)

            # Persist ETag/last_seen changes even if no new stars this cycle
            save_config(config)
            if new_stars:
                print_stats()

            # Print periodic stats even if no new stars
            if clone_queue.qsize() > 0 or scan_queue.qsize() > 0:
                print_stats()

        except Exception as e:
            print(f"[ERROR] Monitor loop error: {str(e)}")

        # Wait for next iteration
        for _ in range(INTERVAL):
            if not running:
                break
            time.sleep(1)

    print("[MONITOR] Stopped")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="GitHub Star Monitor - Monitor and clone starred repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Normal mode: only monitor new stars
  %(prog)s --init=true        # Init mode: clone all historical stars first
  %(prog)s --init              # Short form for init mode
        """
    )

    parser.add_argument(
        "--init",
        action="store_true",
        help="Clone all historical starred repositories before monitoring"
    )

    return parser.parse_args()

def main():
    """Main entry point."""
    global running, INIT_MODE

    # Parse arguments
    args = parse_args()
    INIT_MODE = args.init

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)

    print("GitHub Star Monitor starting...")
    print(f"Configuration: {MAX_CLONE_WORKERS} clone workers, {MAX_SCAN_WORKERS} scan workers")
    print(f"Mode: {'Initialization + Monitoring' if INIT_MODE else 'Monitoring only'}")

    if not TOKEN:
        print("[WARN] GITHUB_TOKEN is not set. Set it in your shell or .env to access /user/starred.")

    # Initialize
    init_csv()
    config = load_config()

    # Start worker threads
    print("[INFO] Starting worker threads...")

    # Clone workers
    clone_workers = []
    for i in range(MAX_CLONE_WORKERS):
        t = threading.Thread(target=clone_worker, name=f"Clone-{i}")
        t.daemon = True
        t.start()
        clone_workers.append(t)

    # Scan workers
    scan_workers = []
    for i in range(MAX_SCAN_WORKERS):
        t = threading.Thread(target=scan_worker, name=f"Scan-{i}")
        t.daemon = True
        t.start()
        scan_workers.append(t)

    # Start monitor thread
    monitor_thread = threading.Thread(target=monitor_loop, name="Monitor")
    monitor_thread.daemon = True
    monitor_thread.start()

    print("[INFO] All threads started. Press Ctrl+C to stop.")

    # Main thread - just wait and print stats periodically
    try:
        while running:
            time.sleep(30)
            if running:  # Only print if still running
                print_stats()
    except KeyboardInterrupt:
        pass

    # Graceful shutdown
    running = False

    # Wait for queues to empty
    print("\n[INFO] Waiting for queues to empty...")
    clone_queue.join()
    scan_queue.join()

    # Send sentinel values to stop workers
    for _ in clone_workers:
        clone_queue.put(None)
    for _ in scan_workers:
        scan_queue.put(None)

    # Wait for workers to finish
    for t in clone_workers + scan_workers + [monitor_thread]:
        t.join(timeout=5)

    print("\n[INFO] Final statistics:")
    print_stats()
    print("[INFO] Shutdown complete.")

if __name__ == "__main__":
    main()