#!/usr/bin/env python3
"""
fim.py — File Integrity Monitor (FIM)

Monitors critical system directories for unauthorized file changes by:
  1. Baseline phase: Recursively scanning directories and storing SHA-256 hashes
     in a baseline.json file.
  2. Monitor phase: Re-scanning the environment and comparing current hashes
     against the baseline to detect modified, deleted, or new files.

Uses 4096-byte chunked reading for memory efficiency when hashing large files.

Usage:
    # Create initial baseline
    python3 fim.py --baseline --dirs /etc /usr/bin /usr/sbin

    # Monitor against baseline (run once or schedule with cron)
    python3 fim.py --monitor

    # Monitor with custom baseline file and alert log
    python3 fim.py --monitor --baseline-file /var/fim/baseline.json --log /var/log/fim.log

Requirements:
    Python 3.8+ (no external dependencies)

Author: CyberPath Defense Toolkit
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHUNK_SIZE = 4096  # Bytes read per iteration — memory-efficient for large files
DEFAULT_BASELINE = "fim_baseline.json"
DEFAULT_LOG = "fim_alerts.log"

# Default directories to monitor (customize for your environment)
DEFAULT_DIRS = [
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
]

# File extensions to skip (add extensions that frequently change legitimately)
SKIP_EXTENSIONS = {".log", ".tmp", ".swp", ".pyc", ".pycache"}

# Directories to skip entirely (frequently changing, low security value)
SKIP_DIRS = {
    "/etc/mtab",
    "/etc/resolv.conf.bak",
    "/proc",
    "/sys",
    "/run",
    "/tmp",
}


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

def setup_logging(log_file: str) -> logging.Logger:
    """Configure logging to both console and file."""
    logger = logging.getLogger("fim")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # File handler for alerts
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.WARNING)  # Only WARN+ goes to alert log
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError as e:
        logger.warning("Could not open log file %s: %s", log_file, e)

    return logger


# ---------------------------------------------------------------------------
# Core Functions
# ---------------------------------------------------------------------------

def sha256_file(filepath: Path) -> Optional[str]:
    """
    Compute the SHA-256 hash of a file using chunked reading.

    Reads the file in CHUNK_SIZE blocks to avoid loading large files
    entirely into memory.

    Returns:
        Hex digest string, or None if the file cannot be read.
    """
    hasher = hashlib.sha256()
    try:
        with filepath.open("rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError) as e:
        return None


def should_skip(path: Path) -> bool:
    """
    Determine if a path should be excluded from scanning.

    Skips:
    - Symbolic links (follow them could cause loops or false positives)
    - Files with frequently-changing extensions
    - Explicitly excluded directory paths
    """
    if path.is_symlink():
        return True
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    for skip in SKIP_DIRS:
        try:
            path.relative_to(skip)
            return True
        except ValueError:
            pass
    return False


def scan_directories(dirs: List[str], logger: logging.Logger) -> Dict[str, dict]:
    """
    Recursively scan the given directories and compute SHA-256 hashes for all files.

    Returns:
        Dict mapping absolute file path strings to metadata dicts:
        {
            "hash": "<sha256>",
            "size": <bytes>,
            "mtime": "<iso timestamp>",
            "scanned_at": "<iso timestamp>"
        }
    """
    results: Dict[str, dict] = {}
    scanned = 0
    skipped = 0
    errors = 0
    scan_time = datetime.utcnow().isoformat()

    for directory in dirs:
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning("Directory does not exist, skipping: %s", directory)
            continue
        if not dir_path.is_dir():
            logger.warning("Path is not a directory, skipping: %s", directory)
            continue

        logger.info("Scanning: %s", directory)

        for filepath in dir_path.rglob("*"):
            if not filepath.is_file():
                continue

            if should_skip(filepath):
                skipped += 1
                continue

            file_hash = sha256_file(filepath)
            if file_hash is None:
                logger.debug("Could not hash: %s", filepath)
                errors += 1
                continue

            try:
                stat = filepath.stat()
                results[str(filepath)] = {
                    "hash": file_hash,
                    "size": stat.st_size,
                    "mtime": datetime.utcfromtimestamp(stat.st_mtime).isoformat(),
                    "scanned_at": scan_time,
                }
                scanned += 1
            except OSError as e:
                logger.debug("Stat error for %s: %s", filepath, e)
                errors += 1

    logger.info(
        "Scan complete: %d files hashed, %d skipped, %d errors",
        scanned,
        skipped,
        errors,
    )
    return results


def save_baseline(
    baseline: Dict[str, dict],
    baseline_path: Path,
    dirs: List[str],
    logger: logging.Logger,
) -> None:
    """Write the baseline data to a JSON file with metadata."""
    payload = {
        "created_at": datetime.utcnow().isoformat(),
        "monitored_dirs": dirs,
        "file_count": len(baseline),
        "files": baseline,
    }

    try:
        baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info(
            "Baseline saved: %s (%d files)", baseline_path, len(baseline)
        )
    except OSError as e:
        logger.error("Failed to write baseline: %s", e)
        sys.exit(1)


def load_baseline(baseline_path: Path, logger: logging.Logger) -> Tuple[dict, List[str]]:
    """
    Load baseline data from a JSON file.

    Returns:
        Tuple of (files_dict, monitored_dirs_list)
    """
    if not baseline_path.exists():
        logger.error(
            "Baseline file not found: %s  — Run with --baseline first.", baseline_path
        )
        sys.exit(1)

    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
        files = payload.get("files", {})
        dirs = payload.get("monitored_dirs", [])
        created = payload.get("created_at", "unknown")
        logger.info(
            "Baseline loaded: %s | Created: %s | %d files",
            baseline_path,
            created,
            len(files),
        )
        return files, dirs
    except (json.JSONDecodeError, KeyError, OSError) as e:
        logger.error("Failed to load baseline: %s", e)
        sys.exit(1)


def compare_snapshots(
    baseline: Dict[str, dict],
    current: Dict[str, dict],
    logger: logging.Logger,
) -> Tuple[List[str], List[str], List[str]]:
    """
    Compare baseline and current snapshots.

    Returns:
        Tuple of three lists: (modified_files, new_files, deleted_files)
    """
    baseline_paths = set(baseline.keys())
    current_paths  = set(current.keys())

    modified = []
    new_files = []
    deleted   = []

    # Modified: path exists in both but hash differs
    for path in baseline_paths & current_paths:
        if baseline[path]["hash"] != current[path]["hash"]:
            modified.append(path)

    # New: in current but not in baseline
    for path in current_paths - baseline_paths:
        new_files.append(path)

    # Deleted: in baseline but not in current
    for path in baseline_paths - current_paths:
        deleted.append(path)

    return sorted(modified), sorted(new_files), sorted(deleted)


def report_changes(
    modified: List[str],
    new_files: List[str],
    deleted: List[str],
    baseline: Dict[str, dict],
    current: Dict[str, dict],
    logger: logging.Logger,
) -> int:
    """
    Log all detected changes. Returns total number of changes found.
    """
    total = len(modified) + len(new_files) + len(deleted)

    print("\n" + "=" * 70)
    print("  CyberPath File Integrity Monitor — Change Report")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print("=" * 70)

    if total == 0:
        print("\n  ✅ No changes detected. All files match the baseline.\n")
        logger.info("FIM check passed: no changes detected.")
        return 0

    # Modified files
    if modified:
        print(f"\n  ⚠️  MODIFIED FILES ({len(modified)}):")
        for path in modified:
            old_hash = baseline[path]["hash"][:16]
            new_hash = current[path]["hash"][:16]
            old_mtime = baseline[path].get("mtime", "?")
            new_mtime = current[path].get("mtime", "?")
            print(f"  [MODIFIED] {path}")
            print(f"             Hash: {old_hash}... → {new_hash}...")
            print(f"             Mtime: {old_mtime} → {new_mtime}")
            logger.warning("MODIFIED: %s | old_hash=%s | new_hash=%s", path, old_hash, new_hash)

    # New files
    if new_files:
        print(f"\n  🆕  NEW FILES ({len(new_files)}):")
        for path in new_files:
            size = current[path].get("size", "?")
            print(f"  [NEW] {path}  (size: {size} bytes)")
            logger.warning("NEW FILE: %s | size=%s", path, size)

    # Deleted files
    if deleted:
        print(f"\n  ❌  DELETED FILES ({len(deleted)}):")
        for path in deleted:
            print(f"  [DELETED] {path}")
            logger.warning("DELETED: %s", path)

    print(f"\n  Total changes: {total} (modified={len(modified)}, new={len(new_files)}, deleted={len(deleted)})")
    print("=" * 70 + "\n")

    return total


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberPath File Integrity Monitor — Detect unauthorized file changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create baseline for /etc and /usr/bin
  python3 fim.py --baseline --dirs /etc /usr/bin

  # Monitor using saved baseline
  python3 fim.py --monitor

  # Custom paths
  python3 fim.py --baseline --dirs /var/www/html --baseline-file /var/fim/web_baseline.json
        """,
    )
    parser.add_argument(
        "--baseline", action="store_true",
        help="Create/update the baseline (overwrites existing)"
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help="Compare current state against baseline and report changes"
    )
    parser.add_argument(
        "--dirs", nargs="+", default=DEFAULT_DIRS,
        help=f"Directories to scan (default: {' '.join(DEFAULT_DIRS)})"
    )
    parser.add_argument(
        "--baseline-file", default=DEFAULT_BASELINE,
        help=f"Path to baseline JSON file (default: {DEFAULT_BASELINE})"
    )
    parser.add_argument(
        "--log", default=DEFAULT_LOG,
        help=f"Alert log file path (default: {DEFAULT_LOG})"
    )
    args = parser.parse_args()

    if not args.baseline and not args.monitor:
        parser.print_help()
        sys.exit(1)

    logger = setup_logging(args.log)
    baseline_path = Path(args.baseline_file)

    if args.baseline:
        logger.info("=== FIM Baseline Mode ===")
        current = scan_directories(args.dirs, logger)
        save_baseline(current, baseline_path, args.dirs, logger)

    elif args.monitor:
        logger.info("=== FIM Monitor Mode ===")
        baseline_data, monitored_dirs = load_baseline(baseline_path, logger)

        # Scan the same directories that were baselined
        dirs_to_scan = args.dirs if args.dirs != DEFAULT_DIRS else monitored_dirs
        current = scan_directories(dirs_to_scan, logger)

        modified, new_files, deleted = compare_snapshots(baseline_data, current, logger)
        changes = report_changes(modified, new_files, deleted, baseline_data, current, logger)

        # Exit code 1 if changes detected (useful for scripting/cron alerting)
        sys.exit(1 if changes > 0 else 0)


if __name__ == "__main__":
    main()
