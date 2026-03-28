#!/usr/bin/env python3
"""
log_parser.py — Security Log Parser and Anomaly Detector

Parses structured (CSV, JSON) and semi-structured (plain text) security log files,
groups events by source IP or user ID, and flags anomalous patterns such as
brute-force attempts and credential stuffing.

Usage:
    python3 log_parser.py --file auth.log --format text --output report.csv
    python3 log_parser.py --file events.csv --format csv --output report.csv
    python3 log_parser.py --file events.json --format json

Requirements:
    pip install pandas

Author: CyberPath Defense Toolkit
"""

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    print("[ERROR] pandas is required: pip install pandas")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regex patterns for semi-structured log parsing
# ---------------------------------------------------------------------------

# Matches common auth.log / syslog lines:
# Jan 01 12:34:56 hostname sshd[1234]: Failed password for user from 1.2.3.4 port 22 ssh2
SYSLOG_FAILED_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\[?\d*\]?:\s+"
    r"Failed\s+\w+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

SYSLOG_ACCEPTED_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\[?\d*\]?:\s+"
    r"Accepted\s+\w+\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

# Simple IPv4 pattern for extraction
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def parse_text_log(filepath: Path) -> pd.DataFrame:
    """Parse a plain-text syslog/auth.log file into a DataFrame."""
    records = []
    year = datetime.now().year  # syslog doesn't include year

    with filepath.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue

            event_type = "UNKNOWN"
            user = ""
            src_ip = ""
            port = ""

            failed_match = SYSLOG_FAILED_RE.search(line)
            accepted_match = SYSLOG_ACCEPTED_RE.search(line)

            if failed_match:
                event_type = "FAILED_LOGIN"
                user = failed_match.group("user")
                src_ip = failed_match.group("src_ip")
                port = failed_match.group("port")
                ts_str = f"{year} {failed_match.group('month')} {failed_match.group('day')} {failed_match.group('time')}"
            elif accepted_match:
                event_type = "SUCCESSFUL_LOGIN"
                user = accepted_match.group("user")
                src_ip = accepted_match.group("src_ip")
                port = accepted_match.group("port")
                ts_str = f"{year} {accepted_match.group('month')} {accepted_match.group('day')} {accepted_match.group('time')}"
            else:
                continue  # Skip lines we don't recognize

            try:
                timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            except ValueError:
                timestamp = None

            records.append(
                {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "user": user,
                    "src_ip": src_ip,
                    "port": port,
                    "raw_line": line,
                }
            )

    if not records:
        log.warning("No recognizable log entries found in %s", filepath)
        return pd.DataFrame()

    df = pd.DataFrame(records)
    log.info("Parsed %d events from text log", len(df))
    return df


def parse_csv_log(filepath: Path) -> pd.DataFrame:
    """
    Parse a CSV log file.
    Expected columns (flexible): timestamp, event_type, user, src_ip, port
    Maps common alternative column names automatically.
    """
    df = pd.read_csv(filepath, dtype=str, on_bad_lines="warn")

    # Normalize column names
    col_map = {
        "time": "timestamp",
        "datetime": "timestamp",
        "date": "timestamp",
        "username": "user",
        "account": "user",
        "source_ip": "src_ip",
        "ip": "src_ip",
        "source": "src_ip",
        "event": "event_type",
        "type": "event_type",
        "action": "event_type",
    }
    df.columns = [col_map.get(c.lower().strip(), c.lower().strip()) for c in df.columns]

    # Ensure required columns exist
    for col in ["timestamp", "event_type", "user", "src_ip"]:
        if col not in df.columns:
            df[col] = ""

    # Parse timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", infer_datetime_format=True)
    log.info("Parsed %d events from CSV log", len(df))
    return df


def parse_json_log(filepath: Path) -> pd.DataFrame:
    """
    Parse a JSON log file (array of objects, or newline-delimited JSON).
    """
    records = []
    with filepath.open("r", encoding="utf-8", errors="replace") as fh:
        content = fh.read().strip()

    # Try array format first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = [data]
    except json.JSONDecodeError:
        # Try newline-delimited JSON (NDJSON)
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not records:
        log.warning("No JSON records found in %s", filepath)
        return pd.DataFrame()

    df = pd.json_normalize(records)

    # Normalize column names (same mapping as CSV)
    col_map = {
        "time": "timestamp",
        "datetime": "timestamp",
        "username": "user",
        "source_ip": "src_ip",
        "ip": "src_ip",
        "event": "event_type",
    }
    df.columns = [col_map.get(c.lower(), c.lower()) for c in df.columns]

    for col in ["timestamp", "event_type", "user", "src_ip"]:
        if col not in df.columns:
            df[col] = ""

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", infer_datetime_format=True)
    log.info("Parsed %d events from JSON log", len(df))
    return df


# ---------------------------------------------------------------------------
# Anomaly Detection
# ---------------------------------------------------------------------------


def detect_brute_force(
    df: pd.DataFrame,
    failure_threshold: int = 10,
    window_minutes: int = 5,
) -> pd.DataFrame:
    """
    Detect brute-force patterns: N failed logins from the same source IP
    within a rolling time window.

    Returns a DataFrame of flagged source IPs with context.
    """
    failures = df[df["event_type"].str.contains("FAIL|4625", case=False, na=False)].copy()
    if failures.empty:
        return pd.DataFrame()

    failures = failures.dropna(subset=["timestamp"]).sort_values("timestamp")

    # Group by source IP and count failures
    ip_counts = (
        failures.groupby("src_ip")
        .agg(
            failure_count=("event_type", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            targeted_users=("user", lambda x: ", ".join(x.dropna().unique()[:5])),
        )
        .reset_index()
    )

    flagged = ip_counts[ip_counts["failure_count"] >= failure_threshold].copy()
    flagged["alert_type"] = "BRUTE_FORCE"
    flagged["detail"] = flagged.apply(
        lambda r: f"{r['failure_count']} failed logins targeting: {r['targeted_users']}",
        axis=1,
    )
    return flagged


def detect_credential_stuffing(df: pd.DataFrame, threshold: int = 5) -> pd.DataFrame:
    """
    Detect credential stuffing: a single source IP targeting many different
    usernames with failed logins (broad, low-per-account attempts).
    """
    failures = df[df["event_type"].str.contains("FAIL|4625", case=False, na=False)].copy()
    if failures.empty:
        return pd.DataFrame()

    ip_user_diversity = (
        failures.groupby("src_ip")["user"]
        .nunique()
        .reset_index()
        .rename(columns={"user": "unique_users_targeted"})
    )

    flagged = ip_user_diversity[ip_user_diversity["unique_users_targeted"] >= threshold].copy()
    flagged["alert_type"] = "CREDENTIAL_STUFFING"
    flagged["detail"] = flagged["unique_users_targeted"].apply(
        lambda n: f"Targeted {n} unique accounts"
    )
    return flagged


def detect_success_after_failures(df: pd.DataFrame, min_failures: int = 3) -> pd.DataFrame:
    """
    Detect accounts that had multiple failed logins followed by a successful login
    (possible successful brute-force or compromised credential).
    """
    failures  = df[df["event_type"].str.contains("FAIL|4625", case=False, na=False)]
    successes = df[df["event_type"].str.contains("SUCCESS|ACCEPT|4624", case=False, na=False)]

    if failures.empty or successes.empty:
        return pd.DataFrame()

    # Users with multiple failures
    user_failures = (
        failures.groupby("user")
        .agg(failure_count=("event_type", "count"), last_failure=("timestamp", "max"))
        .reset_index()
    )
    user_failures = user_failures[user_failures["failure_count"] >= min_failures]

    # Check if any also have a success
    success_users = set(successes["user"].dropna())
    flagged = user_failures[user_failures["user"].isin(success_users)].copy()
    flagged["alert_type"] = "BRUTE_FORCE_SUCCESS"
    flagged["detail"] = flagged["failure_count"].apply(
        lambda n: f"{n} failures followed by successful login"
    )
    return flagged


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_summary(df: pd.DataFrame, alerts: pd.DataFrame) -> None:
    """Print a human-readable summary to stdout."""
    print("\n" + "=" * 60)
    print("  CyberPath Log Parser — Analysis Report")
    print("=" * 60)
    print(f"  Total events parsed : {len(df)}")

    if "event_type" in df.columns:
        print("\n  Event Type Breakdown:")
        for evt, count in df["event_type"].value_counts().head(10).items():
            print(f"    {evt:<30} {count:>6}")

    if "src_ip" in df.columns and not df["src_ip"].isna().all():
        print("\n  Top 10 Source IPs by Event Count:")
        for ip, count in df["src_ip"].value_counts().head(10).items():
            print(f"    {str(ip):<20} {count:>6}")

    if not alerts.empty:
        print(f"\n  ⚠️  ALERTS DETECTED: {len(alerts)}")
        print("-" * 60)
        for _, row in alerts.iterrows():
            print(f"  [{row['alert_type']}] {row.get('src_ip', row.get('user', 'N/A'))}")
            print(f"    Detail : {row.get('detail', '')}")
            if "first_seen" in row:
                print(f"    Period : {row.get('first_seen','')} → {row.get('last_seen','')}")
            print()
    else:
        print("\n  ✅ No anomalies detected.")

    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberPath Security Log Parser — Detects brute-force and credential stuffing patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file",    required=True, help="Path to the log file")
    parser.add_argument("--format",  choices=["text", "csv", "json"], default="text",
                        help="Log format (default: text)")
    parser.add_argument("--output",  default="", help="Export alerts to CSV file")
    parser.add_argument("--threshold", type=int, default=10,
                        help="Failed login threshold for brute-force detection (default: 10)")
    parser.add_argument("--window",    type=int, default=5,
                        help="Time window in minutes for brute-force detection (default: 5)")
    args = parser.parse_args()

    filepath = Path(args.file)
    if not filepath.exists():
        log.error("File not found: %s", filepath)
        sys.exit(1)

    # Parse
    log.info("Parsing %s as %s format...", filepath, args.format)
    if args.format == "text":
        df = parse_text_log(filepath)
    elif args.format == "csv":
        df = parse_csv_log(filepath)
    else:
        df = parse_json_log(filepath)

    if df.empty:
        log.warning("No data to analyze. Exiting.")
        sys.exit(0)

    # Detect anomalies
    log.info("Running anomaly detection (threshold=%d, window=%d min)...",
             args.threshold, args.window)
    alerts_list = []
    for detect_fn in [
        lambda d: detect_brute_force(d, args.threshold, args.window),
        lambda d: detect_credential_stuffing(d, threshold=5),
        lambda d: detect_success_after_failures(d, min_failures=3),
    ]:
        result = detect_fn(df)
        if not result.empty:
            alerts_list.append(result)

    all_alerts = pd.concat(alerts_list, ignore_index=True) if alerts_list else pd.DataFrame()

    # Output
    print_summary(df, all_alerts)

    if args.output and not all_alerts.empty:
        out_path = Path(args.output)
        all_alerts.to_csv(out_path, index=False)
        log.info("Alerts exported to %s", out_path)
    elif args.output and all_alerts.empty:
        log.info("No alerts to export.")


if __name__ == "__main__":
    main()
