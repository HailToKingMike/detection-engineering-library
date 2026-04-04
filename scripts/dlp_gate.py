#!/usr/bin/env python3
"""
dlp_gate.py
Data Loss Prevention validation for the public detection-engineering-library.

Scans all tracked files for patterns that should never appear in a public
repository: internal IP addresses, organizational hostnames, personnel
names, deployment IDs, service account names, and precise operational
metrics.

Runs as a CI/CD gate on every pull request. If any pattern matches, the
build fails and the PR cannot merge until the leak is removed.

Usage:
  python scripts/dlp_gate.py                    # scan entire repo
  python scripts/dlp_gate.py --changed-only     # scan only git-changed files
  python scripts/dlp_gate.py --fix-suggestions  # show what to replace with

Exit codes:
  0 = clean, no leaks detected
  1 = leaks detected, PR must not merge
"""

import os
import re
import sys
import argparse
import subprocess
from pathlib import Path

# ---------------------------------------------------------------
# Patterns that must NEVER appear in the public repository.
# Each pattern has a name, regex, and suggested replacement.
#
# MAINTAINER NOTE: Update this list when new infrastructure is
# deployed, new team members join, or network ranges change.
# This is the single source of truth for what's considered a leak.
# ---------------------------------------------------------------

DLP_PATTERNS = [
    # RFC 1918 internal addresses (specific organizational subnets)
    {
        "name": "Internal IP (10.x)",
        "pattern": r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "exclude_pattern": r"10\.0\.[01]\.\d{1,3}",  # allow lab/example ranges
        "suggestion": "Use lab placeholder IPs (10.0.0.x or 10.0.1.x) or remove",
    },
    {
        "name": "Internal IP (172.16-31.x)",
        "pattern": r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
        "suggestion": "Remove or replace with example range",
    },
    {
        "name": "Internal IP (192.168.x)",
        "pattern": r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
        "suggestion": "Remove or replace with example range",
    },

    # Organizational hostnames and naming conventions
    {
        "name": "DC hostname pattern",
        "pattern": r"\b[A-Z]{2,4}DC\d{2}\b",
        "suggestion": "Use lab-dc-01 or generic placeholder",
    },
    {
        "name": "Deployment ID",
        "pattern": r"[a-z]{3,8}-[a-f0-9]{6}",
        "suggestion": "Use 'your-deployment' placeholder",
    },
    {
        "name": "Kibana endpoint",
        "pattern": r"[a-z]{3,8}-\w+\.kb\.\w+\.aws\.found\.io",
        "suggestion": "Use 'your-deployment.kb.us-west-2.aws.found.io'",
    },
    {
        "name": "ES endpoint",
        "pattern": r"[a-z]{3,8}-\w+\.es\.\w+\.aws\.found\.io",
        "suggestion": "Use 'your-deployment.es.us-west-2.aws.found.io'",
    },

    # Service account names (internal naming convention)
    {
        "name": "Service account",
        "pattern": r"\bsvc-[a-z]+-[a-z]+\b",
        "exclude_pattern": r"svc-(example|test|demo)",
        "suggestion": "Remove or use svc-example-name",
    },
    {
        "name": "Shared IAM user",
        "pattern": r"serviceaccount-p-uw2-\w+",
        "suggestion": "Remove IAM user reference",
    },

    # Precise operational metrics (fingerprints the environment)
    # Round numbers like "150,000+" are public institutional context.
    # Precise counts like "568,694" are internal operational data.
    {
        "name": "Precise operational count",
        "pattern": r"\b\d{2,3},\d{3}(?![\+\s]*users|\+)\b",
        "exclude_pattern": r"\b(150,000|28,000|170,000)\b",  # public round numbers
        "suggestion": "Use approximate language: 'large user population'",
    },
    {
        "name": "Precise doc count",
        "pattern": r"\b\d{2,3}\.\d[MBK]\s*(docs|documents|records|events)",
        "suggestion": "Use 'dominant ingestion source' or remove count",
    },

    # Personnel names (add new team members here)
    {
        "name": "Personnel name",
        "pattern": r"\b(Robert\s+Mooers|Paul\s+Hickey|Jim\s+Ierley|Michael\s+Tatum|"
                   r"Brent\s+Wickham|Adi\s+Kurti|Justin\s+Ramnandan|Alvin\s+Bridges|"
                   r"Bruce\s+Barry|Brian\s+Wasserman|Apryl\s+Williams|Jeff\s+Necker|"
                   r"Anna\s+Espinoza|Mike\s+Manrod|Jamie\s+Spradlin|"
                   r"Kevin\s+Buffington|Adam\s+Pena|Josh\s+Sebastian)\b",
        "suggestion": "Use role reference: 'cloud identity team', 'systems team', etc.",
    },

    # Jira project keys (internal tracking)
    {
        "name": "Jira ticket reference",
        "pattern": r"\bOW-\d{2,4}\b",
        "suggestion": "Remove Jira references from public repo",
    },
    {
        "name": "TDX ticket reference",
        "pattern": r"\bTDX\s*\d{5,6}\b",
        "suggestion": "Remove TDX references from public repo",
    },
]

# ---------------------------------------------------------------
# File types to scan. Binary files and compiled outputs are skipped.
# ---------------------------------------------------------------

SCAN_EXTENSIONS = {
    ".yml", ".yaml", ".json", ".md", ".txt", ".py", ".sh",
    ".conf", ".cfg", ".ini", ".env", ".example",
}

SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "node_modules",
    "compiled",  # auto-generated, not human-authored
}

# The DLP gate script contains the patterns it's looking for.
# Exclude it from scanning itself.
SKIP_FILES = {
    "dlp_gate.py",
}


def get_changed_files():
    """Get files changed in the current PR (vs origin/main)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            capture_output=True, text=True, check=True,
        )
        return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except subprocess.CalledProcessError:
        print("WARN: Could not get git diff, scanning all files")
        return None


def should_scan(filepath):
    """Check if a file should be scanned based on extension and path."""
    path = Path(filepath)

    if path.name in SKIP_FILES:
        return False

    for skip in SKIP_DIRS:
        if skip in path.parts:
            return False

    return path.suffix.lower() in SCAN_EXTENSIONS


def scan_file(filepath, patterns):
    """Scan a single file for DLP pattern matches. Returns list of findings."""
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings

    for line_num, line in enumerate(lines, 1):
        for p in patterns:
            matches = re.finditer(p["pattern"], line, re.IGNORECASE)
            for match in matches:
                # Check if this match is in the exclude pattern
                if "exclude_pattern" in p:
                    if re.match(p["exclude_pattern"], match.group(), re.IGNORECASE):
                        continue

                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "pattern_name": p["name"],
                    "matched_text": match.group(),
                    "full_line": line.rstrip(),
                    "suggestion": p.get("suggestion", "Remove or redact"),
                })

    return findings


def main():
    parser = argparse.ArgumentParser(description="DLP gate for public repo")
    parser.add_argument("--changed-only", action="store_true",
                        help="Only scan files changed in this PR")
    parser.add_argument("--fix-suggestions", action="store_true",
                        help="Show replacement suggestions")
    parser.add_argument("--path", default=".",
                        help="Root path to scan (default: current directory)")
    args = parser.parse_args()

    print("=" * 60)
    print("DLP GATE: Scanning for sensitive data in public repository")
    print("=" * 60)

    # Determine which files to scan
    if args.changed_only:
        files = get_changed_files()
        if files is None:
            files = []
            for root, dirs, filenames in os.walk(args.path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fname in filenames:
                    fpath = os.path.join(root, fname)
                    if should_scan(fpath):
                        files.append(fpath)
        else:
            files = [f for f in files if should_scan(f) and os.path.exists(f)]
    else:
        files = []
        for root, dirs, filenames in os.walk(args.path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                fpath = os.path.join(root, fname)
                if should_scan(fpath):
                    files.append(fpath)

    print(f"\nScanning {len(files)} files against {len(DLP_PATTERNS)} patterns...\n")

    # Scan
    all_findings = []
    for filepath in sorted(files):
        findings = scan_file(filepath, DLP_PATTERNS)
        all_findings.extend(findings)

    # Report
    if not all_findings:
        print("PASS: No sensitive data detected.")
        print(f"  Files scanned: {len(files)}")
        print(f"  Patterns checked: {len(DLP_PATTERNS)}")
        print("=" * 60)
        return 0

    # Failures
    print(f"FAIL: {len(all_findings)} sensitive data match(es) detected.\n")

    for f in all_findings:
        print(f"  [{f['pattern_name']}] {f['file']}:{f['line']}")
        print(f"    Matched: {f['matched_text']}")
        if args.fix_suggestions:
            print(f"    Fix: {f['suggestion']}")
        print()

    print("=" * 60)
    print(f"BLOCKED: {len(all_findings)} leak(s) must be fixed before merge.")
    print("Run with --fix-suggestions for remediation guidance.")
    print("=" * 60)

    return 1


if __name__ == "__main__":
    sys.exit(main())
