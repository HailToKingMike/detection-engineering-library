#!/usr/bin/env python3
"""
update_coverage.py
Regenerates coverage-matrix/current_coverage.json from Sigma rule files and hypothesis YAMLs.
Called by the coverage-update GitHub Actions workflow on every merge to main.
"""

import os, json, yaml, re
from datetime import date

SIGMA_DIR = "sigma"
HYPOTHESES_DIR = "hypotheses"
COVERAGE_FILE = "coverage-matrix/current_coverage.json"

def extract_techniques_from_rule(filepath):
    """Extract ATT&CK technique IDs from a Sigma rule's tags."""
    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
        tags = data.get("tags", [])
        techniques = []
        for tag in tags:
            match = re.match(r"attack\.(t\d+(?:\.\d+)?)", tag.lower())
            if match:
                techniques.append(match.group(1).upper())
        return {
            "title": data.get("title", ""),
            "status": data.get("status", ""),
            "level": data.get("level", ""),
            "techniques": techniques,
            "hypothesis_refs": [t for t in tags if t.startswith("DH-")]
        }
    except Exception as e:
        print(f"  WARN: could not parse {filepath}: {e}")
        return None

def load_hypothesis(hyp_id):
    """Load hypothesis YAML for a given DH-xxx ID."""
    fpath = os.path.join(HYPOTHESES_DIR, f"{hyp_id}.yml")
    if os.path.exists(fpath):
        with open(fpath) as f:
            return yaml.safe_load(f)
    return None

def scan_sigma_rules():
    """Walk sigma/ directory and build technique->rules mapping."""
    technique_map = {}
    rule_count = 0
    for root, dirs, files in os.walk(SIGMA_DIR):
        for fname in files:
            if not fname.endswith(".yml"):
                continue
            fpath = os.path.join(root, fname)
            rule_data = extract_techniques_from_rule(fpath)
            if not rule_data:
                continue
            rule_count += 1
            for tech in rule_data["techniques"]:
                if tech not in technique_map:
                    technique_map[tech] = []
                technique_map[tech].append({
                    "file": fpath,
                    "title": rule_data["title"],
                    "status": rule_data["status"],
                    "level": rule_data["level"],
                    "hypothesis_refs": rule_data["hypothesis_refs"]
                })
    print(f"Scanned {rule_count} Sigma rules, found {len(technique_map)} techniques")
    return technique_map

def compute_score(rules):
    """
    Compute coverage quality score 0-3.
    0 = no rule
    1 = rule exists, experimental status
    2 = rule exists, test status or multiple rules
    3 = rule exists, stable/production status
    """
    if not rules:
        return 0
    statuses = [r["status"] for r in rules]
    if "stable" in statuses or "production" in statuses:
        return 3
    if len(rules) > 1 or "test" in statuses:
        return 2
    return 1

def update_coverage():
    """Main: scan rules, load existing coverage, update and write."""
    print("Loading existing coverage matrix...")
    with open(COVERAGE_FILE) as f:
        coverage = json.load(f)

    print("Scanning Sigma rules...")
    technique_map = scan_sigma_rules()

    updated = 0
    for tech_id, tech_data in coverage["techniques"].items():
        rules = technique_map.get(tech_id, [])
        old_score = tech_data.get("elastic_score", 0)
        new_score = compute_score(rules)

        if rules:
            tech_data["rules"] = [r["title"] for r in rules]
            tech_data["rule_count"] = len(rules)
        else:
            tech_data["rules"] = []
            tech_data["rule_count"] = 0

        tech_data["elastic_score"] = new_score

        if new_score != old_score:
            print(f"  {tech_id}: score {old_score} -> {new_score}")
            updated += 1

    # Update summary
    total = len(coverage["techniques"])
    score3 = sum(1 for t in coverage["techniques"].values() if t.get("elastic_score", 0) == 3)
    score2 = sum(1 for t in coverage["techniques"].values() if t.get("elastic_score", 0) == 2)
    score1 = sum(1 for t in coverage["techniques"].values() if t.get("elastic_score", 0) == 1)
    score0 = sum(1 for t in coverage["techniques"].values() if t.get("elastic_score", 0) == 0)

    coverage["generated"] = str(date.today())
    coverage["summary"]["total_techniques"] = total
    coverage["summary"]["score_3_rules"] = score3
    coverage["summary"]["score_2_rules"] = score2
    coverage["summary"]["score_1_rules"] = score1
    coverage["summary"]["score_0_no_coverage"] = score0
    coverage["summary"]["elastic_coverage_pct"] = round((score3 / total) * 100, 1) if total > 0 else 0

    with open(COVERAGE_FILE, "w") as f:
        json.dump(coverage, f, indent=2)

    print(f"\nCoverage matrix updated: {updated} techniques changed")
    print(f"Score 3 (validated): {score3}/{total}")
    print(f"Score 2 (partial):   {score2}/{total}")
    print(f"Score 1 (rule only): {score1}/{total}")
    print(f"Score 0 (no rule):   {score0}/{total}")
    print(f"Elastic coverage:    {coverage['summary']['elastic_coverage_pct']}%")

if __name__ == "__main__":
    update_coverage()
