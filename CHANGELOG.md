# Changelog

All detection rule and hypothesis changes documented here.
Format: [Date] - [Type] - [Technique] - [Description]

---

## 2026-03-28 - Platform architecture and execution plan

- Two-repository architecture established:
  - `detection-engineering-library` (public): rules, hypotheses, coverage, methodology
  - `detection-platform` (private): AlertTriageService, lab configs, deployment scripts
- Detection validation pipeline fully mapped across 4 work streams (22 tracked tasks):
  - Work Stream 1: Detection lab infrastructure (dev SIEM cluster, 4-VM lab, Fleet enrollment)
  - Work Stream 2: AlertTriageService platform (env var refactor, config profiles, connectivity validation, prompt tuning)
  - Work Stream 3: ART testing loop and Detection-as-Code (Atomic Red Team install, hypothesis mapping, validation loops, CI/CD, promotion SOP)
  - Work Stream 4: Portfolio and brand (repo metadata, public documentation updates)
- AlertTriageService four-tier triage scoring model documented (auto-close, T1 analyst, T2 escalate, auto-contain)
- ART testing loop methodology documented: attack to telemetry to triage to rule to evidence in a single session
- Three-check validation process defined: true positive, false positive, rebuild and retest
- Detection rule promotion SOP scoped: dev validated to production deployment with quality gates
- Detection stack updated to Elastic Cloud 9.3.2
- Validation lab architecture finalized: AWS isolated VPC with DC, 2x Win11, Kali, dev CrowdStrike CID
- Coverage matrix updated: siem_version now reflects 9.3.2, lab_status updated
- DH-001 (T1003.001 LSASS) designated as proof-of-concept ART loop
- Critical path identified: lab VM delivery gates all validation work

---

## 2026-03-26 - Initial commit

- Repository structure initialized
- 19 detection hypotheses seeded (DH-001 through DH-019)
  - Prioritized by adversary frequency targeting the education sector
  - Sources: CISA advisories, REN-ISAC higher education briefings, incident-derived TTPs
- 13 Sigma rules covering top-priority adversary TTPs
  - All rules compile to Elastic and CrowdStrike backends via pySigma
- 4 adversary profiles defined (Ransomware Groups, APT29, APT28, Opportunistic Actors)
- Coverage matrix initialized: 18 ATT&CK techniques at Score 1 (rules written, lab pending)
- Identity Abuse detection family architecture documented as gold standard template
- CI/CD pipeline configured (Sigma validation + multi-backend compilation + coverage auto-update)
- Detection lab: AWS sandbox VPC approved, isolated CrowdStrike CID active, build in progress

---

## Rule Status Key

| Status | Meaning |
|--------|---------|
| Added | New rule submitted via PR |
| Validated | Three-check lab validation complete (TP, FP, rebuild) |
| Tuned | Existing rule updated for FP reduction |
| Promoted | Deployed to production Kibana and CrowdStrike CID |
| Regressed | Rule stopped firing after pipeline change, requires re-validation |
| Retired | Rule removed from active detection with documented reason |
