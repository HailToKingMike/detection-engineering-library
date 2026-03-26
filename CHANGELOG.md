# Changelog

All detection rule and hypothesis changes documented here.
Format: [Date] — [Type] — [Technique] — [Description]

---

## 2026-03-26 — Initial commit

- Repository structure initialized
- 19 detection hypotheses seeded (DH-001 through DH-019)
  - Prioritized by adversary frequency targeting the education sector
  - Sources: CISA advisories, REN-ISAC higher education briefings, incident-derived TTPs
- 13 Sigma rules covering top-priority adversary TTPs
  - All rules compile to Elastic and CrowdStrike backends via pySigma
- 4 adversary profiles defined (Ransomware Groups, APT29, APT28, Opportunistic Actors)
- Coverage matrix initialized — 18 ATT&CK techniques at Score 1 (rules written, lab pending)
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
| Regressed | Rule stopped firing after pipeline change — requires re-validation |
| Retired | Rule removed from active detection with documented reason |
