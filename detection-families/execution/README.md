# Detection Family: Execution

Covers techniques attackers use to run malicious code, with emphasis on LOLBins and
living-off-the-land patterns that evade signature-based detection.

## Hypotheses Covered

| Hypothesis | Technique | Status |
|-----------|-----------|--------|
| DH-006 | T1218/T1059 LOLBin Execution | Backlog |

## Rules in This Family

- `sigma/windows/defense_evasion/lolbin_execution.yml`

## Priority Tuning

LOLBin detection has the highest FP rate in the family. Phase 1 goal:
identify which LOLBin patterns occur legitimately in the DO environment
before hardening thresholds for production. Certutil and regsvr32 are
most commonly abused. Tune mshta and wmic first as lowest FP risk.
