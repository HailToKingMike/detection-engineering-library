# Detection Family: Exfiltration

Covers data exfiltration techniques, primarily DNS-based C2 and large file staging.

## Hypotheses Covered

| Hypothesis | Technique | Status |
|-----------|-----------|--------|
| DH-011 | T1074/T1005 Large File Staging | Backlog |
| DH-019 | T1071.004 DNS Exfiltration | Backlog |
| DH-005 | T1071.004 DNS C2 Beaconing | Backlog |

## Rules in This Family

- `sigma/network/dns_exfiltration_high_entropy.yml`

## Telemetry Dependencies

DNS exfiltration detection depends on:
1. Cloudflare Gateway logs (operational — 148.6M docs)
2. Lab DNS debug logging on lab-dc-01 (configure before Phase 4)

Large file staging rule pending lab validation of Sysmon file creation volume thresholds.
