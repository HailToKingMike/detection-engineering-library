# Detection Family: Identity Abuse

The Identity Abuse detection family covers attacks targeting credentials, MFA, and authentication
systems. This was built as the gold standard template for the detection family architecture.

## Hypotheses Covered

| Hypothesis | Technique | Status |
|-----------|-----------|--------|
| DH-001 | T1003.001 LSASS Credential Dumping | Backlog |
| DH-002 | T1558.003 Kerberoasting | Backlog |
| DH-007 | T1003.006 DCSync | Backlog |
| DH-010 | T1110.003 Password Spray | Backlog |
| DH-013 | T1621 MFA Fatigue | Backlog |
| DH-016 | T1078 Impossible Travel | Backlog |

## Detection Components (8-Component Bundle)

1. **Sigma Rules** — `sigma/windows/credential_access/`
2. **EQL Correlation Rule** — Cross-source sequence detection (Duo + CrowdStrike)
3. **ML Anomaly Job** — Unusual authentication patterns per user peer group
4. **Kibana Dashboard** — Identity Abuse investigation timeline
5. **Alert Triage Guide** — Analyst decision tree per alert type
6. **False Positive Baseline** — Known-good patterns per target environment
7. **Remediation Runbook** — Response steps per confirmed identity abuse scenario
8. **ATT&CK Coverage Map** — Navigator layer for this family

## EQL Correlation: Duo MFA Failure followed by CrowdStrike Alert

Requires `logs-crowdstrike.falcon@custom` lowercase pipeline active.

```eql
sequence by user.name with maxspan=10m
  [authentication where event.dataset == "duo.auth"
   and event.outcome == "failure"
   and duo.auth.factor == "push"]
  [alert where event.dataset == "crowdstrike.falcon"
   and event.kind == "alert"]
```

## Known Issues

- `user.name` case mismatch: CrowdStrike uppercase vs Duo lowercase
- Fix: `logs-crowdstrike.falcon@custom` pipeline applies lowercase processor
- Status: Pipeline built, validation in progress
- Entra ID correlation blocked on P1/P2 license (cloud identity team)

## Triage Scoring

| Score | Tier | Action |
|-------|------|--------|
| 0-30 | Auto-close | Insufficient signal |
| 31-60 | T1 | Analyst triage within 4 hours |
| 61-85 | T2 Escalate | Senior analyst, 1 hour SLA |
| 86-100 | Auto-contain | Immediate isolation + notification |
