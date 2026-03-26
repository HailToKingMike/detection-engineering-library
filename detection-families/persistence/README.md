# Detection Family: Persistence

Covers techniques allowing attackers to maintain access across reboots and credential changes.

## Hypotheses Covered

| Hypothesis | Technique | Status |
|-----------|-----------|--------|
| DH-008 | T1053.005 Scheduled Task | Backlog |
| DH-009 | T1547.001 Registry Run Key | Backlog |

## Rules in This Family

- `sigma/windows/persistence/scheduled_task_creation_suspicious.yml`
- `sigma/windows/persistence/registry_run_key_persistence.yml`

## Tuning Note

Both techniques have legitimate uses. Filter tuning after Phase 1 lab validation is expected.
Do not promote to production until false positive check confirms no admin tooling triggers.
