# Detection Family: Credential Access

Covers all techniques targeting credential theft beyond identity (handles LSASS, Kerberoasting,
DCSync, and password spraying). Complements the Identity Abuse family which focuses on
authentication-layer attacks (MFA, token theft, impossible travel).

## Hypotheses Covered

| Hypothesis | Technique | Status |
|-----------|-----------|--------|
| DH-001 | T1003.001 LSASS Credential Dumping | Backlog |
| DH-002 | T1558.003 Kerberoasting | Backlog |
| DH-007 | T1003.006 DCSync | Backlog |
| DH-010 | T1110.003 Password Spraying | Backlog |

## Rules in This Family

- `sigma/windows/credential_access/lsass_dump_rundll32.yml`
- `sigma/windows/credential_access/lsass_access_sysmon.yml`
- `sigma/windows/credential_access/kerberoasting_rc4_ticket.yml`
- `sigma/windows/credential_access/dcsync_non_dc_source.yml`
- `sigma/windows/credential_access/password_spray_multiple_accounts.yml`

## Lab Notes

DH-002 requires a service account with SPN in `corp.lab`. Create before testing:
```
setspn -A MSSQLSvc/lab-dc-01:1433 lab-svc-sql
```
Use a weak password for realistic offline cracking simulation.
