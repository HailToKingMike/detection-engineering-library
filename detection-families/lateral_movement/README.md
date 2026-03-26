# Detection Family: Lateral Movement

Covers attacker movement between systems after initial foothold.

## Hypotheses Covered

| Hypothesis | Technique | Status |
|-----------|-----------|--------|
| DH-004 | T1550.002 Pass-the-Hash | Backlog |
| DH-003 | T1087/T1069 AD Enumeration (precursor) | Backlog |

## Rules in This Family

- `sigma/windows/lateral_movement/pass_the_hash_ntlm.yml`
- `sigma/windows/discovery/ad_enumeration_ldap.yml`

## Key Correlation

Pass-the-hash is most valuable when correlated with preceding AD enumeration.
EQL sequence rule target (Phase 3 detection engineering):

```eql
sequence by host.name with maxspan=30m
  [process where process.name == "net.exe" and
   process.command_line like "*group /domain*"]
  [authentication where event.action == "logged-in" and
   winlog.logon.type == "Network" and
   winlog.logon.auth_package == "NTLM" and
   source.ip != "127.0.0.1"]
```
