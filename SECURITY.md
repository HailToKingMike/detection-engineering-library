# Security Policy

## Supported Versions

This library is actively maintained. Detection rules, CI/CD pipelines,
and supporting scripts in the `main` branch receive security updates.

| Branch | Supported |
|--------|-----------|
| main | ✅ Active |
| older commits | ❌ Not supported |

---

## Reporting a Vulnerability

Imperium Defense LLC takes security seriously. If you discover a
vulnerability in this repository — including issues with the DLP gate,
CI/CD pipeline, detection logic, or any supporting scripts — please
report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

Email: **security@imperiumdefense.com**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested remediation (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| 48 hours | Acknowledgment of your report |
| 7 days | Initial assessment and severity classification |
| 30 days | Remediation or documented mitigation |
| 90 days | Public disclosure (coordinated with reporter) |

We follow responsible disclosure principles. Reporters who follow this
process will be credited in the remediation commit unless anonymity
is requested.

---

## Scope

### In Scope

- Vulnerabilities in `scripts/dlp_gate.py` that could allow sensitive
  data to pass through CI/CD validation
- Logic errors in `sigma-validation.yml` that could allow malformed
  or malicious rules to merge undetected
- Security issues in `coverage-update.yml` that could allow
  unauthorized writes to the repository
- Detection logic bypasses in Sigma rules that could cause
  known-malicious behavior to evade detection

### Out of Scope

- Theoretical vulnerabilities without proof of concept
- Issues in third-party dependencies (report directly to maintainers
  of pySigma, GitHub Actions, etc.)
- Rules failing to detect novel, undiscovered techniques
  (these are detection gaps, not vulnerabilities — open an issue)

---

## Detection Rule Quality Issues

If you find a detection rule that produces excessive false positives,
misses a documented technique variant, or has a logic error — these
are **not security vulnerabilities**. Open a standard GitHub issue
using the Rule Submission template.

---

## Recognition

Imperium Defense LLC maintains a list of security researchers who have
responsibly disclosed vulnerabilities. Contributors will be acknowledged
in the repository unless anonymity is requested.

---

*Imperium Defense LLC — imperiumdefense.com*
