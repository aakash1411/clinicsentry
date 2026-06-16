# Security Policy

## Supported Versions

ClinicSentry is pre-1.0 software. Only the latest minor release receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.3.x   | yes       |
| < 0.3.0 | no        |

## Reporting a Vulnerability

**Please do not open a public issue for security reports.**

Preferred: use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Report a vulnerability" under the Security tab).

Alternatively, email the maintainer: `skyshah97@gmail.com` with subject line
`[SECURITY] clinicsentry`.

Include:

1. A description of the vulnerability.
2. Steps to reproduce (proof-of-concept code preferred).
3. The affected version and configuration.
4. Your assessment of impact.

We acknowledge receipt within 72 hours and aim to provide a remediation plan within 14 days. Coordinated disclosure window: 90 days from acknowledgement.

## Scope

In scope: code in `src/clinicsentry/` and the published Python distribution.

Out of scope (see ADR-0014):

- Attacks requiring local-user or root access on the host.
- Side channels in the underlying Python runtime or OpenSSL.
- DoS via resource exhaustion (rate limit at ingress).
- LLM provider behavior — we are middleware, not an LLM.

PHI-detection bypasses (inputs that evade redaction on the production
`PHIFirewall.scan` path) **are in scope** and treated as vulnerabilities, not
model-quality issues.

## Recognition

Researchers acting in good faith and adhering to this policy will be credited in `SECURITY-HALL-OF-FAME.md` (created on first valid report).
