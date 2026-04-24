<!-- Pentra Banner -->

<p align="center">
  <img src="https://raw.githubusercontent.com/ByteBeem/pentra/main/pentra-banner.png" alt="Pentra Banner" />
</p>

# Security Policy

## Supported Versions

Pentra is actively evolving. Security updates are only guaranteed for the latest stable releases.

| Version                 | Supported       |
| ----------------------- | --------------- |
| Latest (main)           | Supported       |
| Previous minor versions | Limited Support |
| Legacy versions         | Not Supported   |

Important: Due to the security-sensitive nature of penetration testing tools, running outdated versions may expose you to vulnerabilities or inaccurate results. Always use the latest release.

---

## Reporting a Vulnerability

Pentra is a security tool, so its own security is critical.

If you discover a vulnerability in Pentra itself (not in scanned targets), please report it responsibly.

### Contact

Email: [contact@mxolisi.dev](mailto:contact@mxolisi.dev)

---

## What to Include

To help us investigate efficiently, include:

* Type of issue (e.g., memory safety flaw, remote code execution, privilege escalation, data leak)
* Affected component (scanner, CLI, plugin system, etc.)
* Clear reproduction steps
* Proof-of-concept (code, payload, or logs)
* Impact assessment (what an attacker could achieve)

---

## Response Timeline

* Initial response: within 24–48 hours
* Triage and validation: within 2–5 days
* Fix and patch release: depends on severity

Critical vulnerabilities are prioritized immediately.

---

## Vulnerability Handling Process

### If Accepted

* The issue is confirmed and classified by severity
* A fix is developed and tested
* A patch is released in a new version
* Public disclosure may follow after remediation
* Reporter credit is given (optional)

### If Declined

* A clear explanation will be provided
* Suggestions may be given if the issue is out of scope

---

## Scope

This policy applies only to vulnerabilities in Pentra itself, including:

* Core engine
* CLI interface
* Plugin system
* Internal networking logic

It does not apply to:

* Vulnerabilities discovered on targets using Pentra
* Misuse of the tool
* Third-party integrations or external scripts

---

## Responsible Disclosure

We expect researchers to:

* Avoid public disclosure before a fix is released
* Not exploit vulnerabilities beyond proof-of-concept
* Avoid accessing or modifying user data
* Provide reasonable time for remediation

---

## Legal and Ethical Use

Pentra is built for authorized penetration testing only.

We do not support or condone:

* Unauthorized scanning
* Illegal intrusion
* Abuse of the platform

Any misuse of Pentra is the sole responsibility of the user.

---

## Commitment

We are committed to maintaining a secure, memory-safe codebase (Rust-first approach), rapidly addressing vulnerabilities, and building trust with the security community.

---
