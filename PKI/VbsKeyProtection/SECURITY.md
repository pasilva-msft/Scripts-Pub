# Security Policy

## Supported versions

The latest released version receives security fixes.

## Reporting a vulnerability

Please report suspected security vulnerabilities **privately** using GitHub's
**"Report a vulnerability"** button under this repository's **Security** tab
(Private Vulnerability Reporting). **Do not** open a public issue for security reports.

When reporting, please include:

- the affected version,
- a clear description of the issue,
- reproduction steps, and
- the potential impact.

Reports will be acknowledged promptly, and a fix and coordinated disclosure will follow.

## Design notes relevant to security

- Keys created by this module are **non-exportable and device-bound** by design; deleting a
  VBS key is **irreversible** (rotate/re-issue rather than attempting recovery).
- `Import-VbsKeyPfx` enforces a minimum imported-key strength and audits for leftover
  exportable software copies of the keypair.
- Attestation verification (`Test-VbsKeyAttestation`) is **secure-by-default**: `.Accepted`
  requires a verified fresh challenge, a born-in-VBS key, and a non-debuggable trustlet.
- Known limitation (Low): on Windows PowerShell 5.1 only, `Import-VbsKeyPfx` falls back to a
  persisted exportable key set for the re-export step; a hard crash mid-import could orphan a
  software key container. PowerShell 7+ is unaffected. See the README for details.
