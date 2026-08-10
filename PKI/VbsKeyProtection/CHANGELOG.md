# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0]

### Added
- Initial public release.
- VBS-isolated CNG key lifecycle: `Test-VbsKeyReady`, `New-VbsKey`, `Get-VbsKey`, `Remove-VbsKey`, `Test-VbsKeyUsable`.
- Certificate and CSR issuance on VBS keys: `New-VbsKeySelfSignedCertificate`, `New-VbsKeyCsr`.
- PFX import into VBS with a minimum-strength gate (`-MinRsaKeySize`): `Import-VbsKeyPfx`.
- Residual software-copy auditing for a certificate's keypair: `Find-CertKeyContainers`.
- VBS key attestation — create and verify (local or off-box), with a secure-by-default
  acceptance policy: `New-VbsKeyAttestation`, `Test-VbsKeyAttestation`, `Get-VbsPublicKeyBlob`.
- `Get-VbsKeyVersion`.
- Self-contained regression suite: `Test-VbsKeyProtection.ps1`.

[1.0.0]: https://github.com/pasilva-msft/VbsKeyProtection/releases/tag/v1.0.0
