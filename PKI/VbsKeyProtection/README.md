# VbsKeyProtection

A single-file PowerShell module for managing **VBS-isolated (Virtualization-Based Security) CNG keys** on Windows, the certificates that use them, and **attesting** that a key is genuinely hardware-protected.

Windows can generate CNG keys inside VBS (VTL1), so the private key lives in the secure world: **non-exportable** and **device-bound**, resistant to theft even by an admin/SYSTEM-level attacker or memory-scraping malware. This module wraps that whole lifecycle in friendly cmdlets.

> Works on **Windows PowerShell 5.1** and **PowerShell 7+**. No external dependencies — just dot-source the script.

> ⚠️ **Preview.** Windows **VBS key attestation** (`New-VbsKeyAttestation` / `Test-VbsKeyAttestation` / `Get-VbsPublicKeyBlob`) relies on VBS/CNG claim APIs (`NCryptCreateClaim` / `NCryptVerifyClaim` with the `NCRYPT_CLAIM_VBS_*` types) that Microsoft documents as **prerelease — subject to change before general availability** — and it requires very recent Windows builds. Treat attestation as **experimental**: validate it on your target build and avoid hard production dependencies until the APIs are finalized. The core key-lifecycle functions run on supported builds (≥ 26052).

## Requirements

- Windows 11 or Windows Server 2025, **build ≥ 26052**
- **VBS running**, **TPM 2.0**, **UEFI Secure Boot**
- `Test-VbsKeyReady` verifies all of this for you.

## Quick start

```powershell
. .\VbsKeyProtection.ps1

if (Test-VbsKeyReady) {
    New-VbsKey -Name 'MyAppKey' -Algorithm RSA -Bits 2048
    Get-VbsKey | Format-Table -AutoSize
}
```

## Functions

| Function | Purpose |
|----------|---------|
| `Test-VbsKeyReady` | Verify the VBS prerequisites are met |
| `New-VbsKey` | Create a VBS-isolated RSA or ECC key |
| `Get-VbsKey` | List VBS keys and any bound certificate thumbprint(s) |
| `Remove-VbsKey` | Delete a VBS key |
| `Test-VbsKeyUsable` | Probe whether a key still resolves and can sign |
| `New-VbsKeySelfSignedCertificate` | Create/reuse a VBS key and bind a self-signed cert |
| `New-VbsKeyCsr` | Create/reuse a VBS key and generate a PKCS#10 CSR for a CA |
| `Import-VbsKeyPfx` | Import an existing PFX so its private key becomes VBS-isolated |
| `Find-CertKeyContainers` | List every container holding a cert's keypair (spot leftover software copies) |
| `New-VbsKeyAttestation` | Produce a VBS attestation claim proving a key is VBS-isolated |
| `Test-VbsKeyAttestation` | Verify a VBS attestation claim (secure-kernel signature + trustlet details) |
| `Get-VbsPublicKeyBlob` | Extract a subject public key blob from a cert or CSR (for remote verify) |
| `Get-VbsKeyVersion` | Report the module version |

See **[VbsKeyProtection-UserGuide.md](VbsKeyProtection-UserGuide.md)** (or the HTML version) for full parameter details and examples.

## Key attestation

> ⚠️ **Preview feature** — see the note above. The attestation APIs may change before GA.

An attestation claim is a **secure-kernel-signed statement** (rooted in the TPM) proving a key is VBS-isolated, and reports whether it was **born in VBS** (`CreatedInIsolation`) vs imported. A relying party / CA can verify it — locally or off-box — with a challenge to prevent replay:

```powershell
# Attestor: create a CSR + attestation for its key, using the verifier's challenge
$csr = New-VbsKeyCsr -Subject 'CN=app.contoso.com' -OutputPath .\app.req
$att = New-VbsKeyAttestation -KeyName $csr.KeyName -Nonce $challenge
# send app.req + $att.Claim to the verifier

# Verifier (relying party / RA): one call, secure by default
$r = Test-VbsKeyAttestation -CsrPath .\app.req -Claim $att.ClaimRaw -ExpectedNonce $challenge
if ($r.Accepted) { <# issue the cert #> }
```

`.Accepted` is **secure-by-default**: it requires a valid signature **and** a verified fresh challenge **and** born-in-VBS **and** a non-debuggable trustlet. Relax individual requirements only with `-AllowMissingChallenge` / `-AllowImportedKey` / `-AllowDebuggableTrustlet`. (`.Valid` is the raw signature/nonce validity.)

> **AD CS note:** built-in AD CS key attestation validates **TPM** claims, not VBS. To gate enrollment on a VBS claim, run this verification in a custom CA policy module or an RA-gated (manager-approval) template.

## Security notes

- VBS keys are **non-exportable and device-bound** — plan **rotation/re-issue**, not key backup or migration between machines.
- `Import-VbsKeyPfx` enforces a **minimum key strength** (RSA ≥ 2048 via `-MinRsaKeySize`, ECDSA ≥ 256) and audits for leftover exportable software copies of the keypair.
- Secure-delete of a source PFX (`-DeleteSourcePfx`) is **best-effort**; on SSD/copy-on-write/journaling volumes or where VSS snapshots exist, rely on full-disk encryption (e.g. BitLocker).
- **Known limitation (Low):** on Windows PowerShell 5.1 only, `Import-VbsKeyPfx` falls back to a persisted exportable key set for the re-export step; a hard crash mid-import could orphan a software key container. PowerShell 7+ is unaffected.

## Testing

`Test-VbsKeyProtection.ps1` is a self-contained, self-cleaning regression suite that exercises every function on a VBS-capable host:

```powershell
.\Test-VbsKeyProtection.ps1
```

## License

[MIT](LICENSE)
