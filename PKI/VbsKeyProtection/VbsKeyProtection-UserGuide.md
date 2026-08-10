# 🔐 VbsKeyProtection.ps1 — Usage Guide

**Script:** VbsKeyProtection.ps1 | **Functions:** 13 | **Version:** 1.0.0
**Platform:** Windows 11 / Server 2025 (build ≥ 26052) with VBS running; Windows PowerShell 5.1 or PowerShell 7+
**Author:** Paulo da Silva | **License:** MIT | **Release:** 1.0.0

> **What is this?** A reusable PowerShell module for the full lifecycle of **VBS** (VBS key protection) CNG keys and the certificates that use them. VBS keys are generated in the *Microsoft Software Key Storage Provider* with the CNG virtual-isolation flag, so the private key lives inside the VBS secure world (VTL1) — **non-exportable** and **device-bound**, resistant to admin/SYSTEM key theft.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Loading the module](#2-loading-the-module)
3. [Quick start (full lifecycle)](#3-quick-start-full-lifecycle)
4. [Test-VbsKeyReady](#4-test-vbskeyready)
5. [New-VbsKey](#5-new-vbskey)
6. [Get-VbsKey](#6-get-vbskey)
7. [Remove-VbsKey](#7-remove-vbskey)
8. [Test-VbsKeyUsable](#8-test-vbskeyusable)
9. [New-VbsKeySelfSignedCertificate](#9-new-vbskeyselfsignedcertificate)
10. [New-VbsKeyCsr](#10-new-vbskeycsr)
11. [Import-VbsKeyPfx](#11-import-vbskeypfx)
12. [Get-VbsKeyVersion](#12-get-vbskeyversion)
13. [Find-CertKeyContainers](#13-find-certkeycontainers)
14. [New-VbsKeyAttestation](#14-new-vbskeyattestation)
15. [Test-VbsKeyAttestation](#15-test-vbskeyattestation)
16. [Attestation workflows (CSR & PFX)](#16-attestation-workflows-csr--pfx)
17. [Notes, gotchas & troubleshooting](#17-notes-gotchas--troubleshooting)

---

## 1. Prerequisites

- **VBS enabled and running** (Windows hypervisor, 64-bit, IOMMU). Verify: `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` → `VirtualizationBasedSecurityStatus = 2`.
- **TPM 2.0** (bare metal) or **vTPM** (VMs) — used to seal the key at rest.
- **UEFI Secure Boot** enabled.
- **Windows build ≥ 26052** (Windows 11 / Server 2025). The feature debuted in that build.
- **Elevation** is required only for *machine-scope* keys (`-Machine` / `-StoreLocation LocalMachine`).
- **PowerShell:** runs on **Windows PowerShell 5.1** (built in to Windows) and **PowerShell 7+**.

`Test-VbsKeyReady` checks the VBS + build prerequisites for you.

## 2. Loading the module

Dot-source the script to load its functions into your session:

```powershell
. C:\Temp\MSHardwareKeysReport\VbsKeyProtection.ps1
```

The script defines a P/Invoke helper type once (guarded, so re-running in the same session is safe) and then exposes the ten functions below. No installation or admin rights are needed just to load it.

## 3. Quick start (full lifecycle)

```powershell
. C:\Temp\MSHardwareKeysReport\VbsKeyProtection.ps1

# 1) Verify prerequisites
if (-not (Test-VbsKeyReady)) { throw "VBS not available on this machine." }

# 2) Create a VBS-isolated key (-Name is optional; auto 'vbs-<GUID>' if omitted)
New-VbsKey -Name 'MyAppKey' -Algorithm RSA -Bits 2048

# 3) List VBS keys (with any associated cert thumbprint)
Get-VbsKey | Format-Table -AutoSize

# 4) Delete when done
Remove-VbsKey -Name 'MyAppKey'
```

Or go straight to a certificate (these create the key for you):

```powershell
# Self-signed cert on a new VBS key
New-VbsKeySelfSignedCertificate -Subject 'CN=app.contoso.com' -KeyName 'AppKey' -DnsName 'app.contoso.com'

# CSR to submit to a CA
New-VbsKeyCsr -Subject 'CN=app.contoso.com,O=Contoso' -KeyName 'AppKey2' -OutputPath .\app.req

# Import an existing PFX so its private key becomes VBS-isolated
$pw = Read-Host -AsSecureString 'PFX password'
Import-VbsKeyPfx -PfxPath .\legacy.pfx -Password $pw
```

---

## 4. Test-VbsKeyReady

Verifies the machine can create VBS keys: VBS running (status 2) and OS build ≥ 26052. Returns `$true`/`$false` and prints a status/warning.

**Parameters:** None.

**Example**

```powershell
if (Test-VbsKeyReady) { "Ready" } else { "VBS not available" }
```

## 5. New-VbsKey

Creates a VBS-isolated RSA or ECC key via CNG P/Invoke.

**Parameters**

| Name | Type / Values | Default | Description |
|------|---------------|---------|-------------|
| `-Name` | string | auto `vbs-<GUID>` | CNG key container name. Optional — if omitted, a unique `vbs-<GUID>` name is generated. |
| `-Algorithm` | RSA, ECDSA_P256/384/521, ECDH_P256/384/521 | RSA | Key algorithm. ECDSA = signing, ECDH = key agreement. |
| `-Bits` | int | 2048 | RSA key size. Valid range **2048–16384**; weaker sizes are rejected. *Ignored for ECC* (curve fixes the size). |
| `-Machine` | switch | off | Create in the machine key store (run elevated). |
| `-PreferFallback` | switch | off | PREFER VBS; fall back to a software key if VBS is unavailable (instead of failing). **The resulting key's isolation is verified**: if it falls back to a non-VBS software key, a *warning* is emitted and the success message reflects the real status — it is never silently reported as VBS-backed. |
| `-Force` | switch | off | Overwrite an existing key of the same name (delete-then-recreate) instead of failing with `NTE_EXISTS`. |

**Examples**

```powershell
New-VbsKey -Name 'RsaKey'                       # RSA 2048 (require VBS)
New-VbsKey                                      # auto name vbs-<GUID>
New-VbsKey -Name 'EccKey' -Algorithm ECDSA_P384 # ECC P-384
New-VbsKey -Name 'RsaKey' -Force                # overwrite if it already exists
New-VbsKey -Name 'MachKey' -Machine             # machine store (elevated)
```

## 6. Get-VbsKey

Lists VBS-isolated keys and, for each, the certificate **thumbprint(s)** that use it. The cert mapping is read from certificate *metadata* (no private-key access), so it never triggers UI prompts.

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-Machine` | switch | off | List machine-store keys (run elevated). Otherwise lists user-store keys. |

**Output:** Objects with `Name`, `Algorithm`, `Scope`, `Thumbprint` (`(none)` if no cert uses the key).

**Examples**

```powershell
Get-VbsKey | Format-Table -AutoSize
Get-VbsKey -Machine | Where-Object Thumbprint -ne '(none)'   # machine keys bound to a cert
```

## 7. Remove-VbsKey

Deletes a VBS key by **container name** (via the .NET `CngKey` API). Irreversible — **prompts to confirm by default** (high-impact `ShouldProcess`); honours `-WhatIf` and `-Confirm:$false`. After a successful delete it re-probes ([Test-VbsKeyUsable](#8-test-vbskeyusable)) and **warns** only if the key unexpectedly still resolves (e.g. a second/residual key).

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-Name` (required) | string | — | CNG key **container** name to delete (e.g. `vbs-<GUID>`) — **not** a certificate thumbprint. Use `Get-VbsKey` to map a thumbprint→container. |
| `-Machine` | switch | off | Machine store (run elevated). Required for `LocalMachine` keys. |
| `-SkipCacheCheck` | switch | off | Skip the post-delete crypto probe / cache warning. |

**Examples**

```powershell
Remove-VbsKey -Name 'MyAppKey'
Remove-VbsKey -Name 'MyAppKey' -WhatIf     # preview only
Remove-VbsKey -Name 'MachKey' -Machine     # elevated / LocalMachine
```

> ⚠️ **Irreversible.** VBS keys are non-exportable — a deleted key cannot be recovered, and any certificate bound to it loses its private key. Rotate/re-issue first.

> **Deletion is immediate.** In testing (Windows build 26200, user *and* machine scope) a deleted key is instantly unobtainable via every path — `CngKey.Open`, `CryptAcquireCertificatePrivateKey` (the API `certutil` uses), and `certutil` itself all fail with `NTE_BAD_KEYSET (0x80090016)`. No cache, no reboot needed. As a safety net the cmdlet re-probes after deletion (`Test-VbsKeyUsable`) and warns only if the key **unexpectedly** still resolves — which would indicate the certificate has a *second / software* key, or that the container you deleted was not the cert's bound key. If you ever see `certutil` still report `Encryption test passed` after deleting a key (note the description flips from `Private key is a VSM key` to `NOT plain text exportable`), look for a second key; a reboot is a safe fallback.

## 8. Test-VbsKeyUsable

Probes whether a VBS key container still **resolves** and can still **perform crypto** (a throwaway test signature that does not change persisted state). Use it to confirm a deletion truly took effect (deletion is immediate, so expect `Resolves=False` right after `Remove-VbsKey`), or to audit whether a key is currently usable.

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-Name` (required) | string | — | CNG key container name (e.g. `vbs-<GUID>`). |
| `-Machine` | switch | off | Machine store (run elevated). |

**Returns**

| Property | Meaning |
|----------|---------|
| `Resolves` | `$true` if the container handle opens (whether persisted or cached). |
| `CryptoUsable` | `$true` if a test signature succeeded — the key can still do crypto. |
| `Detail` | Human-readable outcome (algorithm used, or the failure reason). |

**Examples**

```powershell
# A live key: resolves and can sign
Test-VbsKeyUsable -Name 'vbs-1234abcd-...'
# Resolves     : True
# CryptoUsable : True
# Detail       : RSA test signature succeeded (crypto works)

# After Remove-VbsKey: gone immediately (no reboot needed)
Test-VbsKeyUsable -Name 'vbs-1234abcd-...'
# Resolves     : False
# CryptoUsable : False
# Detail       : does not resolve: Keyset does not exist
```

> **Read-only probe.** It opens the key, signs a fixed test buffer, then disposes the handle — it does not create, modify, or persist anything.

## 9. New-VbsKeySelfSignedCertificate

Creates (or reuses) a VBS key and binds a **self-signed certificate** to it. Returns the certificate object.

**Parameters**

| Name | Type / Values | Default | Description |
|------|---------------|---------|-------------|
| `-Subject` (required) | string | — | Certificate subject, e.g. `CN=app.contoso.com`. |
| `-KeyName` | string | auto `vbs-<GUID>` | CNG container name for the VBS key. Optional — auto-generated if omitted. |
| `-Algorithm` | RSA, ECDSA_P256/384/521 | RSA | Key algorithm (when creating the key). |
| `-Bits` | int | 2048 | RSA size (valid **2048–16384**; weak sizes rejected); ignored for ECC. |
| `-HashAlgorithm` | SHA256/384/512 | SHA256 | Signature hash. |
| `-DnsName` | string[] | — | Subject Alternative Name(s). |
| `-StoreLocation` | CurrentUser / LocalMachine | CurrentUser | Cert store (LocalMachine implies machine key + elevation). |
| `-UseExistingKey` | switch | off | Reuse an existing VBS key instead of creating one. The container is **verified to be VBS-isolated** (`Virtual Iso=1`) before binding *and the bound key is re-verified after the cert is created* (fails closed on a mid-operation container swap) — a non-VBS software key is rejected. |
| `-Force` | switch | off | Overwrite an existing key of the same name when creating (delete-then-recreate). |
| `-RemoveResidualKeyCopies` | switch | off | After binding, delete any leftover *software* copy of the keypair (see [Find-CertKeyContainers](#13-find-certkeycontainers)). Without it, a warning is shown if extra copies exist. |

**Example**

```powershell
New-VbsKeySelfSignedCertificate -Subject 'CN=app.contoso.com' -KeyName 'AppKey' -UseExistingKey
```

## 10. New-VbsKeyCsr

Creates (or reuses) a VBS key and generates a **PKCS#10 CSR** (signed inside VBS) to submit to a CA. After the CA issues the cert, run `certreq -accept <issued.cer>` to marry the returned certificate back to the same VBS key. The returned `.req` file object also carries a `KeyName` property (the container name, including an auto-generated `vbs-<GUID>`) so you can attest the key with [New-VbsKeyAttestation](#14-new-vbskeyattestation).

**Parameters**

| Name | Type / Values | Default | Description |
|------|---------------|---------|-------------|
| `-Subject` (required) | string | — | Certificate subject, e.g. `CN=app.contoso.com,O=Contoso`. |
| `-KeyName` | string | auto `vbs-<GUID>` | CNG container name for the VBS key. Optional — auto-generated if omitted. |
| `-OutputPath` (required) | string | — | Path to write the `.req` (PKCS#10) file. |
| `-Algorithm` | RSA, ECDSA_P256/384/521 | RSA | Key algorithm (when creating the key). |
| `-Bits` | int | 2048 | RSA size (valid **2048–16384**; weak sizes rejected); ignored for ECC. |
| `-HashAlgorithm` | SHA256/384/512 | SHA256 | Signature hash. |
| `-DnsName` | string[] | — | Subject Alternative Name(s). |
| `-Machine` | switch | off | Machine-store key (run elevated). |
| `-UseExistingKey` | switch | off | Reuse an existing VBS key instead of creating one. The container is **verified to be VBS-isolated** (`Virtual Iso=1`) before signing *and re-verified after certreq signs* (fails closed on a mid-operation container swap) — a non-VBS software key is rejected. |
| `-Force` | switch | off | Overwrite an existing key of the same name when creating (delete-then-recreate). |

**Example**

```powershell
New-VbsKeyCsr -Subject 'CN=app.contoso.com,O=Contoso' -KeyName 'AppKey' `
    -OutputPath .\app.req -Algorithm RSA -Bits 2048 -DnsName 'app.contoso.com'

# 1) Submit app.req to your CA.
# 2) When the certificate is issued, bind it back to the SAME VBS key:
certreq -accept .\issued.cer
```

> **Input validation.** `-Subject` and `-KeyName` reject double-quote/CR/LF (INF-injection guard); `-DnsName` values must be host names (allowlist), blocking SAN/INF injection. Internally the module invokes `certreq` via its absolute `%SystemRoot%\System32\certreq.exe` path to prevent PATH-based binary planting.

## 11. Import-VbsKeyPfx

Imports an existing PFX/P12 so its private key becomes **VBS-protected** (VBS-isolated). The private key is never exposed in the clear — it is re-exported as an encrypted PKCS#8 and decrypted *inside* the VBS secure world.

**Parameters**

| Name | Type / Values | Default | Description |
|------|---------------|---------|-------------|
| `-PfxPath` (required) | string | — | Path to the `.pfx` / `.p12` file. |
| `-Password` (required) | securestring | — | PFX password. |
| `-KeyName` | string | auto `vbs-<GUID>` | CNG container name for the imported key. Optional — auto-generated if omitted. |
| `-StoreLocation` | CurrentUser / LocalMachine | CurrentUser | Cert store to install into (LocalMachine implies machine key + elevation). |
| `-MinRsaKeySize` | int | 2048 | Reject an imported RSA key below this size (ECDSA below 256-bit is always rejected), so a weak legacy key can't be migrated into VBS as an isolated-but-weak key. Lower it (e.g. `1024`) only for a deliberate legacy migration. |
| `-Force` | switch | off | Overwrite an existing VBS key of the same name (delete-then-recreate). |
| `-DeleteSourcePfx` | switch | off | After a successful import, **best-effort** overwrite → delete the source PFX. Prompts to confirm (high-impact `ShouldProcess`); respects `-WhatIf` and `-Confirm:$false`. Refuses reparse points, and **binds the delete to the source file's identity** (volume serial + file index) captured at import start — a path/junction swap during the operation is refused. *Single-pass overwrite is defense-in-depth only* — on SSD/copy-on-write/journaling volumes or where VSS snapshots exist, residual bytes may persist; rely on full-disk encryption (e.g. BitLocker). |
| `-RemoveResidualKeyCopies` | switch | off | After import, delete any leftover *software* copy of the keypair (these defeat VBS non-exportability). Without it, a warning is shown if extra copies exist. |

**Output:** The installed `X509Certificate2` (with `HasPrivateKey = $true`) bound to the VBS-isolated key. It also carries a `KeyName` property — the container name (including an auto-generated `vbs-<GUID>`) — so you can attest the key with [New-VbsKeyAttestation](#14-new-vbskeyattestation) without re-deriving it.

**Examples**

```powershell
# Import a PFX (prompt for password); key gets an auto vbs-<GUID> name
$pw = Read-Host -AsSecureString
Import-VbsKeyPfx -PfxPath .\legacy.pfx -Password $pw

# Named key, into the machine store (run elevated)
Import-VbsKeyPfx -PfxPath .\server.pfx -Password $pw -KeyName 'WebTls' -StoreLocation LocalMachine

# Re-import over an existing key of the same name
Import-VbsKeyPfx -PfxPath .\server.pfx -Password $pw -KeyName 'WebTls' -Force

# Import, then securely shred the source PFX (prompts; add -Confirm:$false in automation)
Import-VbsKeyPfx -PfxPath .\server.pfx -Password $pw -DeleteSourcePfx
```

> **How it works:** the private key is never exposed in the clear. The PFX is re-exported as an **encrypted PKCS#8** (under a random one-time password), and that encrypted blob is handed to `NCryptImportKey` with the virtual-isolation flag — Windows decrypts it *inside* the VBS secure world (VTL1). RSA and ECDSA are handled identically (the key type and usage are preserved), and the encrypted material is zeroed from memory after import. The PFX is loaded with `EphemeralKeySet` where the runtime supports it, so **no transient exportable key container is written to disk** (it falls back to an on-disk keyset only on Windows PowerShell 5.1 / older .NET Framework, which cannot re-export an ephemeral key). Because the key stays encrypted end-to-end, this works on both Windows PowerShell 5.1 and PowerShell 7+.

> ⚠️ **Confirmation:** `Import-VbsKeyPfx` is high-impact (`ShouldProcess`), so it **prompts before importing** and fully honors `-WhatIf` (a dry run makes no change — no key, no cert, no PFX load). Pass `-Confirm:$false` for unattended automation.

> ⚠️ Once imported, the key is non-exportable — you cannot get the PFX back out. Keep your original PFX backup in a secure location until you have validated the imported certificate, then use `-DeleteSourcePfx` (or shred it yourself) to remove the exportable copy.

## 12. Get-VbsKeyVersion

Returns the version of this VBS function library so scripts can check what they are running against.

**Output:** A `PSCustomObject` with `Version` (a `[version]` object, so it compares correctly), `ReleaseDate`, and `Author`.

**Examples**

```powershell
Get-VbsKeyVersion
# Version ReleaseDate Author
# ------- ----------- ------
# 1.0.0   Paulo da Silva

# Guard on a minimum version
if ((Get-VbsKeyVersion).Version -lt [version]'1.0.0') { throw 'Update VbsKeyProtection.ps1' }
```

## 13. Find-CertKeyContainers

Audits for **all copies of a certificate's keypair**. It enumerates the VBS KSP and returns every container whose public key matches the cert — VBS *and* plain software — so you can spot **leftover exportable software keys** that survive after you delete the VBS key. Supports **RSA and ECDSA** certificates (RSA matches on modulus, ECDSA on the public point Q).

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-Thumbprint` (required) | string | — | Certificate SHA1 thumbprint (in the `My` store). Must be exactly **40 hex characters** (validated) and is looked up with `-LiteralPath`, so wildcards are not expanded. |
| `-Machine` | switch | off | LocalMachine store/keys (run elevated). |

**Output:** One object per matching container: `Name`, `VBS` (bool), `Exportable` (bool), `ExportPolicy`, `Scope`, `UniqueName`, and `BlobPath` (the on-disk key file).

**Examples**

```powershell
# List every container holding this cert's keypair
Find-CertKeyContainers -Thumbprint 8DBCB6... -Machine

# Purge every non-VBS software copy (keep only the VBS key)
Find-CertKeyContainers -Thumbprint 8DBCB6... -Machine |
    Where-Object { -not $_.VBS } |
    ForEach-Object { Remove-VbsKey -Name $_.Name -Machine }
```

> ⚠️ **Why this matters (security).** A certificate created with a software key first and later "VBS-protected" (re-key or [Import-VbsKeyPfx](#11-import-vbskeypfx)) keeps its original **exportable software key** on disk (machine keys live under `%ProgramData%\Microsoft\Crypto\Keys`, filename = the *Unique container name*). Deleting the VBS key does *not* remove it, and Windows — notably `certutil -repairstore` — will silently re-bind the cert to the surviving software key by public-key match. That defeats VBS's non-exportability. `New-VbsKeySelfSignedCertificate` and `Import-VbsKeyPfx` run this audit automatically and support `-RemoveResidualKeyCopies` to purge the software copies.

## 14. New-VbsKeyAttestation

> ⚠️ **Preview.** VBS key attestation relies on VBS/CNG claim APIs (`NCryptCreateClaim` / `NCryptVerifyClaim` with the `NCRYPT_CLAIM_VBS_*` types) that Microsoft documents as **prerelease — subject to change before general availability**, and it requires very recent Windows builds. Treat `New-VbsKeyAttestation` / `Test-VbsKeyAttestation` / `Get-VbsPublicKeyBlob` as **experimental**; validate on your target build and avoid hard production dependencies until the APIs are finalized.

Produces a **VBS key-attestation claim** — a secure-kernel-signed statement proving that an existing VBS key really is protected inside VBS (VTL1), was **created in isolation**, and is non-exportable. Hand the claim to a relying party (or CA) as cryptographic proof of the key's protection. Refuses keys that are not VBS-isolated.

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-KeyName` (required) | string | — | Name of an existing VBS key to attest. |
| `-Nonce` | byte[] | — | Optional relying-party challenge (1–1024 bytes), embedded in and signed by the claim to prevent replay. If specified it must be **non-empty** — passing an empty/null value errors (so a dropped challenge can't silently disable replay protection). Omit it entirely for a no-challenge claim. |
| `-OutputPath` | string | — | Optional path to also write the raw (binary) claim for out-of-band verification. Honors `-WhatIf`/`-Confirm`. |
| `-Machine` | switch | off | Attest a machine-store key (run elevated). |

**Output:** A `PSCustomObject`: `KeyName`, `KeyAlgorithm` (`RSA`/`ECDSA`/`ECDH`), `ClaimType` (`VBS_ROOT`), `ClaimBytes`, `Nonce` (base64 or `$null`), `Claim` (base64), `ClaimRaw` (byte[]), `PublicKeyBlob` (base64 — hand to a remote verifier), `PublicKeyBlobRaw` (byte[]), `OutputPath`.

**Examples**

```powershell
# Attest a key with a relying-party challenge, save the claim to a file
$nonce = [byte[]](1..16)
$att = New-VbsKeyAttestation -KeyName 'MyAppKey' -Nonce $nonce -OutputPath .\myappkey.claim
$att.Claim           # base64 claim string to send to the verifier
$att.PublicKeyBlob   # base64 public key — send this too for OFF-BOX verification
```

## 15. Test-VbsKeyAttestation

Verifies a claim produced by [New-VbsKeyAttestation](#14-new-vbskeyattestation). It validates the secure-kernel signature and returns the **trustlet details**. Any tampering is detected (invalid signature) and, with `-ExpectedNonce`, the signed challenge is confirmed to match (replay protection). Verify a **local** key by name, or **off-box** (as a remote relying party) from just the subject's public key blob — no private key required. Read-only.

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-KeyName` | string | — | **Local subject.** Opens the key by container name on this machine. |
| `-PublicKeyBlob` | byte[] | — | **Remote subject.** The subject's BCRYPT public key blob (RSA/ECC). |
| `-PublicKeyBlobBase64` | string | — | Same as `-PublicKeyBlob`, base64-encoded (as emitted by `New-VbsKeyAttestation.PublicKeyBlob`). |
| `-CertPath` / `-Certificate` | string / X509Certificate2 | — | **Remote subject.** Extracts the public key from a `.cer` file or cert object (via `Get-VbsPublicKeyBlob`). |
| `-CsrPath` | string | — | **Remote subject.** Extracts the public key from a PKCS#10 `.req` (PS 7.3+). |
| `-ClaimBase64` / `-Claim` / `-ClaimPath` | string / byte[] / string | — | The claim to verify, supplied as base64, raw bytes, or a file path (choose one). |
| `-ExpectedNonce` | byte[] | — | Challenge to confirm; the embedded (signed) nonce must match or the result is `Valid = $false`. Required for `.Accepted` by default (see below). |
| `-AllowMissingChallenge` | switch | off | **Relaxes** the default policy: accept even if no fresh `-ExpectedNonce` was verified (replay risk). |
| `-AllowImportedKey` | switch | off | **Relaxes** the default policy: accept keys not born in VBS (`CreatedInIsolation=$false`, e.g. PFX imports). |
| `-AllowDebuggableTrustlet` | switch | off | **Relaxes** the default policy: accept a debuggable trustlet. |
| `-Machine` | switch | off | Local `-KeyName` subject is in the machine store (run elevated). |

Choose **exactly one** subject (`-KeyName` / `-PublicKeyBlob` / `-PublicKeyBlobBase64` / `-CertPath` / `-Certificate` / `-CsrPath`) and one claim source (`-ClaimBase64` / `-Claim` / `-ClaimPath`).

> 🔒 **`.Accepted` is secure-by-default.** Unlike `.Valid` (raw signature + nonce validity), `.Accepted` is the policy decision a relying party should act on. By default it requires *all* of: a valid claim, a **verified fresh challenge** (`-ExpectedNonce` supplied and matched), **born-in-VBS** (`CreatedInIsolation`), and a **non-debuggable** trustlet. Each requirement can be individually relaxed with the corresponding `-Allow*` switch. A bare verify with no `-ExpectedNonce` yields `Valid=$true` but `Accepted=$false`.

**Output:** A `PSCustomObject`: `Valid` (bool — signature + nonce), `Accepted` (bool — the secure-by-default policy decision), `SubjectSource` (which subject parameter was used), `Status` (hex status code), `Details` (`CreatedInIsolation`, `TrustletId`, `TrustletSecurityVersion`, `TrustletDebuggable`, `KeyFlags`), `EmbeddedNonce` (base64), `NonceMatch`.

**Examples**

```powershell
# Local: verify a claim and confirm the challenge we issued
$r = Test-VbsKeyAttestation -KeyName 'MyAppKey' -ClaimPath .\myappkey.claim -ExpectedNonce $nonce
$r.Valid                        # True
$r.Details.CreatedInIsolation   # True = key was generated inside VBS, never software

# Remote (relying party): verify off-box from just the claim + public key blob
$r = Test-VbsKeyAttestation -PublicKeyBlobBase64 $att.PublicKeyBlob `
        -ClaimBase64 $att.Claim -ExpectedNonce $nonce
$r.SubjectSource   # PublicKeyBlobBase64
```

> **Trust root.** VBS-isolated keys are ultimately anchored in the **TPM**, so a valid claim ties the key to this device's hardware root of trust. `CreatedInIsolation = $true` and `TrustletDebuggable = $false` are the strong-assurance signals.

## 16. Attestation workflows: CSR & PFX

End-to-end recipes for proving to a relying party / CA that a certificate's key is VBS-isolated. The model is **challenge–response**: the **verifier (RA/CA) issues a fresh random nonce**, the **holder (client)** attests its key with that nonce, and the verifier checks the signed claim. Acceptance gates on **all four** of: `Valid`, `NonceMatch`, `Details.CreatedInIsolation`, and `-not Details.TrustletDebuggable`. `Valid = $true` alone is *not* enough — an imported key is also `Valid` (see workflow B).

**RA helper: `Get-VbsPublicKeyBlob`** — extract the subject's public key from the artifact you trust (the issued/target `.cer` or the CSR), never from a blob the client sends alongside the claim. The module provides this as one call (RSA + ECDSA):

```powershell
# from a .cer file (PS 5.1 & 7+), an X509Certificate2 object, or a .req CSR (PS 7.3+)
$pub = Get-VbsPublicKeyBlob -CertPath .\thecert.cer
$pub = Get-VbsPublicKeyBlob -Certificate $cert
$pub = Get-VbsPublicKeyBlob -CsrPath .\app.req
```

`Test-VbsKeyAttestation` also accepts `-CertPath` / `-Certificate` / `-CsrPath` directly and returns a secure-by-default `.Accepted` decision, so the RA check is usually a single call.

### A. Attest a key created via New-VbsKeyCsr (born-in-VBS → ISSUE)

```powershell
# [RA] issue a fresh challenge (store it against the pending request)
$challenge = [byte[]](Get-Random -Count 32 -InputObject (0..255))

# [CLIENT] create the VBS key + CSR, then attest that key with the RA's challenge
$csr = New-VbsKeyCsr -Subject 'CN=app.contoso.com' -OutputPath .\app.req
$att = New-VbsKeyAttestation -KeyName $csr.KeyName -Nonce $challenge
# send app.req + $att.Claim to the RA

# [RA] ONE call: verify against the CSR's own key + challenge. .Accepted is secure by
# default (fresh challenge + born-in-VBS + non-debuggable) -- no policy switches needed.
$r = Test-VbsKeyAttestation -CsrPath .\app.req -Claim $att.ClaimRaw -ExpectedNonce $challenge
if ($r.Accepted) { certreq -submit .\app.req }   # Accepted = True -> ISSUE
```

### B. Attest a key imported via Import-VbsKeyPfx (imported → REJECT)

An imported key *is* genuinely VBS-isolated (`Valid = True`), but the claim reports `CreatedInIsolation = False` because the private key existed as software before import. Because `.Accepted` requires born-in-VBS **by default**, the RA's `.Accepted` is `False` with no extra switches — this is how it *detects* a PFX-origin key. (Pass `-AllowImportedKey` only to deliberately accept it.)

```powershell
# [CLIENT] the key backing an installed cert (from Import-VbsKeyPfx)
$installed = Get-Item 'Cert:\CurrentUser\My\<thumbprint>'
$priv    = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($installed)
$keyName = $priv.Key.KeyName; $priv.Dispose()
$att = New-VbsKeyAttestation -KeyName $keyName -Nonce $challenge

# [RA] ONE call against the .cer (secure default)
$r = Test-VbsKeyAttestation -CertPath .\thecert.cer -Claim $att.ClaimRaw -ExpectedNonce $challenge
$r.Valid      # True  (it IS VBS-isolated now)
$r.Accepted   # False (imported from PFX, not hardware-born) -> REJECT
```

> ⚠️ **Verifier must bind to the request.** Always derive the public key from the CSR/cert tied to the enrollment, not from a blob the client sends with the claim. Because a claim only verifies against its true subject key (swap-resistance), this ties `{request ↔ key ↔ claim ↔ challenge}` together and blocks a client from pairing someone else's valid claim with its own key.

> **AD CS integration.** A stock CA won't run this verification automatically — built-in AD CS key attestation validates **TPM** claims, not VBS. Use a **custom CA policy module** (extract the claim from a request attribute and verify at submission) or an **RA-gated template** (manager approval; an operator/script runs the four checks before approving).

## 17. Notes, gotchas & troubleshooting

- **Non-exportable & device-bound:** VBS keys cannot be backed up or migrated. A lost/reimaged device destroys the key — plan rotation/re-issuance.
- **Require vs. Prefer:** by default keys REQUIRE VBS (fail if unavailable). Use `-PreferFallback` only if a software fallback is acceptable — the module verifies the created key's `Virtual Iso` status and **warns** if it fell back to a non-VBS software key, so a fallback is never silently treated as VBS-protected.
- **RSA vs. ECC size:** `-Bits` applies only to RSA; ECC size comes from the named curve (the module skips the Length property for ECC automatically). RSA `-Bits` is validated to **2048–16384** — requests below 2048 are rejected at parameter binding.
- **Reusing a key requires VBS isolation:** `-UseExistingKey` on `New-VbsKeySelfSignedCertificate` / `New-VbsKeyCsr` verifies the named container is VBS-isolated (`Virtual Iso=1`) before binding. If you point it at a plain software key it throws, so a non-VBS key can never be silently presented as VBS-backed.
- **Binding to a cert uses `-Container`:** under the hood the self-signed path uses `New-SelfSignedCertificate -ExistingKey -Container` (there is no `-KeyName` parameter on that cmdlet).
- **Duplicate key names:** creating/importing a key whose name already exists fails with `NTE_EXISTS (0x8009000F)` and a friendly message. Pass `-Force` to overwrite (delete-then-recreate), or omit `-Name`/`-KeyName` to get a unique `vbs-<GUID>` name.
- **RSA & ECDSA imports:** `Import-VbsKeyPfx` imports the key as an encrypted PKCS#8 that Windows decrypts inside VBS, so both RSA and ECDSA (P-256/384/521) keep their correct key type and usage (ECDSA stays a signing key).
- **Cert deletion may remove the key:** removing a certificate with `-DeleteKey` also deletes the bound VBS key, so a later `Remove-VbsKey` may report "Keyset does not exist" (harmless).
- **certutil still passes after deleting a key?** In testing, deletion is immediate at every layer (`CngKey.Open`, `CryptAcquireCertificatePrivateKey`, and `certutil` all return `NTE_BAD_KEYSET 0x80090016`). If `certutil` still shows `Encryption test passed` for a cert after you deleted its key, that cert most likely has a **second / software key** (note the description flips from `VSM key` to `NOT plain text exportable`), or the container you deleted was not the cert's bound key. Verify with `Test-VbsKeyUsable`; a reboot is a safe fallback.
- **Leftover software key copies:** re-keying or importing can leave OLD copies of a keypair in other containers (often *exportable software* keys) — and `certutil -repairstore` will re-bind the cert to one. Use [`Find-CertKeyContainers`](#13-find-certkeycontainers) to list every copy for a cert and remove the non-VBS ones; `New-VbsKeySelfSignedCertificate` / `Import-VbsKeyPfx` audit this automatically (pass `-RemoveResidualKeyCopies` to purge).
- **CSR pending request:** `certreq -new` leaves a pending request in `Cert:\CurrentUser\REQUEST`; it is consumed by `certreq -accept` when the issued cert returns.
- **Machine scope needs elevation:** `-Machine` / `-StoreLocation LocalMachine` require an elevated PowerShell session.

**Verify a cert's key is VBS-isolated:**

```powershell
$c = Get-Item Cert:\CurrentUser\My\<thumbprint>
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
$rsa.Key.GetProperty("Virtual Iso",[System.Security.Cryptography.CngPropertyOptions]::None).GetValue()[0]
# 1 = VBS
```

---

## Version history

### 1.0.0
Initial public release. Full VBS-isolated key lifecycle (create / list / remove / probe),
certificate and CSR issuance on VBS keys, PFX import into VBS with a minimum-strength gate,
residual software-copy auditing, best-effort secure deletion, and VBS key attestation
(create + verify, local or off-box, with a secure-by-default acceptance policy).

