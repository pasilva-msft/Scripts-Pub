<#
.SYNOPSIS
    Create and manage Windows VBS-isolated (Virtualization-Based Security) CNG keys and the
    certificates that use them, and attest that a key is genuinely hardware-protected.

.DESCRIPTION
    Windows can generate CNG keys inside Virtualization-Based Security (VTL1), so the private
    key lives in the VBS secure world: non-exportable and device-bound, resistant to theft
    even by an admin/SYSTEM-level attacker. This module wraps the full lifecycle:

        Test-VbsKeyReady                   - verify the VBS prerequisites are met
        New-VbsKey                         - create a VBS-isolated RSA or ECC key
        Get-VbsKey                         - list VBS keys and any bound certificate thumbprint(s)
        Remove-VbsKey                      - delete a VBS key
        Test-VbsKeyUsable                  - probe whether a key still resolves and can sign
        New-VbsKeySelfSignedCertificate    - create/reuse a VBS key and bind a self-signed cert
        New-VbsKeyCsr                      - create/reuse a VBS key and generate a PKCS#10 CSR for a CA
        Import-VbsKeyPfx                   - import an existing PFX so its private key becomes VBS-isolated
        Find-CertKeyContainers             - list every container holding a cert's keypair (spot software copies)
        New-VbsKeyAttestation              - produce a VBS attestation claim proving a key is VBS-isolated
        Test-VbsKeyAttestation             - verify a VBS attestation claim (secure-kernel signature + details)
        Get-VbsPublicKeyBlob               - extract a subject public key blob from a cert or CSR (for remote verify)
        Get-VbsKeyVersion                  - report the module version

    Keys are created in the Microsoft Software Key Storage Provider with the CNG
    virtual-isolation flag. Verified on Windows 11 / Windows Server 2025 (build >= 26052)
    with VBS running. Runs on Windows PowerShell 5.1 (.NET Framework) and PowerShell 7+.

.EXAMPLE
    . .\VbsKeyProtection.ps1
    if (Test-VbsKeyReady) {
        New-VbsKey -Name 'MyAppKey' -Algorithm RSA -Bits 2048
        Get-VbsKey | Format-Table -AutoSize
    }

.EXAMPLE
    # Self-signed certificate on a new VBS key
    New-VbsKeySelfSignedCertificate -Subject 'CN=app.contoso.com' -Algorithm ECDSA_P256 -DnsName 'app.contoso.com'

.EXAMPLE
    # CSR to submit to a CA (creates the VBS key too), then attest that key
    $csr = New-VbsKeyCsr -Subject 'CN=app.contoso.com' -OutputPath .\app.req
    $att = New-VbsKeyAttestation -KeyName $csr.KeyName -Nonce $challenge

.EXAMPLE
    # Import an existing PFX so its private key becomes VBS-isolated
    Import-VbsKeyPfx -PfxPath .\mycert.pfx -Password (Read-Host -AsSecureString) -KeyName 'ImportedAppKey'

.NOTES
    Author  : Paulo da Silva
    Version : 1.0.0
    License : MIT

    Requirements: Windows 11 / Windows Server 2025 (build >= 26052), VBS running, TPM 2.0,
    UEFI Secure Boot. Test-VbsKeyReady verifies this for you. Deleting a non-exportable key
    is IRREVERSIBLE -- rotate/re-issue instead of trying to recover it.

    PREVIEW: Windows VBS *key attestation* (New-VbsKeyAttestation / Test-VbsKeyAttestation /
    Get-VbsPublicKeyBlob) uses VBS/CNG claim APIs (NCryptCreateClaim / NCryptVerifyClaim with
    the NCRYPT_CLAIM_VBS_* types) that Microsoft documents as PRERELEASE and subject to change
    before general availability, and it requires very recent Windows builds. Treat the
    attestation features as experimental and validate them on your target build; the core key
    lifecycle (create/list/remove/cert/CSR/import) is supported on build >= 26052.

    Known limitation (LOW): on Windows PowerShell 5.1 only, Import-VbsKeyPfx cannot use an
    ephemeral key set for the re-export step and falls back to a persisted, exportable key
    set; a hard process crash between load and disposal could orphan an exportable software
    key container. PowerShell 7+ (the primary target) is unaffected. Mitigate on 5.1 with
    full-disk encryption; the post-import residual-key audit removes leftovers on success.

    Version history
    ---------------
    1.0.0  - Initial public release.
#>

# ---------------------------------------------------------------------------
# P/Invoke definitions (loaded once per session). Guarded so re-running the
# script in the same session does not error on a duplicate type.
# ---------------------------------------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'VbsNative').Type) {
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class VbsNative {
  // NCryptEnumKeys returns a pointer to this structure for each key
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct NCryptKeyName { public IntPtr pszName; public IntPtr pszAlgid; public uint dwLegacyKeySpec; public uint dwFlags; }

  // CERT_KEY_PROV_INFO_PROP_ID metadata: tells us which provider + container a cert uses
  // (read WITHOUT opening the private key, so no UI prompts / no hangs)
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CRYPT_KEY_PROV_INFO {
    public string pwszContainerName; public string pwszProvName;
    public uint dwProvType; public uint dwFlags; public uint cProvParam;
    public IntPtr rgProvParam; public uint dwKeySpec;
  }

  // Parameter buffers used to pass the key name into NCryptImportKey
  [StructLayout(LayoutKind.Sequential)]
  public struct NCryptBuffer { public uint cbBuffer; public uint BufferType; public IntPtr pvBuffer; }
  [StructLayout(LayoutKind.Sequential)]
  public struct NCryptBufferDesc { public uint ulVersion; public uint cBuffers; public IntPtr pBuffers; }

  // Used by Remove-VbsKeyFileSecurely to validate file identity on an OPEN handle
  // (reparse-point detection) and to delete via that same handle, eliminating the
  // check/use (TOCTOU) window that a separate path-based check + open would leave.
  [StructLayout(LayoutKind.Sequential, Pack=4)]
  public struct BY_HANDLE_FILE_INFORMATION {
    public uint dwFileAttributes; public long ftCreationTime; public long ftLastAccessTime; public long ftLastWriteTime;
    public uint dwVolumeSerialNumber; public uint nFileSizeHigh; public uint nFileSizeLow; public uint nNumberOfLinks;
    public uint nFileIndexHigh; public uint nFileIndexLow;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct FILE_DISPOSITION_INFO { public byte DeleteFile; }

  [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr p,string n,uint f);
  [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] public static extern int NCryptCreatePersistedKey(IntPtr p,out IntPtr k,string alg,string name,uint spec,uint f);
  [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] public static extern int NCryptImportKey(IntPtr hProvider,IntPtr hImportKey,string pszBlobType,IntPtr pParameterList,out IntPtr phKey,byte[] pbData,uint cbData,uint dwFlags);
  [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] public static extern int NCryptSetProperty(IntPtr o,string prop,byte[] v,uint cb,uint f);
  [DllImport("ncrypt.dll")] public static extern int NCryptFinalizeKey(IntPtr k,uint f);
  [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] public static extern int NCryptEnumKeys(IntPtr p,[MarshalAs(UnmanagedType.LPWStr)]string scope,out IntPtr ppKeyName,ref IntPtr ppState,uint f);
  [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] public static extern int NCryptOpenKey(IntPtr p,out IntPtr k,string name,uint spec,uint f);
  [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)] public static extern int NCryptGetProperty(IntPtr o,string prop,byte[] outv,uint cb,out uint res,uint f);
  [DllImport("ncrypt.dll")] public static extern int NCryptFreeObject(IntPtr o);
  [DllImport("ncrypt.dll")] public static extern int NCryptFreeBuffer(IntPtr b);
  // VBS key attestation: produce/verify a secure-kernel-signed claim that a key is VBS-isolated.
  [DllImport("ncrypt.dll")] public static extern int NCryptCreateClaim(IntPtr hSubjectKey,IntPtr hAuthorityKey,uint dwClaimType,IntPtr pParameterList,byte[] pbClaimBlob,uint cbClaimBlob,out uint pcbResult,uint dwFlags);
  [DllImport("ncrypt.dll")] public static extern int NCryptVerifyClaim(IntPtr hSubjectKey,IntPtr hAuthorityKey,uint dwClaimType,IntPtr pParameterList,byte[] pbClaimBlob,uint cbClaimBlob,IntPtr pOutput,uint dwFlags);
  [DllImport("crypt32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool CertGetCertificateContextProperty(IntPtr ctx,uint propId,IntPtr pvData,ref uint pcbData);

  // Handle-based file APIs for atomic (race-free) secure delete.
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  public static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
  [DllImport("kernel32.dll",SetLastError=true)]
  public static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);
  [DllImport("kernel32.dll",SetLastError=true)]
  public static extern bool SetFileInformationByHandle(SafeFileHandle hFile, int FileInformationClass, ref FILE_DISPOSITION_INFO lpFileInformation, uint dwBufferSize);
}
'@
}

# Provider that hosts VBS keys (VBS flag is applied at key creation).
$script:VbsProvider = 'Microsoft Software Key Storage Provider'

# Single source of truth for this library's version (kept in sync with the
# .NOTES version history above). Surfaced at runtime via Get-VbsKeyVersion.
$script:VbsKeyVersion     = '1.0.0'
$script:VbsKeyReleaseDate = '2026-07-24'

# ===========================================================================
# Get-VbsKeyVersion: report the version of this VBS function library.
# Returns a version object so callers can compare (e.g. -ge [version]'1.1.0').
# ===========================================================================
function Get-VbsKeyVersion {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    [PSCustomObject]@{
        Version     = [version]$script:VbsKeyVersion
        ReleaseDate = $script:VbsKeyReleaseDate
        Author      = 'Paulo da Silva'
    }
}

# ---------------------------------------------------------------------------
# Remove-VbsKeyFileSecurely (internal): best-effort secure delete of a file
# that held key material. Overwrites the contents with cryptographically
# random bytes, flushes to disk, then removes the file.
# NOTE: On SSDs / wear-leveling / copy-on-write or journaling file systems,
# an in-place overwrite cannot guarantee the original bytes are unrecoverable.
# Treat this as defense-in-depth, not a guaranteed forensic wipe.
# ---------------------------------------------------------------------------
function Remove-VbsKeyFileSecurely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        # Optional expected file identity (volume serial + NTFS file index) captured
        # BEFORE the operation, so we can refuse if the path now resolves to a different
        # file (e.g. a parent-directory junction swap) -- closes the residual TOCTOU.
        [switch]$VerifyIdentity,
        [uint32]$ExpectedVolumeSerial,
        [uint32]$ExpectedFileIndexHigh,
        [uint32]$ExpectedFileIndexLow
    )

    # Open the file ONCE and do everything (identity check, overwrite, delete) on that
    # single handle, so there is no path re-resolution a local attacker could race
    # (TOCTOU / CWE-367). FILE_FLAG_OPEN_REPARSE_POINT means that if the final path
    # component is a symlink/junction we get a handle to the LINK itself, which we then
    # reject via GetFileInformationByHandle -- a normal file ignores the flag. Deletion
    # is requested on the same handle (SetFileInformationByHandle), never by path.
    # NOTE: a junction on a PARENT directory is still followed by the OS during path
    # resolution; keep PFX files in a directory only you can write to.
    $GENERIC_WRITE = [uint32]0x40000000; $DELETE = [uint32]0x00010000
    $OPEN_EXISTING = [uint32]3
    $FILE_FLAG_OPEN_REPARSE_POINT = [uint32]0x00200000
    $FILE_ATTRIBUTE_REPARSE_POINT = [uint32]0x00000400
    $FileDispositionInfo = 4

    $h = [VbsNative]::CreateFileW($Path, ($GENERIC_WRITE -bor $DELETE), [uint32]0, [IntPtr]::Zero,
                            $OPEN_EXISTING, $FILE_FLAG_OPEN_REPARSE_POINT, [IntPtr]::Zero)
    if ($h.IsInvalid) {
        $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Could not open '$Path' for secure delete (Win32 error $e)."
    }
    $ownedByStream = $false
    try {
        # Validate identity on the OPEN handle (not by re-reading the path).
        $info = New-Object VbsNative+BY_HANDLE_FILE_INFORMATION
        if (-not [VbsNative]::GetFileInformationByHandle($h, [ref]$info)) {
            $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Could not query '$Path' for secure delete (Win32 error $e)."
        }
        if ($info.dwFileAttributes -band $FILE_ATTRIBUTE_REPARSE_POINT) {
            throw "Refusing to securely delete '$Path': it is a reparse point (symlink/junction)."
        }
        # Bind to the originally-captured file identity: if the path now resolves to a
        # different file (parent-directory junction/path swap), refuse.
        if ($VerifyIdentity -and (
                $info.dwVolumeSerialNumber -ne $ExpectedVolumeSerial -or
                $info.nFileIndexHigh -ne $ExpectedFileIndexHigh -or
                $info.nFileIndexLow -ne $ExpectedFileIndexLow)) {
            throw "Refusing to securely delete '$Path': file identity changed since import (possible path/junction swap)."
        }
        [int64]$len = ([int64]$info.nFileSizeHigh -shl 32) -bor ([int64]$info.nFileSizeLow -band 0xFFFFFFFF)

        # Overwrite with cryptographically random bytes via a FileStream that wraps the
        # SAME validated handle; the stream takes ownership and closes it on Dispose.
        $fs = [System.IO.FileStream]::new($h, [System.IO.FileAccess]::Write)
        $ownedByStream = $true
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            if ($len -gt 0) {
                $chunk = New-Object byte[] ([int][Math]::Min([int64]65536, $len))
                [int64]$written = 0
                while ($written -lt $len) {
                    $toWrite = [int][Math]::Min([int64]$chunk.Length, $len - $written)
                    $rng.GetBytes($chunk)
                    $fs.Write($chunk, 0, $toWrite)
                    $written += $toWrite
                }
                $fs.Flush($true)
            }
            # Mark for deletion on the same handle; closing the stream (below) deletes it.
            $disp = New-Object VbsNative+FILE_DISPOSITION_INFO
            $disp.DeleteFile = [byte]1
            $sz = [System.Runtime.InteropServices.Marshal]::SizeOf([type]([VbsNative+FILE_DISPOSITION_INFO]))
            if (-not [VbsNative]::SetFileInformationByHandle($h, $FileDispositionInfo, [ref]$disp, [uint32]$sz)) {
                $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Overwrote but could not delete '$Path' (Win32 error $e)."
            }
        } finally {
            $rng.Dispose()
            $fs.Dispose()   # closes the handle -> deletion (set above) takes effect
        }
    } finally {
        if (-not $ownedByStream -and -not $h.IsInvalid) { $h.Dispose() }
    }
}

# ---------------------------------------------------------------------------
# Get-VbsKeyFileIdentity (internal): return a file's identity (volume serial +
# NTFS file index) via an open handle. Captured before an operation so a later
# secure-delete can verify the path still resolves to the SAME file and refuse a
# parent-directory junction / path swap (TOCTOU). Opens with a shared, read-only
# handle so it does not block the importer, and with FILE_FLAG_OPEN_REPARSE_POINT
# so the check matches Remove-VbsKeyFileSecurely's final-component semantics.
# ---------------------------------------------------------------------------
function Get-VbsKeyFileIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $FILE_READ_ATTRIBUTES = [uint32]0x0080   # enough for GetFileInformationByHandle; avoids GENERIC_READ (0x80000000) int overflow
    $SHARE_ALL    = [uint32]7   # READ | WRITE | DELETE
    $OPEN_EXISTING = [uint32]3
    $FILE_FLAG_OPEN_REPARSE_POINT = [uint32]0x00200000
    $h = [VbsNative]::CreateFileW($Path, $FILE_READ_ATTRIBUTES, $SHARE_ALL, [IntPtr]::Zero,
                            $OPEN_EXISTING, $FILE_FLAG_OPEN_REPARSE_POINT, [IntPtr]::Zero)
    if ($h.IsInvalid) {
        $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Could not open '$Path' to capture file identity (Win32 error $e)."
    }
    try {
        $info = New-Object VbsNative+BY_HANDLE_FILE_INFORMATION
        if (-not [VbsNative]::GetFileInformationByHandle($h, [ref]$info)) {
            $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Could not query identity of '$Path' (Win32 error $e)."
        }
        [pscustomobject]@{ Vol = $info.dwVolumeSerialNumber; IdxHigh = $info.nFileIndexHigh; IdxLow = $info.nFileIndexLow }
    } finally {
        $h.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Get-VbsKeyShroudedKey (internal): scan PKCS#12 bytes for the first
# pkcs8ShroudedKeyBag and return its EncryptedPrivateKeyInfo (an encrypted
# PKCS#8 blob). Used by Import-VbsKeyPfx to hand the still-encrypted key to
# NCryptImportKey. Only a DER walk is needed -- the key stays encrypted.
# ---------------------------------------------------------------------------
function Get-VbsKeyShroudedKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Pkcs12Bytes)

    # OID 1.2.840.113549.1.12.10.1.2 (pkcs8ShroudedKeyBag) as a DER OID TLV.
    $oid = [byte[]](0x06,0x0B,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x0C,0x0A,0x01,0x02)
    $b   = $Pkcs12Bytes
    for ($i = 0; $i -le $b.Length - $oid.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $oid.Length; $j++) { if ($b[$i+$j] -ne $oid[$j]) { $match = $false; break } }
        if (-not $match) { continue }

        # SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ... }
        # The OID is immediately followed by the [0] (0xA0) wrapping an
        # EncryptedPrivateKeyInfo SEQUENCE.
        $k = $i + $oid.Length
        if ($k -ge $b.Length -or $b[$k] -ne 0xA0) { continue }
        $k++
        $first = $b[$k]; $k++
        if ($first -lt 0x80) { $len = [int]$first }
        else {
            $n = $first -band 0x7F; $len = 0
            if ($n -lt 1 -or $n -gt 4) { continue }
            for ($x = 0; $x -lt $n; $x++) { $len = ($len * 256) + $b[$k]; $k++ }
        }
        if ($len -le 0 -or ($k + $len) -gt $b.Length) { continue }
        return ,$b[$k..($k + $len - 1)]     # EncryptedPrivateKeyInfo TLV
    }
    return $null
}

# ===========================================================================
# Test-VbsKeyReady: verify prerequisites before creating a VBS key.
# VBS (VBS key protection) requires VBS *running* and a recent OS build.
# ===========================================================================
function Test-VbsKeyReady {
    [CmdletBinding()]
    param()
    # VirtualizationBasedSecurityStatus: 0 = off, 1 = enabled-not-running, 2 = running
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
                          -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $vbsRunning = $dg -and $dg.VirtualizationBasedSecurityStatus -eq 2
    $build      = [System.Environment]::OSVersion.Version.Build
    $buildOk    = $build -ge 26052   # VBS key protection debuted in build 26052

    if (-not $vbsRunning) {
        Write-Warning "VBS is not running (status=$($dg.VirtualizationBasedSecurityStatus)). Cannot create VBS keys."
        return $false
    }
    if (-not $buildOk) {
        Write-Warning "OS build $build is below 26052; VBS may be unavailable."
        return $false
    }
    Write-Host "VBS prerequisites OK (VBS running, build $build)." -ForegroundColor Green
    return $true
}

# ===========================================================================
# New-VbsKey: create a VBS-isolated (VBS) RSA or ECC key via CNG.
# There is no built-in cmdlet, so we call NCryptCreatePersistedKey directly.
# If -Name is omitted, a unique name 'vbs-<GUID>' is generated (like the
# platform generates te-/le-<GUID>). Returns the container name.
# ===========================================================================
function New-VbsKey {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Name,                           # optional; auto-generated as 'vbs-<GUID>' if omitted
        # RSA, or an ECC named-curve algorithm. ECDSA = signing, ECDH = key agreement.
        [ValidateSet('RSA','ECDSA_P256','ECDSA_P384','ECDSA_P521','ECDH_P256','ECDH_P384','ECDH_P521')]
        [string]$Algorithm = 'RSA',
        [ValidateRange(2048, 16384)]             # enforce a secure RSA minimum (ignored for ECC); single choke point for all key creation
        [int]$Bits = 2048,                       # RSA key size (IGNORED for ECC - the curve fixes the size)
        [switch]$Machine,                        # machine store (requires elevation)
        [switch]$PreferFallback,                 # PREFER VBS (fall back to software) instead of REQUIRE
        [switch]$Force                           # overwrite an existing key with the same name
    )
    # Auto-generate a unique, identifiable name when none is supplied.
    if (-not $Name) { $Name = 'vbs-' + [guid]::NewGuid().ToString() }

    $openOpts = if ($Machine) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
                else          { [System.Security.Cryptography.CngKeyOpenOptions]::None }

    # -Force: delete any pre-existing key with this name first (ignore if absent).
    # Deleting a VBS key is IRREVERSIBLE. -Force is the caller's explicit consent;
    # the delete is still gated by ShouldProcess so -WhatIf skips it and -Confirm prompts.
    # If the delete is declined, the create below fails cleanly with NTE_EXISTS.
    if ($Force) {
        $existing = $null
        try {
            $existing = [System.Security.Cryptography.CngKey]::Open(
                            $Name, [System.Security.Cryptography.CngProvider]::new($script:VbsProvider), $openOpts)
        } catch { }   # not present -> nothing to remove
        if ($existing) {
            if ($PSCmdlet.ShouldProcess($Name, 'Delete existing VBS key (irreversible)')) {
                $existing.Delete()          # Delete() also releases the handle
            } else {
                $existing.Dispose()         # declined -> just release our handle
            }
        }
    }

    # Flag selection (values from ncrypt.h):
    #   0x00020000 = NCRYPT_USE_VIRTUAL_ISOLATION_FLAG   (alias NCRYPT_REQUIRE_VBS_FLAG): fail if VBS unavailable
    #   0x00010000 = NCRYPT_PREFER_VIRTUAL_ISOLATION_FLAG (alias NCRYPT_PREFER_VBS_FLAG): fall back to software
    #   0x00000020 = NCRYPT_MACHINE_KEY_FLAG: create in the machine key store (needs admin)
    $flags = if ($PreferFallback) { [uint32]0x00010000 } else { [uint32]0x00020000 }
    if ($Machine) { $flags = $flags -bor [uint32]0x00000020 }

    # Gate the key creation itself so -WhatIf makes NO change (honors the ShouldProcess
    # contract). Medium impact -> does not prompt on a normal run; -Confirm still prompts.
    if (-not $PSCmdlet.ShouldProcess($Name, "Create $Algorithm VBS key")) { return }

    $prov=[IntPtr]::Zero; $key=[IntPtr]::Zero; $sizeMismatch=$null
    try {
        if ([VbsNative]::NCryptOpenStorageProvider([ref]$prov,$script:VbsProvider,0)) { throw 'NCryptOpenStorageProvider failed' }
        # Pass the chosen algorithm (e.g. "RSA" or "ECDSA_P256") to CNG
        $s = [VbsNative]::NCryptCreatePersistedKey($prov,[ref]$key,$Algorithm,$Name,0,$flags)
        if ($s -ne 0) {
            $hex = "0x{0:X8}" -f $s
            if ($hex -eq '0x8009000F') {   # NTE_EXISTS
                throw "A VBS key named '$Name' already exists. Use -Force to overwrite, or -UseExistingKey (cert/CSR functions) to reuse it."
            }
            throw "NCryptCreatePersistedKey failed $hex (VBS unavailable?)"
        }

        # Only RSA takes an explicit Length. ECC named curves derive their size from the
        # curve - setting Length there can cause errors.
        if ($Algorithm -eq 'RSA') {
            $ls = [VbsNative]::NCryptSetProperty($key,'Length',[BitConverter]::GetBytes([int]$Bits),4,0)
            if ($ls -ne 0) { throw ("NCryptSetProperty('Length'=$Bits) failed 0x{0:X8}" -f $ls) }
        }

        $s = [VbsNative]::NCryptFinalizeKey($key,0)
        if ($s -ne 0) { throw ("NCryptFinalizeKey failed 0x{0:X8}" -f $s) }

        # Verify the resulting key's isolation on the still-open handle. With
        # -PreferFallback the provider may have created a plain SOFTWARE key when VBS
        # was unavailable; detect that so we never report a non-isolated key as
        # VBS-backed (silent security downgrade, CWE-757).
        $isoBuf = New-Object byte[] 4; $isoCb = [uint32]0; $isolated = 0
        if ([VbsNative]::NCryptGetProperty($key,'Virtual Iso',$isoBuf,4,[ref]$isoCb,0) -eq 0) { $isolated = [BitConverter]::ToInt32($isoBuf,0) }

        # Confirm the finalized RSA key is ACTUALLY the requested size. The Length set is
        # status-checked above, but verify post-finalize too so a provider that silently
        # clamped to its default (e.g. 2048) can never be misreported as the requested size
        # (CWE-252 unchecked-downgrade). ECC size is fixed by the curve.
        if ($Algorithm -eq 'RSA') {
            $lenBuf = New-Object byte[] 4; $lenCb = [uint32]0; $actualBits = 0
            if ([VbsNative]::NCryptGetProperty($key,'Length',$lenBuf,4,[ref]$lenCb,0) -eq 0) { $actualBits = [BitConverter]::ToInt32($lenBuf,0) }
            if ($actualBits -ne $Bits) { $sizeMismatch = $actualBits }
        }
    } finally {
        if ($key  -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($key) }
        if ($prov -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($prov) }
    }

    if ($sizeMismatch) {
        # A wrong-size RSA key must never be returned/misreported (CWE-252): remove it and
        # fail closed so a caller requesting e.g. 4096-bit can't silently deploy 2048-bit.
        try { [System.Security.Cryptography.CngKey]::Open($Name,[System.Security.Cryptography.CngProvider]::new($script:VbsProvider),$openOpts).Delete() } catch {}
        throw "Key length downgrade: requested $Bits-bit RSA but the provider produced $sizeMismatch-bit. The key was removed; no key was created."
    }

    $desc = if ($Algorithm -eq 'RSA') { "$Bits-bit RSA" } else { $Algorithm }
    if ($isolated -eq 1) {
        Write-Host "Created VBS key '$Name' ($desc, VBS-isolated)." -ForegroundColor Green
    } else {
        Write-Warning ("Created key '$Name' ($desc) but it is NOT VBS-isolated (Virtual Iso=$isolated). " +
            "With -PreferFallback and VBS unavailable, this is a plain SOFTWARE key -- NOT VBS-protected. " +
            "Recreate without -PreferFallback (or enable VBS) to guarantee isolation.")
    }
    return $Name   # return the container name (useful when auto-generated)
}

# ===========================================================================
# Get-VbsKey: list VBS-isolated keys and, for each, the
# certificate thumbprint(s) that use it.
#
# The container -> thumbprint map is built from certificate METADATA
# (CERT_KEY_PROV_INFO_PROP_ID) so we never open a private key. This avoids
# triggering interactive UI prompts (and hangs) for UI-protected keys.
# ===========================================================================
function Get-VbsKey {
    [CmdletBinding()]
    param([switch]$Machine)   # -Machine lists machine-store keys (run elevated)

    $flags     = if ($Machine) { [uint32]0x00000020 } else { [uint32]0 }   # 0x20 = NCRYPT_MACHINE_KEY_FLAG
    $storePath = if ($Machine) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
    $CERT_KEY_PROV_INFO_PROP_ID = [uint32]2

    # --- Build container-name -> thumbprint(s) map from cert metadata (no key access) ---
    $map = @{}
    foreach ($c in (Get-ChildItem $storePath -ErrorAction SilentlyContinue | Where-Object HasPrivateKey)) {
        $cb = [uint32]0
        if (-not [VbsNative]::CertGetCertificateContextProperty($c.Handle,$CERT_KEY_PROV_INFO_PROP_ID,[IntPtr]::Zero,[ref]$cb)) { continue }
        $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal([int]$cb)
        try {
            if ([VbsNative]::CertGetCertificateContextProperty($c.Handle,$CERT_KEY_PROV_INFO_PROP_ID,$buf,[ref]$cb)) {
                $info = [Runtime.InteropServices.Marshal]::PtrToStructure($buf,[type]([VbsNative+CRYPT_KEY_PROV_INFO]))
                if ($info.pwszProvName -eq $script:VbsProvider -and $info.pwszContainerName) {
                    if (-not $map.ContainsKey($info.pwszContainerName)) { $map[$info.pwszContainerName] = @() }
                    $map[$info.pwszContainerName] += $c.Thumbprint
                }
            }
        } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
    }

    # --- Enumerate KSP keys; keep only those with Virtual Iso = 1 (VBS) ---
    $p = [IntPtr]::Zero
    if ([VbsNative]::NCryptOpenStorageProvider([ref]$p,$script:VbsProvider,0)) { throw 'open provider failed' }
    $state=[IntPtr]::Zero; $pName=[IntPtr]::Zero; $rc=0; $out=@()
    try {
        do {
            # NOTE: use [NullString]::Value (NOT $null) for the scope --
            # PowerShell marshals $null as "" which returns NTE_INVALID_PARAMETER (0x80090027).
            $rc = [VbsNative]::NCryptEnumKeys($p,[NullString]::Value,[ref]$pName,[ref]$state,$flags)
            if ($rc -eq 0) {
                $kn   = [Runtime.InteropServices.Marshal]::PtrToStructure($pName,[type]([VbsNative+NCryptKeyName]))
                $name = [Runtime.InteropServices.Marshal]::PtrToStringUni($kn.pszName)
                $alg  = [Runtime.InteropServices.Marshal]::PtrToStringUni($kn.pszAlgid)
                $kk=[IntPtr]::Zero; $iso=0
                if ([VbsNative]::NCryptOpenKey($p,[ref]$kk,$name,0,$flags) -eq 0) {
                    $b=New-Object byte[] 4; $cb2=[uint32]0
                    if ([VbsNative]::NCryptGetProperty($kk,'Virtual Iso',$b,4,[ref]$cb2,0) -eq 0) { $iso=[BitConverter]::ToInt32($b,0) }
                    [void][VbsNative]::NCryptFreeObject($kk)
                }
                if ($iso -eq 1) {
                    $tp = if ($map.ContainsKey($name)) { $map[$name] -join ', ' } else { '(none)' }
                    $out += [pscustomobject]@{
                        Name       = $name
                        Algorithm  = $alg
                        Scope      = if ($Machine) { 'Machine' } else { 'User' }
                        Thumbprint = $tp
                    }
                }
                [void][VbsNative]::NCryptFreeBuffer($pName); $pName=[IntPtr]::Zero
            }
        } while ($rc -eq 0)   # loop ends on 0x8009002A (NTE_NO_MORE_ITEMS)
    } finally {
        if ($pName -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeBuffer($pName) }
        if ($state -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeBuffer($state) }
        if ($p     -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($p) }
    }
    $out
}

# ===========================================================================
# Remove-VbsKey: delete a VBS key by container name.
# Uses the .NET CngKey API (no P/Invoke needed for deletion).
# WARNING: irreversible - non-exportable keys cannot be recovered.
#
# DELETION IS IMMEDIATE: in testing (Windows build 26200, user AND machine scope)
# a deleted key becomes instantly unobtainable via every path -- CngKey.Open,
# CryptAcquireCertificatePrivateKey (the API certutil uses), and certutil itself
# all fail with NTE_BAD_KEYSET (0x80090016). No cache, no reboot needed.
# As a safety net this function re-probes after deletion (Test-VbsKeyUsable)
# and warns only if the key UNEXPECTEDLY still resolves (pass -SkipCacheCheck to
# skip). If that ever happens, the certificate likely has a second/software key,
# or the deleted container was not the cert's bound key -- investigate; a reboot
# is a safe fallback.
#
# NOTE: -Name is the CNG key CONTAINER name (e.g. 'vbs-<GUID>'), NOT a certificate
# thumbprint. Use Get-VbsKey to map a thumbprint to its container name, and
# add -Machine (elevated) for LocalMachine keys.
# ===========================================================================
function Remove-VbsKey {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$Name,   # CNG key container name (e.g. 'vbs-<GUID>'), NOT a cert thumbprint
        [switch]$Machine,                       # machine store (run elevated)
        [switch]$SkipCacheCheck                 # skip the post-delete cache/eviction verification
    )
    $opts = if ($Machine) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
            else          { [System.Security.Cryptography.CngKeyOpenOptions]::None }
    $prov = [System.Security.Cryptography.CngProvider]::new($script:VbsProvider)
    try {
        $k = [System.Security.Cryptography.CngKey]::Open($Name, $prov, $opts)
        if ($PSCmdlet.ShouldProcess($Name,'Delete VBS key')) {
            $k.Delete()   # removes the persisted key + its VBS-isolated material
            Write-Host "Deleted VBS key '$Name'." -ForegroundColor Green

            # --- Post-delete verification (safety net) ------------------------
            # In testing, deletion is immediate: the container no longer resolves
            # via any path. Re-probe to CONFIRM that; warn only if it unexpectedly
            # still resolves (would indicate a second/software key on the cert, or
            # that this container was not the cert's bound key).
            if (-not $SkipCacheCheck) {
                $probe = Test-VbsKeyUsable -Name $Name -Machine:$Machine
                if ($probe.CryptoUsable) {
                    Write-Warning ("UNEXPECTED: VBS key '$Name' was deleted but can STILL PERFORM CRYPTO " +
                        "($($probe.Detail)). The certificate may have a second/software key, or this container was not the " +
                        "cert's bound key. Investigate; a REBOOT is a safe fallback.")
                } elseif ($probe.Resolves) {
                    Write-Warning ("UNEXPECTED: VBS key '$Name' was deleted but its container still RESOLVES " +
                        "($($probe.Detail)). Investigate; a REBOOT is a safe fallback.")
                } else {
                    Write-Verbose "Post-delete check: '$Name' no longer resolves; deletion confirmed complete."
                }
            }
        } else {
            $k.Dispose()   # -WhatIf / declined confirmation: release the handle we opened
        }
    } catch {
        Write-Warning "Could not delete '$Name': $($_.Exception.Message)"
    }
}

# ===========================================================================
# Test-VbsKeyUsable: probe whether a VBS key container can still be
# opened AND perform a crypto operation (a throwaway test signature). Useful to
# confirm a Remove-VbsKey actually took effect (deletion is immediate -- a
# removed key returns Resolves=$false right away), or to detect that a certificate
# still has a working key via a second/residual container. Does not modify state.
# Returns: Name, Resolves (handle opens), CryptoUsable (a sign succeeded), Detail.
# ===========================================================================
function Test-VbsKeyUsable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,   # CNG key container name (e.g. 'vbs-<GUID>')
        [switch]$Machine                        # machine store (run elevated)
    )
    $opts = if ($Machine) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
            else          { [System.Security.Cryptography.CngKeyOpenOptions]::None }
    $prov = [System.Security.Cryptography.CngProvider]::new($script:VbsProvider)

    try {
        $k = [System.Security.Cryptography.CngKey]::Open($Name, $prov, $opts)
    } catch {
        return [pscustomobject]@{ Name=$Name; Resolves=$false; CryptoUsable=$false; Detail="does not resolve: $($_.Exception.Message)" }
    }

    $usable = $false; $detail = 'resolves; crypto not attempted'
    try {
        $probeData = [System.Text.Encoding]::UTF8.GetBytes('vbs-key-usability-probe')
        if ($k.AlgorithmGroup -eq [System.Security.Cryptography.CngAlgorithmGroup]::Rsa) {
            $rsa = [System.Security.Cryptography.RSACng]::new($k)
            try { [void]$rsa.SignData($probeData, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) }
            finally { $rsa.Dispose() }
            $usable = $true; $detail = 'RSA test signature succeeded (crypto works)'
        }
        elseif ($k.AlgorithmGroup -eq [System.Security.Cryptography.CngAlgorithmGroup]::ECDsa) {
            $ec = [System.Security.Cryptography.ECDsaCng]::new($k)
            try { [void]$ec.SignData($probeData, [System.Security.Cryptography.HashAlgorithmName]::SHA256) }
            finally { $ec.Dispose() }
            $usable = $true; $detail = 'ECDSA test signature succeeded (crypto works)'
        }
        else {
            $detail = "resolves; unsupported algorithm group for probe: $($k.AlgorithmGroup.AlgorithmGroup)"
        }
    } catch {
        $usable = $false; $detail = "resolves but crypto FAILED: $($_.Exception.Message)"
    } finally {
        $k.Dispose()
    }
    [pscustomobject]@{ Name=$Name; Resolves=$true; CryptoUsable=$usable; Detail=$detail }
}

# ===========================================================================
# Find-CertKeyContainers: return EVERY CNG key container (in the VBS KSP)
# whose public key matches a certificate -- i.e. all copies of the cert's
# keypair, VBS AND plain software. Use it to spot leftover exportable
# software copies that survive after deleting the VBS key (and that
#'certutil -repairstore' will silently re-bind the cert to). RSA AND ECDSA certs.
# Returns per match: Name, VBS, Exportable, ExportPolicy, Scope, UniqueName, BlobPath.
# ===========================================================================
function Find-CertKeyContainers {
    [CmdletBinding()]
    param(
        # SHA1 thumbprint (exactly 40 hex chars). Validated to prevent wildcard/path
        # expansion in the Cert: provider lookup below.
        [Parameter(Mandatory)][ValidatePattern('\A[0-9A-Fa-f]{40}\z')][string]$Thumbprint,
        [switch]$Machine                             # LocalMachine store/keys (run elevated)
    )
    $store = if ($Machine) { 'LocalMachine' } else { 'CurrentUser' }
    # -LiteralPath prevents wildcard interpretation of the thumbprint.
    $cert = Get-Item -LiteralPath "Cert:\$store\My\$Thumbprint" -ErrorAction Stop
    $fp = Get-VbsKeyCertFingerprint -Cert $cert
    Find-KeyContainersByFingerprint -Algorithm $fp.Alg -Fingerprint $fp.Fp -Machine:$Machine
}

# ---------------------------------------------------------------------------
# Get-VbsKeyCertFingerprint (internal): return a public-key fingerprint for a
# certificate that identifies its keypair regardless of algorithm.
#   RSA   -> modulus;  ECDSA -> the public point Q (X|Y).
# ---------------------------------------------------------------------------
function Get-VbsKeyCertFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Cert)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert)
    if ($rsa) { return [pscustomobject]@{ Alg = 'RSA'; Fp = [BitConverter]::ToString($rsa.ExportParameters($false).Modulus) } }
    $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert)
    if ($ec) {
        $p = $ec.ExportParameters($false)
        return [pscustomobject]@{ Alg = 'ECDSA'; Fp = ([BitConverter]::ToString($p.Q.X) + '|' + [BitConverter]::ToString($p.Q.Y)) }
    }
    throw "Certificate has no RSA or ECDSA public key (VBS audit supports RSA and ECDSA)."
}

# ---------------------------------------------------------------------------
# Find-KeyContainersByFingerprint (internal): enumerate ONE key-store scope of the
# VBS KSP and return every container whose public key matches the given
# fingerprint. Decoupled from the cert lookup so callers can audit either/both
# scopes (CurrentUser and LocalMachine) for the same keypair.
# ---------------------------------------------------------------------------
function Find-KeyContainersByFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('RSA','ECDSA')][string]$Algorithm,
        [Parameter(Mandatory)][string]$Fingerprint,
        [switch]$Machine
    )
    $flags    = if ($Machine) { [uint32]0x20 } else { [uint32]0 }   # NCRYPT_MACHINE_KEY_FLAG
    $openOpts = if ($Machine) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
                else          { [System.Security.Cryptography.CngKeyOpenOptions]::None }
    $keyDir   = if ($Machine) { "$env:ProgramData\Microsoft\Crypto\Keys" } else { "$env:APPDATA\Microsoft\Crypto\Keys" }

    $out = @()
    $inspectFailures = 0
    $p = [IntPtr]::Zero
    if ([VbsNative]::NCryptOpenStorageProvider([ref]$p, $script:VbsProvider, 0)) { throw 'NCryptOpenStorageProvider failed' }
    $state=[IntPtr]::Zero; $pName=[IntPtr]::Zero; $rc=0
    try {
        do {
            $rc = [VbsNative]::NCryptEnumKeys($p, [NullString]::Value, [ref]$pName, [ref]$state, $flags)
            if ($rc -eq 0) {
                $kn   = [Runtime.InteropServices.Marshal]::PtrToStructure($pName, [type]([VbsNative+NCryptKeyName]))
                $name = [Runtime.InteropServices.Marshal]::PtrToStringUni($kn.pszName)
                $k = $null; $rsa = $null; $ec = $null
                try {
                    $k = [System.Security.Cryptography.CngKey]::Open($name, [System.Security.Cryptography.CngProvider]::new($script:VbsProvider), $openOpts)
                    $grp = $k.AlgorithmGroup
                    $match = $false
                    if ($Algorithm -eq 'RSA' -and $grp -eq [System.Security.Cryptography.CngAlgorithmGroup]::Rsa) {
                        $rsa = [System.Security.Cryptography.RSACng]::new($k)
                        $match = ([BitConverter]::ToString($rsa.ExportParameters($false).Modulus) -eq $Fingerprint)
                    }
                    elseif ($Algorithm -eq 'ECDSA' -and $grp -eq [System.Security.Cryptography.CngAlgorithmGroup]::ECDsa) {
                        $ec  = [System.Security.Cryptography.ECDsaCng]::new($k)
                        $ecp2 = $ec.ExportParameters($false)
                        $match = ((([BitConverter]::ToString($ecp2.Q.X) + '|' + [BitConverter]::ToString($ecp2.Q.Y)) -eq $Fingerprint))
                    }
                    if ($match) {
                        $iso = try { [BitConverter]::ToInt32($k.GetProperty('Virtual Iso',[System.Security.Cryptography.CngPropertyOptions]::None).GetValue(),0) } catch { 0 }
                        $ep  = try { [BitConverter]::ToInt32($k.GetProperty('Export Policy',[System.Security.Cryptography.CngPropertyOptions]::None).GetValue(),0) } catch { -1 }
                        $uniq= try { $k.UniqueName } catch { $null }
                        $out += [pscustomobject]@{
                            Name         = $name
                            VBS          = ($iso -eq 1)
                            Exportable   = ($ep -ge 1)
                            ExportPolicy = $ep
                            Scope        = if ($Machine) { 'Machine' } else { 'User' }
                            UniqueName   = $uniq
                            BlobPath     = if ($uniq) { Join-Path $keyDir $uniq } else { $null }
                        }
                    }
                } catch { $inspectFailures++ } finally {
                    if ($rsa) { $rsa.Dispose() }
                    if ($ec)  { $ec.Dispose() }
                    if ($k)   { $k.Dispose() }
                }
                [void][VbsNative]::NCryptFreeBuffer($pName); $pName=[IntPtr]::Zero
            }
        } while ($rc -eq 0)
    } finally {
        if ($pName -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeBuffer($pName) }
        if ($state -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeBuffer($state) }
        if ($p     -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($p) }
    }
    # Surface (don't swallow) containers that could not be opened/inspected, so callers
    # can distinguish "no matching copies" from "could not fully check" (fail-loud).
    if ($inspectFailures -gt 0) {
        Write-Warning "Find-KeyContainersByFingerprint: $inspectFailures key container(s) could not be inspected; residual-key results may be incomplete."
    }
    $out
}

# ===========================================================================
# Assert-VbsKeyExclusive (internal): after a cert is bound to a VBS key,
# warn if its keypair ALSO lives in other (software/exportable) containers, and
# optionally remove those software copies. Keeps $KeepContainer (the VBS key).
# RSA and ECDSA. The audit fails LOUD: if it cannot run for any reason it warns
# (Write-Warning) rather than looking like a clean result. Audits BOTH the user and
# machine scopes (opposite scope is best-effort; warns if it cannot be enumerated,
# e.g. machine scope without elevation).
# ===========================================================================
function Assert-VbsKeyExclusive {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$KeepContainer,
        [switch]$Machine,
        [switch]$Remove
    )
    # Compute the cert's public-key fingerprint once (from its own store scope), then
    # enumerate BOTH scopes for matching containers -- a residual exportable copy in the
    # OTHER scope (CurrentUser vs LocalMachine) would otherwise go undetected.
    $store = if ($Machine) { 'LocalMachine' } else { 'CurrentUser' }
    try {
        $cert = Get-Item -LiteralPath "Cert:\$store\My\$Thumbprint" -ErrorAction Stop
        $fp   = Get-VbsKeyCertFingerprint -Cert $cert
    } catch {
        Write-Warning "Residual-key audit could NOT run (result NOT verified): $($_.Exception.Message)"; return
    }

    $copies = @()
    try { $copies += @(Find-KeyContainersByFingerprint -Algorithm $fp.Alg -Fingerprint $fp.Fp -Machine:$Machine) }
    catch { Write-Warning "Residual-key audit could NOT run for the cert's own scope (result NOT verified): $($_.Exception.Message)"; return }
    # Opposite scope is best-effort (machine scope typically needs elevation).
    try { $copies += @(Find-KeyContainersByFingerprint -Algorithm $fp.Alg -Fingerprint $fp.Fp -Machine:(-not $Machine)) }
    catch { Write-Warning ("Could not audit the {0} scope for residual copies (may require elevation): {1}" -f $(if($Machine){'user'}else{'machine'}), $_.Exception.Message) }

    $residual = @($copies | Where-Object { $_.Name -ne $KeepContainer })
    if (-not $residual) { Write-Verbose "Residual-key audit: no other containers hold this keypair. Good."; return }

    $soft = @($residual | Where-Object { -not $_.VBS })
    $exp  = @($soft | Where-Object { $_.Exportable })
    Write-Warning ("This cert's keypair also exists in $($residual.Count) OTHER container(s): " +
        ($residual.Name -join ', ') + ". Of those, $($soft.Count) is/are non-VBS software copies " +
        "($($exp.Count) exportable) -- these defeat VBS non-exportability.")
    if ($Remove) {
        foreach ($r in $soft) { $null = Remove-VbsKey -Name $r.Name -Machine:($r.Scope -eq 'Machine') -SkipCacheCheck }
        # Do NOT assume success -- re-audit both scopes and report what ACTUALLY remains.
        $remaining = @()
        try {
            $remaining += @(Find-KeyContainersByFingerprint -Algorithm $fp.Alg -Fingerprint $fp.Fp -Machine:$Machine | Where-Object { $_.Name -ne $KeepContainer -and -not $_.VBS })
            $remaining += @(Find-KeyContainersByFingerprint -Algorithm $fp.Alg -Fingerprint $fp.Fp -Machine:(-not $Machine) | Where-Object { $_.Name -ne $KeepContainer -and -not $_.VBS })
        } catch {}
        if ($remaining.Count -eq 0) {
            Write-Host "Removed $($soft.Count) residual software key copy(ies); none remain." -ForegroundColor Green
        } else {
            Write-Warning ("Attempted removal of $($soft.Count) residual software copy(ies), but $($remaining.Count) STILL remain: " +
                ($remaining.Name -join ', ') + " -- delete failed or was declined; these still defeat VBS non-exportability.")
        }
    } else {
        Write-Warning "Re-run with -RemoveResidualKeyCopies, or use Find-CertKeyContainers + Remove-VbsKey, to purge them."
    }
}

# ===========================================================================
# Assert-VbsKeyIsolated (internal): verify that an existing CNG key
# container is VBS-isolated (Virtual Iso = 1) before it is reused to
# back a certificate or CSR. Throws if the container cannot be opened or is a
# non-isolated (software) key. Closes the gap where -UseExistingKey could bind
# a plain software key while the operation is presented as VBS-backed.
# ===========================================================================
function Assert-VbsKeyIsolated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,   # CNG key container name (e.g. 'vbs-<GUID>')
        [switch]$Machine                        # machine store (run elevated)
    )
    $storeName = if ($Machine) { 'LocalMachine' } else { 'CurrentUser' }
    $opts = if ($Machine) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
            else          { [System.Security.Cryptography.CngKeyOpenOptions]::None }
    $prov = [System.Security.Cryptography.CngProvider]::new($script:VbsProvider)
    try {
        $k = [System.Security.Cryptography.CngKey]::Open($Name, $prov, $opts)
    } catch {
        throw "-UseExistingKey: VBS key '$Name' could not be opened in the $storeName store: $($_.Exception.Message)"
    }
    try {
        $iso = try { [BitConverter]::ToInt32($k.GetProperty('Virtual Iso',[System.Security.Cryptography.CngPropertyOptions]::None).GetValue(),0) } catch { 0 }
    } finally {
        $k.Dispose()
    }
    if ($iso -ne 1) {
        throw ("Existing key '$Name' is NOT VBS-isolated (Virtual Iso=$iso); refusing to back a certificate/CSR " +
               "with a non-VBS key. Create a new key (omit -UseExistingKey) or select an isolated container.")
    }
}

# ===========================================================================
# New-VbsKeySelfSignedCertificate: create (or reuse) a VBS key and bind
# a self-signed certificate to it.
# The cert's private key stays VBS-isolated and non-exportable.
# ===========================================================================
function New-VbsKeySelfSignedCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Subject,   # e.g. "CN=myservice.contoso.com"
        [string]$KeyName,                          # optional; auto-generated as 'vbs-<GUID>' if omitted
        [ValidateSet('RSA','ECDSA_P256','ECDSA_P384','ECDSA_P521')]
        [string]$Algorithm = 'RSA',
        [int]$Bits = 2048,                         # RSA only; ignored for ECC
        [ValidateSet('SHA256','SHA384','SHA512')]
        [string]$HashAlgorithm = 'SHA256',
        [string[]]$DnsName,                        # optional Subject Alternative Names
        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$StoreLocation = 'CurrentUser',
        [switch]$UseExistingKey,                   # reuse an existing VBS key instead of creating one
        [switch]$Force,                            # overwrite an existing key with the same name
        [switch]$RemoveResidualKeyCopies           # after binding, remove any leftover software copy of the keypair
    )
    $machine = ($StoreLocation -eq 'LocalMachine')
    if ($UseExistingKey -and -not $KeyName) { throw "-KeyName is required when -UseExistingKey is specified." }
    if (-not $KeyName) { $KeyName = 'vbs-' + [guid]::NewGuid().ToString() }

    # Gate the whole operation (key creation + cert install) behind ShouldProcess so
    # -WhatIf makes NO change. Medium impact -> no prompt on a normal run; -Confirm prompts.
    if (-not $PSCmdlet.ShouldProcess("$Subject ($StoreLocation)", 'Create VBS key and self-signed certificate')) { return }

    # Create the VBS key first, unless reusing an existing one.
    # ($null = ...) suppresses the container name that New-VbsKey returns.
    if (-not $UseExistingKey) {
        $null = New-VbsKey -Name $KeyName -Algorithm $Algorithm -Bits $Bits -Machine:$machine -Force:$Force -Confirm:$false
    } else {
        # Reusing a caller-supplied key: verify it is VBS-isolated before
        # binding, so a non-isolated software key is never presented as VBS-backed.
        Assert-VbsKeyIsolated -Name $KeyName -Machine:$machine
    }

    # Bind a self-signed cert to the EXISTING key (-ExistingKey + -Container).
    # The cert inherits the key's algorithm (RSA/ECDSA) automatically.
    $params = @{
        Subject           = $Subject
        Provider          = $script:VbsProvider
        ExistingKey       = $true
        Container         = $KeyName
        HashAlgorithm     = $HashAlgorithm
        KeyExportPolicy   = 'NonExportable'
        CertStoreLocation = "Cert:\$StoreLocation\My"
    }
    if ($DnsName) { $params['DnsName'] = $DnsName }

    $cert = New-SelfSignedCertificate @params

    # Post-binding verification (closes the check-then-use race on -UseExistingKey): confirm
    # the key ACTUALLY bound to the new cert is VBS-isolated. If a same-scope process swapped
    # the container to a software key between the isolation check and this bind, fail closed --
    # remove the just-created cert and throw.
    $boundIso = -1
    try {
        $bk = if ($cert.GetKeyAlgorithm() -eq '1.2.840.113549.1.1.1') {
                  [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
              } else {
                  [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
              }
        try { $boundIso = [BitConverter]::ToInt32($bk.Key.GetProperty('Virtual Iso',[System.Security.Cryptography.CngPropertyOptions]::None).GetValue(),0) }
        finally { if ($bk) { $bk.Dispose() } }
    } catch { $boundIso = -1 }
    if ($boundIso -ne 1) {
        try { Remove-Item -LiteralPath "Cert:\$StoreLocation\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue } catch {}
        throw ("Post-binding check FAILED: the key bound to cert '$($cert.Thumbprint)' is NOT VBS-isolated (Virtual Iso=$boundIso). " +
               "The certificate was removed (possible key-container swap during creation).")
    }

    Write-Host "Created self-signed cert '$($cert.Thumbprint)' bound to VBS key '$KeyName'." -ForegroundColor Green
    Assert-VbsKeyExclusive -Thumbprint $cert.Thumbprint -KeepContainer $KeyName -Machine:$machine -Remove:$RemoveResidualKeyCopies
    # Expose the (possibly auto-generated) container name so callers can attest the key
    # (New-VbsKeyAttestation -KeyName) without re-deriving it. Non-breaking: the
    # returned object is still an X509Certificate2, just with an added KeyName property.
    $cert | Add-Member -NotePropertyName KeyName -NotePropertyValue $KeyName -PassThru
}

# ===========================================================================
# New-VbsKeyCsr: create (or reuse) a VBS key and generate a PKCS#10 CSR
# (signed inside VBS) to submit to a CA. After the CA issues the cert, run
#   certreq -accept <issued.cer>
# to marry the returned certificate back to the same VBS key.
# ===========================================================================
function New-VbsKeyCsr {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Subject,      # e.g. "CN=myservice.contoso.com,O=Contoso"
        [string]$KeyName,                             # optional; auto-generated as 'vbs-<GUID>' if omitted
        [Parameter(Mandatory)][string]$OutputPath,    # path to write the .req (PKCS#10) file
        [ValidateSet('RSA','ECDSA_P256','ECDSA_P384','ECDSA_P521')]
        [string]$Algorithm = 'RSA',
        [int]$Bits = 2048,                            # RSA only; ignored for ECC
        [ValidateSet('SHA256','SHA384','SHA512')]
        [string]$HashAlgorithm = 'SHA256',
        [string[]]$DnsName,                           # optional Subject Alternative Names
        [switch]$Machine,                             # machine-store key (run elevated)
        [switch]$UseExistingKey,                      # reuse an existing VBS key instead of creating one
        [switch]$Force                                # overwrite an existing key with the same name
    )
    if ($UseExistingKey -and -not $KeyName) { throw "-KeyName is required when -UseExistingKey is specified." }
    if (-not $KeyName) { $KeyName = 'vbs-' + [guid]::NewGuid().ToString() }

    # --- Guard against INF / SAN injection ---
    # $Subject and $KeyName are written inside quoted INF values, so a double-quote
    # (or CR/LF) could break out and inject directives. $DnsName values are written
    # into certreq's {text} SAN format, where '&' separates SAN token types
    # (dns=, upn=, email=, ...) -- an unescaped '&' could inject an extra SAN
    # (e.g. a rogue UPN usable for authentication). Validate strictly.
    foreach ($v in @($Subject, $KeyName)) {
        if ($v -match '["\r\n]') { throw "Value contains illegal characters (INF-injection risk): '$v'" }
    }
    foreach ($d in $DnsName) {
        if ($d -notmatch '\A(\*\.)?([A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?\z') {
            throw "Invalid DNS SAN '$d': only host names are allowed (blocks SAN/INF injection)."
        }
    }

    # Gate the whole operation (key creation + CSR signing/file write) behind
    # ShouldProcess so -WhatIf makes NO change. Medium impact -> no prompt on a normal
    # run; -Confirm prompts.
    if (-not $PSCmdlet.ShouldProcess("$Subject -> $OutputPath", 'Create VBS key and generate CSR')) { return }

    # Create the VBS key first, unless reusing an existing one.
    # ($null = ...) suppresses the container name that New-VbsKey returns.
    if (-not $UseExistingKey) {
        $null = New-VbsKey -Name $KeyName -Algorithm $Algorithm -Bits $Bits -Machine:$Machine -Force:$Force -Confirm:$false
    } else {
        # Reusing a caller-supplied key: verify it is VBS-isolated before
        # signing the CSR, so a non-isolated software key is never presented as VBS-backed.
        Assert-VbsKeyIsolated -Name $KeyName -Machine:$Machine
    }

    # Build the [Extensions] block (EKU: Server Authentication, plus optional DNS SANs).
    $extLines = @('[Extensions]','2.5.29.37 = "{text}1.3.6.1.5.5.7.3.1"')
    if ($DnsName) {
        $extLines += '2.5.29.17 = "{text}"'
        foreach ($d in $DnsName) { $extLines += "_continue_ = `"dns=$d&`"" }
    }
    $extBlock = $extLines -join "`r`n"

    $keyStore = if ($Machine) { 'MachineKeySet = TRUE' } else { 'MachineKeySet = FALSE' }

    # INF references the EXISTING VBS key (UseExistingKeySet + KeyContainer),
    # so certreq does NOT generate a new (non-VBS) key.
    $inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "$Subject"
ProviderName = "$($script:VbsProvider)"
UseExistingKeySet = TRUE
KeyContainer = "$KeyName"
$keyStore
RequestType = PKCS10
HashAlgorithm = $HashAlgorithm

$extBlock
"@

    # Write the INF to a securely-named temp file and always clean it up.
    $infPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('kgcsr_' + [guid]::NewGuid().ToString('N') + '.inf'))
    $resolvedOut = if ([System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath }
                   else { Join-Path (Get-Location).Path $OutputPath }
    Set-Content -Path $infPath -Value $inf -Encoding Unicode   # UTF-16LE: certreq-compatible and preserves non-ASCII Subject values
    try {
        # Invoke certreq via its absolute System32 path (not bare name) to prevent
        # PATH-based binary planting (untrusted search path, CWE-426).
        # Resolve certreq.exe by its absolute System32 path via GetFolderPath (not
        # $env:SystemRoot, which a caller could spoof). Fail CLOSED if it is missing --
        # never fall back to a bare name / PATH resolution, which would reintroduce
        # executable-search-path hijacking / binary planting (CWE-426).
        $certReqExe = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'certreq.exe'
        if (-not (Test-Path -LiteralPath $certReqExe)) { throw "certreq.exe not found at '$certReqExe'." }
        $out = & $certReqExe -new -f $infPath $resolvedOut 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq failed (exit $LASTEXITCODE): $($out -join ' ')" }
        # Post-signing verification (closes the check-then-use race on -UseExistingKey):
        # re-confirm the container is STILL VBS-isolated after certreq signed with it. If a
        # same-scope process swapped it to a software key during the window, fail closed --
        # delete the CSR and throw.
        try { Assert-VbsKeyIsolated -Name $KeyName -Machine:$Machine }
        catch {
            Remove-Item -LiteralPath $resolvedOut -Force -ErrorAction SilentlyContinue
            throw "Post-signing check FAILED: $($_.Exception.Message) The CSR '$resolvedOut' was deleted."
        }
        Write-Host "CSR written to '$resolvedOut' (signed by VBS key '$KeyName')." -ForegroundColor Green
        Write-Host "Submit it to your CA, then run: certreq -accept <issued.cer>" -ForegroundColor Yellow
        # Expose the (possibly auto-generated) container name so callers can attest the key
        # (New-VbsKeyAttestation -KeyName) without re-deriving it. Non-breaking: still
        # returns the CSR FileInfo, just with an added KeyName property.
        Get-Item $resolvedOut | Add-Member -NotePropertyName KeyName -NotePropertyValue $KeyName -PassThru
    } finally {
        Remove-Item $infPath -Force -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# Import-VbsKeyPfx: import an existing PFX (cert + private key) so the private
# key is protected by VBS-isolated and the certificate is installed
# in the store, bound to that key.
#
# The private key is never exported in the clear. The PFX is re-exported as an
# encrypted PKCS#8 (EncryptedPrivateKeyInfo) and handed to NCryptImportKey with
# the virtual-isolation flag; Windows decrypts it *inside* VBS, so the key lands
# in VTL1 and is non-exportable. This keeps the key encrypted end-to-end and
# works on Windows PowerShell 5.1 (.NET Framework) as well as PowerShell 7+.
# Supports RSA and ECDSA PFX files.
# ===========================================================================
function Import-VbsKeyPfx {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$PfxPath,          # path to the .pfx / .p12 file
        [Parameter(Mandatory)][securestring]$Password,   # PFX password
        [string]$KeyName,                                # optional; auto-generated as 'vbs-<GUID>' if omitted
        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$StoreLocation = 'CurrentUser',          # LocalMachine implies machine key + elevation
        [ValidateRange(1024,16384)]
        [int]$MinRsaKeySize = 2048,                       # reject imported RSA keys below this (CWE-326); lower only for legacy migration
        [switch]$Force,                                  # overwrite an existing key with the same name
        [switch]$DeleteSourcePfx,                        # after a successful import, securely delete the source PFX
        [switch]$RemoveResidualKeyCopies                 # after import, remove any leftover software copy of the keypair
    )
    if (-not (Test-Path $PfxPath)) { throw "PFX not found: $PfxPath" }
    $machine = ($StoreLocation -eq 'LocalMachine')
    if (-not $KeyName) { $KeyName = 'vbs-' + [guid]::NewGuid().ToString() }

    # Honor -WhatIf/-Confirm for the whole persistent operation (import the key + install
    # the certificate). Under -WhatIf this returns before ANY state change or PFX load.
    # The inner -Force overwrite and -DeleteSourcePfx paths keep their own prompts.
    if (-not $PSCmdlet.ShouldProcess("$KeyName ($StoreLocation)", 'Import PFX into VBS and install certificate')) { return }

    # Capture the source PFX's file identity up front so the optional secure-delete at the
    # end can refuse if the path was swapped to a different file (e.g. a parent-directory
    # junction) between import and cleanup (TOCTOU).
    $srcId = if ($DeleteSourcePfx) { Get-VbsKeyFileIdentity -Path $PfxPath } else { $null }

    # 1) Load the PFX to validate the password and obtain the public cert. We never
    #    export the private key in the clear -- we re-export it as an encrypted PKCS#8 and
    #    let Windows decrypt it *inside* the VBS KSP.
    #    Prefer EphemeralKeySet so the private key stays in memory and no transient
    #    exportable key container is written to disk (which a crash could orphan). Windows
    #    PowerShell 5.1 / older .NET Framework cannot re-export an ephemeral key, so we
    #    fall back to Exportable-only there (handled at the Export call below).
    $USE_VBS      = [uint32]0x00020000   # NCRYPT_USE_VIRTUAL_ISOLATION_FLAG
    $MACHINE_FLAG = [uint32]0x00000020   # NCRYPT_MACHINE_KEY_FLAG
    $OVERWRITE    = [uint32]0x00000080   # NCRYPT_OVERWRITE_KEY_FLAG
    $KEYNAME_BUF  = [uint32]45           # NCRYPTBUFFER_PKCS_KEY_NAME
    $SECRET_BUF   = [uint32]46           # NCRYPTBUFFER_PKCS_SECRET

    $skf = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
    $usedEphemeral = $false
    if ([enum]::GetNames([type]$skf) -contains 'EphemeralKeySet') {
        $pfx = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $Password, ($skf::Exportable -bor $skf::EphemeralKeySet))
        $usedEphemeral = $true
    } else {
        $pfx = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $Password, $skf::Exportable)
    }

    $M = [System.Runtime.InteropServices.Marshal]
    $reexport=$null; $epki=$null; $prov=[IntPtr]::Zero; $tmpSec=$null
    $namePtr=[IntPtr]::Zero; $secretPtr=[IntPtr]::Zero; $arrPtr=[IntPtr]::Zero; $descPtr=[IntPtr]::Zero; $hKey=[IntPtr]::Zero
    # One try/finally spans re-export through import, so the transient PKCS#12, the
    # encrypted key blob, the decryption secret, and all native handles are always
    # released/zeroed -- even on early failures.
    try {
        if (-not $pfx.HasPrivateKey) { throw "PFX '$PfxPath' has no private key." }

        # Enforce a minimum key strength on the IMPORTED key: migrating a weak legacy key
        # into VBS would just yield an isolated-but-weak key. Reject RSA below
        # -MinRsaKeySize (default 2048) and ECDSA below 256-bit (CWE-326). Lower
        # -MinRsaKeySize only for a deliberate legacy migration.
        $impRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($pfx)
        if ($impRsa) {
            $rbits = $impRsa.KeySize; $impRsa.Dispose()
            if ($rbits -lt $MinRsaKeySize) { throw "PFX RSA key is $rbits-bit, below the $MinRsaKeySize-bit minimum. Re-issue with a stronger key, or pass -MinRsaKeySize to override." }
        } else {
            $impEc = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($pfx)
            if ($impEc) { $ebits = $impEc.KeySize; $impEc.Dispose(); if ($ebits -lt 256) { throw "PFX ECDSA key is $ebits-bit, below the 256-bit minimum. Re-issue with a stronger key." } }
        }

        # 2) Re-export to a normalized PKCS#12 under a random transient password (from a
        #    CSPRNG), then pull out the EncryptedPrivateKeyInfo (the pkcs8ShroudedKeyBag).
        #    .NET always writes the key bag into a plaintext SafeContents, so it can be
        #    located without decrypting anything; the key itself stays encrypted.
        #    The password is built as a pinned char[] -> SecureString so it is NEVER
        #    materialized as an immutable managed string (which could not be zeroed,
        #    CWE-316). All intermediate buffers are cleared immediately.
        $rngBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($rngBytes) } finally { $rng.Dispose() }
        $pwChars = New-Object char[] ([int][Math]::Ceiling($rngBytes.Length / 3.0) * 4)
        $nChars  = [Convert]::ToBase64CharArray($rngBytes, 0, $rngBytes.Length, $pwChars, 0)
        [Array]::Clear($rngBytes, 0, $rngBytes.Length)
        $tmpSec = New-Object System.Security.SecureString
        for ($i = 0; $i -lt $nChars; $i++) { $tmpSec.AppendChar($pwChars[$i]) }
        $tmpSec.MakeReadOnly()
        [Array]::Clear($pwChars, 0, $pwChars.Length)

        try {
            $reexport = $pfx.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $tmpSec)
        } catch {
            if ($usedEphemeral) {
                # This runtime (e.g. Windows PowerShell 5.1) cannot re-export an ephemeral
                # key set. Reload with a persisted Exportable key set and retry once. This
                # reintroduces the transient on-disk key container only on that legacy path.
                $pfx.Dispose()
                $pfx = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $Password, $skf::Exportable)
                $usedEphemeral = $false
                $reexport = $pfx.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $tmpSec)
            } else { throw }
        }
        $epki     = Get-VbsKeyShroudedKey -Pkcs12Bytes $reexport
        if (-not $epki) { throw "Could not locate an encrypted private key inside the PFX (unsupported PKCS#12 layout)." }

        $pubCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx.RawData)
        $isRsa   = ($pubCert.GetKeyAlgorithm() -eq '1.2.840.113549.1.1.1')

        # 3) Import the (still-encrypted) key into the VBS (VBS) KSP under a persisted
        #    name. NCryptImportKey receives the key name and the decryption secret via a
        #    buffer list; Windows decrypts the PKCS#8 straight into VBS isolation.
        $flags = $USE_VBS
        if ($machine) { $flags = $flags -bor $MACHINE_FLAG }
        # -Force overwrites an existing (irreversible) key -- gate it behind ShouldProcess.
        if ($Force -and $PSCmdlet.ShouldProcess($KeyName, 'Overwrite existing VBS key (irreversible)')) {
            $flags = $flags -bor $OVERWRITE
        }

        if ([VbsNative]::NCryptOpenStorageProvider([ref]$prov,$script:VbsProvider,0)) { throw 'NCryptOpenStorageProvider failed' }

        # Two-element NCryptBuffer array: [0] key name, [1] decryption secret.
        $bufSize = $M::SizeOf([type]([VbsNative+NCryptBuffer]))
        $arrPtr  = $M::AllocHGlobal($bufSize * 2)

        $namePtr = $M::StringToHGlobalUni($KeyName)
        $b0 = New-Object VbsNative+NCryptBuffer
        $b0.cbBuffer = [uint32](($KeyName.Length + 1) * 2); $b0.BufferType = $KEYNAME_BUF; $b0.pvBuffer = $namePtr
        $M::StructureToPtr($b0, $arrPtr, $false)

        $secretPtr = $M::SecureStringToGlobalAllocUnicode($tmpSec)
        $b1 = New-Object VbsNative+NCryptBuffer
        $b1.cbBuffer = [uint32](($tmpSec.Length + 1) * 2); $b1.BufferType = $SECRET_BUF; $b1.pvBuffer = $secretPtr
        $M::StructureToPtr($b1, [IntPtr]($arrPtr.ToInt64() + $bufSize), $false)

        $desc = New-Object VbsNative+NCryptBufferDesc
        $desc.ulVersion = [uint32]0; $desc.cBuffers = [uint32]2; $desc.pBuffers = $arrPtr
        $descPtr = $M::AllocHGlobal($M::SizeOf([type]([VbsNative+NCryptBufferDesc])))
        $M::StructureToPtr($desc, $descPtr, $false)

        $s = [VbsNative]::NCryptImportKey($prov,[IntPtr]::Zero,'PKCS8_PRIVATEKEY',$descPtr,[ref]$hKey,$epki,[uint32]$epki.Length,$flags)
        if ($s -ne 0) {
            $hex = "0x{0:X8}" -f $s
            if ($hex -eq '0x8009000F') { throw "A VBS key named '$KeyName' already exists. Use -Force to overwrite." }
            throw "NCryptImportKey failed $hex (VBS unavailable?)"
        }

        # Verify the imported key is VBS-isolated.
        $b=New-Object byte[] 4; $cb=[uint32]0; $iso=0
        if ([VbsNative]::NCryptGetProperty($hKey,'Virtual Iso',$b,4,[ref]$cb,0) -eq 0) { $iso=[BitConverter]::ToInt32($b,0) }
        if ($iso -ne 1) { throw "Imported key is not VBS-isolated (Virtual Iso=$iso)." }
    } finally {
        if ($pfx) { $pfx.Dispose() }   # releases the source PFX's temporary key container
        if ($hKey -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($hKey) }
        if ($prov -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($prov) }
        if ($descPtr   -ne [IntPtr]::Zero) { $M::FreeHGlobal($descPtr) }
        if ($secretPtr -ne [IntPtr]::Zero) { $M::ZeroFreeGlobalAllocUnicode($secretPtr) }
        if ($namePtr   -ne [IntPtr]::Zero) { $M::FreeHGlobal($namePtr) }
        if ($arrPtr    -ne [IntPtr]::Zero) { $M::FreeHGlobal($arrPtr) }
        if ($tmpSec)   { $tmpSec.Dispose() }
        # Zero the encrypted key material and the transient PKCS#12 in memory.
        if ($epki)     { [Array]::Clear($epki, 0, $epki.Length) }
        if ($reexport) { [Array]::Clear($reexport, 0, $reexport.Length) }
    }

    # 4) Install the certificate (public part) and bind it to the imported VBS key.
    $openOpts = if ($machine) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
                else          { [System.Security.Cryptography.CngKeyOpenOptions]::None }
    $cngKey  = [System.Security.Cryptography.CngKey]::Open($KeyName, [System.Security.Cryptography.CngProvider]::new($script:VbsProvider), $openOpts)
    if ($isRsa) {
        $kcng = [System.Security.Cryptography.RSACng]::new($cngKey)
        $certWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($pubCert, $kcng)
    } else {
        $kcng = [System.Security.Cryptography.ECDsaCng]::new($cngKey)
        $certWithKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($pubCert, $kcng)
    }
    $loc = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $loc)
    try {
        $store.Open('ReadWrite')
        $store.Add($certWithKey)
    } finally {
        $store.Close()
    }

    Write-Host "Imported PFX into VBS: cert '$($certWithKey.Thumbprint)' bound to VBS-isolated key '$KeyName' (Cert:\$StoreLocation\My)." -ForegroundColor Green

    # Audit for leftover copies of this keypair (e.g. the source PFX had an exportable
    # software key that was previously imported elsewhere). Warn, or remove with the switch.
    Assert-VbsKeyExclusive -Thumbprint $certWithKey.Thumbprint -KeepContainer $KeyName -Machine:$machine -Remove:$RemoveResidualKeyCopies

    # 5) Optionally remove the source PFX. It still holds an *exportable* copy of the
    #    private key, whereas the imported VBS key is non-exportable/VBS-isolated,
    #    so deleting the PFX shrinks the attack surface. ShouldProcess prompts before
    #    the destructive delete (respects -WhatIf / -Confirm / -Confirm:$false).
    if ($DeleteSourcePfx) {
        $resolvedPfx = (Resolve-Path -LiteralPath $PfxPath).Path
        if ($PSCmdlet.ShouldProcess($resolvedPfx, 'Securely delete source PFX (overwrite then remove)')) {
            try {
                # -VerifyIdentity binds the delete to the file we captured at import start,
                # so a path/junction swap during the operation is refused (TOCTOU).
                Remove-VbsKeyFileSecurely -Path $resolvedPfx -VerifyIdentity `
                    -ExpectedVolumeSerial $srcId.Vol -ExpectedFileIndexHigh $srcId.IdxHigh -ExpectedFileIndexLow $srcId.IdxLow
                Write-Host "Source PFX overwritten and deleted (best-effort): $resolvedPfx" -ForegroundColor Green
                Write-Warning ("Best-effort wipe only: on SSD/wear-leveled/copy-on-write/journaling volumes, or where " +
                    "VSS snapshots exist, original bytes may remain recoverable. Full-disk encryption (e.g. BitLocker) is the primary control.")
            } catch {
                Write-Warning "Import succeeded, but secure delete of '$resolvedPfx' failed: $($_.Exception.Message)"
            }
        }
    }

    $certWithKey
}

# ---------------------------------------------------------------------------
# Get-VbsKeyClaimNonce (internal): extract the signature-covered nonce from a
# VBS key-attestation statement (VKAS) blob so a verifier can compare it to the
# challenge it issued. Returns $null if the blob has no nonce / is not a VKAS.
#
# VKAS layout: NCRYPT_VBS_KEY_ATTESTATION_STATEMENT (12 bytes: Magic,Version,ClaimType)
#   followed by NCRYPT_VBS_ROOT_ATTESTATION_HEADER (24 bytes: Magic,Version,
#   cbAttributes,cbNonce,cbReport,cbSignature), then Attributes[], Nonce[], ...
# ---------------------------------------------------------------------------
function Get-VbsKeyClaimNonce {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][byte[]]$ClaimBlob)

    if ($ClaimBlob.Length -lt 36) { return $null }
    if ([BitConverter]::ToUInt32($ClaimBlob,0)  -ne 0x53414B56) { return $null }  # 'VKAS'
    if ([BitConverter]::ToUInt32($ClaimBlob,12) -ne 0x48435256) { return $null }  # 'VRCH'
    $cbAttributes = [BitConverter]::ToUInt32($ClaimBlob,20)
    $cbNonce      = [BitConverter]::ToUInt32($ClaimBlob,24)
    if ($cbNonce -eq 0) { return $null }
    $nonceStart = 36 + $cbAttributes
    if (($nonceStart + $cbNonce) -gt $ClaimBlob.Length) { return $null }
    return ,($ClaimBlob[$nonceStart..($nonceStart + $cbNonce - 1)])
}

# ===========================================================================
# New-VbsKeyAttestation: produce a VBS key-attestation claim proving that
# an existing VBS key is protected inside VBS (VTL1). The claim is a
# secure-kernel-signed statement (NCryptCreateClaim, NCRYPT_CLAIM_VBS_ROOT) that
# a relying party (or CA) can verify to confirm the key is non-exportable and
# device-bound. An optional -Nonce (challenge) is embedded in, and signed by,
# the claim to prevent replay.
# ===========================================================================
function New-VbsKeyAttestation {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9._\- ]{0,511}\z')]
        [string]$KeyName,
        # Optional relying-party challenge (1-1024 bytes). Embedded in and signed by the
        # claim so the verifier can prove freshness / prevent replay.
        [byte[]]$Nonce,
        # Optional path to also write the raw (binary) claim blob for out-of-band verification.
        [string]$OutputPath,
        [switch]$Machine                         # attest a machine-store key (run elevated)
    )

    # If the caller explicitly passed -Nonce, it must be a non-empty challenge: silently
    # dropping it would remove the replay protection the caller intended (fail closed).
    # Omitting -Nonce entirely is still fine (produces a no-challenge claim).
    if ($PSBoundParameters.ContainsKey('Nonce')) {
        if ($null -eq $Nonce -or $Nonce.Length -lt 1) {
            throw "-Nonce was specified but is empty/null; pass a non-empty byte[] challenge (1-1024 bytes) or omit -Nonce."
        }
        if ($Nonce.Length -gt 1024) { throw "-Nonce must be 1-1024 bytes (got $($Nonce.Length))." }
    }

    $M = [System.Runtime.InteropServices.Marshal]
    # ncrypt.h constants:
    #   0x00000004 = NCRYPT_CLAIM_VBS_KEY_ATTESTATION_STATEMENT (auto-transformed to
    #                NCRYPT_CLAIM_VBS_ROOT in NCryptCreateClaim/VerifyClaim; available RS3+)
    #   49         = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE
    #   0x20       = NCRYPT_MACHINE_KEY_FLAG
    $CLAIM_VBS = [uint32]0x00000004
    $NONCE_BUF = [uint32]49
    $openFlags = if ($Machine) { [uint32]0x00000020 } else { [uint32]0 }

    $prov=[IntPtr]::Zero; $key=[IntPtr]::Zero
    $pNonce=[IntPtr]::Zero; $pBuf=[IntPtr]::Zero; $pDesc=[IntPtr]::Zero
    $blob=$null
    try {
        if ([VbsNative]::NCryptOpenStorageProvider([ref]$prov,$script:VbsProvider,0)) { throw 'NCryptOpenStorageProvider failed' }
        $s = [VbsNative]::NCryptOpenKey($prov,[ref]$key,$KeyName,0,$openFlags)
        if ($s -ne 0) {
            $hex = "0x{0:X8}" -f $s
            if ($hex -eq '0x80090016') { throw "VBS key '$KeyName' not found (NTE_BAD_KEYSET)." }
            throw "NCryptOpenKey('$KeyName') failed $hex"
        }

        # Refuse to attest a key that is not actually VBS-isolated: a claim over a plain
        # software key would be misleading, and the secure kernel would reject it anyway.
        $isoBuf=New-Object byte[] 4; $isoCb=[uint32]0; $isolated=0
        if ([VbsNative]::NCryptGetProperty($key,'Virtual Iso',$isoBuf,4,[ref]$isoCb,0) -eq 0) { $isolated=[BitConverter]::ToInt32($isoBuf,0) }
        if ($isolated -ne 1) { throw "Key '$KeyName' is NOT VBS-isolated (Virtual Iso=$isolated); nothing to attest." }

        # Build the optional nonce parameter list (NCryptBufferDesc -> one NCryptBuffer).
        $pParams=[IntPtr]::Zero
        if ($Nonce) {
            $pNonce=$M::AllocHGlobal($Nonce.Length); $M::Copy($Nonce,0,$pNonce,$Nonce.Length)
            $buf=New-Object VbsNative+NCryptBuffer; $buf.cbBuffer=[uint32]$Nonce.Length; $buf.BufferType=$NONCE_BUF; $buf.pvBuffer=$pNonce
            $pBuf=$M::AllocHGlobal($M::SizeOf([type]([VbsNative+NCryptBuffer]))); $M::StructureToPtr($buf,$pBuf,$false)
            $desc=New-Object VbsNative+NCryptBufferDesc; $desc.ulVersion=0; $desc.cBuffers=1; $desc.pBuffers=$pBuf
            $pDesc=$M::AllocHGlobal($M::SizeOf([type]([VbsNative+NCryptBufferDesc]))); $M::StructureToPtr($desc,$pDesc,$false)
            $pParams=$pDesc
        }

        # Two-call pattern: size query, then fill.
        $cb=[uint32]0
        $s=[VbsNative]::NCryptCreateClaim($key,[IntPtr]::Zero,$CLAIM_VBS,$pParams,$null,0,[ref]$cb,0)
        if ($s -ne 0) { throw ("NCryptCreateClaim (size) failed 0x{0:X8}. VBS key attestation may be unavailable on this OS build." -f $s) }
        $blob=New-Object byte[] $cb
        $s=[VbsNative]::NCryptCreateClaim($key,[IntPtr]::Zero,$CLAIM_VBS,$pParams,$blob,$cb,[ref]$cb,0)
        if ($s -ne 0) { throw ("NCryptCreateClaim (fill) failed 0x{0:X8}" -f $s) }
    } finally {
        if ($pNonce -ne [IntPtr]::Zero) { $M::FreeHGlobal($pNonce) }
        if ($pBuf   -ne [IntPtr]::Zero) { $M::FreeHGlobal($pBuf) }
        if ($pDesc  -ne [IntPtr]::Zero) { $M::FreeHGlobal($pDesc) }
        if ($key    -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($key) }
        if ($prov   -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($prov) }
    }

    # Export the subject's PUBLIC key blob so a relying party can verify the claim OFF-BOX
    # (Test-VbsKeyAttestation -PublicKeyBlob) without opening this key by name. The
    # public part is always exportable, even for a non-exportable VBS key.
    $pubBlob=$null; $keyAlg=$null
    try {
        $openOpts = if ($Machine) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey }
                    else          { [System.Security.Cryptography.CngKeyOpenOptions]::None }
        $ck=[System.Security.Cryptography.CngKey]::Open($KeyName,[System.Security.Cryptography.CngProvider]::new($script:VbsProvider),$openOpts)
        try {
            $keyAlg=$ck.AlgorithmGroup.AlgorithmGroup                       # 'RSA' / 'ECDSA' / 'ECDH'
            $fmt = if ($keyAlg -eq 'RSA') { 'RSAPUBLICBLOB' } else { 'ECCPUBLICBLOB' }
            $pubBlob=$ck.Export([System.Security.Cryptography.CngKeyBlobFormat]::new($fmt))
        } finally { $ck.Dispose() }
    } catch {
        Write-Warning "Public key blob export for '$KeyName' failed (remote verification will be unavailable): $($_.Exception.Message)"
    }

    $resolvedOut=$null
    if ($OutputPath) {
        $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        # Writing the claim file is the only state change, so gate it behind ShouldProcess
        # (-WhatIf still returns the claim object without touching disk).
        if ($PSCmdlet.ShouldProcess($full,'Write VBS attestation claim to file')) {
            [System.IO.File]::WriteAllBytes($full,$blob)
            $resolvedOut=$full
            Write-Host "Attestation claim ($($blob.Length) bytes) written to '$full'." -ForegroundColor Green
        }
    }

    Write-Host "Created VBS key-attestation claim for '$KeyName' ($($blob.Length) bytes)." -ForegroundColor Green
    [PSCustomObject]@{
        KeyName    = $KeyName
        Machine    = [bool]$Machine
        ClaimType  = 'VBS_ROOT'
        ClaimBytes = $blob.Length
        Nonce      = if ($Nonce) { [Convert]::ToBase64String($Nonce) } else { $null }
        Claim            = [Convert]::ToBase64String($blob)
        ClaimRaw         = $blob
        KeyAlgorithm     = $keyAlg
        PublicKeyBlob    = if ($pubBlob) { [Convert]::ToBase64String($pubBlob) } else { $null }
        PublicKeyBlobRaw = $pubBlob
        OutputPath       = $resolvedOut
    }
}

# ===========================================================================
# Get-VbsPublicKeyBlob: extract a subject's public key as a BCRYPT public
# key blob (RSAPUBLICBLOB / ECCPUBLICBLOB) from a certificate (.cer file or an
# X509Certificate2) or a PKCS#10 CSR (.req file). A relying party feeds the
# result to Test-VbsKeyAttestation -PublicKeyBlob to verify a claim against
# the key in the request it trusts. Supports RSA and ECDSA.
# ===========================================================================
function Get-VbsPublicKeyBlob {
    [CmdletBinding(DefaultParameterSetName='CertPath')]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, ParameterSetName='CertPath')][string]$CertPath,
        [Parameter(Mandatory, ParameterSetName='Certificate')][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory, ParameterSetName='CsrPath')][string]$CsrPath
    )
    $rsa=$null; $ecdsa=$null; $ownCert=$null
    try {
        switch ($PSCmdlet.ParameterSetName) {
            'CertPath' {
                $full=(Resolve-Path -LiteralPath $CertPath).Path
                $ownCert=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($full)
                $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($ownCert)
                if (-not $rsa) { $ecdsa=[System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($ownCert) }
            }
            'Certificate' {
                $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
                if (-not $rsa) { $ecdsa=[System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate) }
            }
            'CsrPath' {
                # PKCS#10 parsing needs CertificateRequest.LoadSigningRequest (.NET 7+ / PS 7.3+).
                if (-not ([System.Security.Cryptography.X509Certificates.CertificateRequest].GetMethods().Name -contains 'LoadSigningRequest')) {
                    throw "Reading a CSR requires .NET 7+ (PowerShell 7.3+). On Windows PowerShell 5.1, verify from the issued certificate (-CertPath) instead."
                }
                $full=(Resolve-Path -LiteralPath $CsrPath).Path
                $der=[Convert]::FromBase64String(((Get-Content -LiteralPath $full -Raw) -replace '-----[^-]+-----','' -replace '\s',''))
                $req=[System.Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequest($der,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::Default)
                $rsa=$req.PublicKey.GetRSAPublicKey()
                if (-not $rsa) { $ecdsa=$req.PublicKey.GetECDsaPublicKey() }
            }
        }
        if ($rsa) {
            $t=[System.Security.Cryptography.RSACng]::new()
            try { $t.ImportParameters($rsa.ExportParameters($false)); return ,($t.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::new('RSAPUBLICBLOB'))) }
            finally { $t.Dispose() }
        } elseif ($ecdsa) {
            $t=[System.Security.Cryptography.ECDsaCng]::new()
            try { $t.ImportParameters($ecdsa.ExportParameters($false)); return ,($t.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::new('ECCPUBLICBLOB'))) }
            finally { $t.Dispose() }
        }
        throw "Could not extract an RSA or ECDSA public key from the supplied input."
    } finally {
        if ($rsa)     { $rsa.Dispose() }
        if ($ecdsa)   { $ecdsa.Dispose() }
        if ($ownCert) { $ownCert.Dispose() }
    }
}

# ===========================================================================
# Test-VbsKeyAttestation: verify a VBS key-attestation claim produced by
# New-VbsKeyAttestation. Confirms the secure-kernel signature (NCryptVerifyClaim,
# NCRYPT_CLAIM_VBS_ROOT) and returns the trustlet details (CreatedInIsolation,
# TrustletId, SecurityVersion, Debuggable). Optionally checks that the embedded,
# signature-covered nonce matches an -ExpectedNonce challenge. Read-only.
# ===========================================================================
function Test-VbsKeyAttestation {
    [CmdletBinding(DefaultParameterSetName='Base64')]
    [OutputType([PSCustomObject])]
    param(
        # --- Subject key: choose exactly ONE. -KeyName opens the key locally; the rest
        #     verify OFF-BOX from just the subject's public key (no private key needed):
        #     -PublicKeyBlob / -PublicKeyBlobBase64 (raw blob), or -CertPath / -Certificate
        #     / -CsrPath (the RA extracts the key from the request artifact it trusts). ---
        [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9._\- ]{0,511}\z')]
        [string]$KeyName,                                    # local subject (by container name)
        [byte[]]$PublicKeyBlob,                              # remote subject: BCRYPT public key blob (RSA/ECC)
        [string]$PublicKeyBlobBase64,                        # remote subject: same blob, base64-encoded
        [string]$CertPath,                                   # remote subject: verify against a .cer file's key
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,  # remote subject: an X509 object
        [string]$CsrPath,                                    # remote subject: a PKCS#10 .req file (PS 7.3+)
        [Parameter(Mandatory, ParameterSetName='Base64')][string]$ClaimBase64,
        [Parameter(Mandatory, ParameterSetName='Bytes')][byte[]]$Claim,
        [Parameter(Mandatory, ParameterSetName='Path')][string]$ClaimPath,
        # Optional expected challenge; the embedded (signature-covered) nonce must match
        # or the attestation is reported INVALID (replay / wrong-claim protection).
        [byte[]]$ExpectedNonce,
        # .Accepted is a SECURE-BY-DEFAULT policy decision (see the computation below).
        # These switches RELAX it for callers who understand the trade-off -- each one
        # weakens the guarantee, so use sparingly:
        [switch]$AllowMissingChallenge,                      # accept even if no fresh -ExpectedNonce was verified (replay risk)
        [switch]$AllowImportedKey,                           # accept keys not born in VBS (CreatedInIsolation=$false, e.g. PFX imports)
        [switch]$AllowDebuggableTrustlet,                    # accept a debuggable trustlet
        [switch]$Machine                                     # local -KeyName in the machine store
    )

    $blob = switch ($PSCmdlet.ParameterSetName) {
        'Base64' { [Convert]::FromBase64String($ClaimBase64) }
        'Bytes'  { $Claim }
        'Path'   { [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ClaimPath).Path) }
    }
    if (-not $blob -or $blob.Length -lt 36) { throw 'Claim blob is empty or too small to be a VBS attestation statement.' }

    # Resolve exactly ONE subject source (to a local key name or a public key blob).
    # NOTE: wrap the whole pipeline in @() so a single match stays an ARRAY (otherwise
    # Where-Object returns the scalar string and $subjectParams[0] would index a char).
    $subjectParams = @(@('KeyName','PublicKeyBlob','PublicKeyBlobBase64','CertPath','Certificate','CsrPath') |
        Where-Object { $PSBoundParameters.ContainsKey($_) })
    if ($subjectParams.Count -ne 1) {
        throw "Specify exactly one subject: -KeyName, -PublicKeyBlob, -PublicKeyBlobBase64, -CertPath, -Certificate, or -CsrPath."
    }
    $hasName = $subjectParams[0] -eq 'KeyName'
    switch ($subjectParams[0]) {
        'PublicKeyBlobBase64' { $PublicKeyBlob = [Convert]::FromBase64String($PublicKeyBlobBase64) }
        'CertPath'            { $PublicKeyBlob = Get-VbsPublicKeyBlob -CertPath $CertPath }
        'Certificate'         { $PublicKeyBlob = Get-VbsPublicKeyBlob -Certificate $Certificate }
        'CsrPath'             { $PublicKeyBlob = Get-VbsPublicKeyBlob -CsrPath $CsrPath }
    }
    if (-not $hasName -and (($null -eq $PublicKeyBlob) -or ($PublicKeyBlob.Length -lt 1))) {
        throw "Could not obtain a public key from the supplied subject."
    }
    $subjectLabel = if ($hasName) { "'$KeyName'" } else { 'the subject key' }

    $M = [System.Runtime.InteropServices.Marshal]
    #   0x00000004 = NCRYPT_CLAIM_VBS_KEY_ATTESTATION_STATEMENT (-> VBS_ROOT)
    #   0x00100000 = NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG
    #   94         = NCRYPTBUFFER_VBS_ATTESTATION_STATEMENT_ROOT_DETAILS
    #   0x20       = NCRYPT_MACHINE_KEY_FLAG
    $CLAIM_VBS      = [uint32]0x00000004
    $RETURN_DETAILS = [uint32]0x00100000
    $ROOT_DETAILS   = 94
    $openFlags = if ($Machine) { [uint32]0x00000020 } else { [uint32]0 }

    $prov=[IntPtr]::Zero; $key=[IntPtr]::Zero; $pOut=[IntPtr]::Zero; $outBuffersPtr=[IntPtr]::Zero
    $details=$null; $status=0
    try {
        if ([VbsNative]::NCryptOpenStorageProvider([ref]$prov,$script:VbsProvider,0)) { throw 'NCryptOpenStorageProvider failed' }
        if ($hasName) {
            $s=[VbsNative]::NCryptOpenKey($prov,[ref]$key,$KeyName,0,$openFlags)
            if ($s -ne 0) {
                $hex = "0x{0:X8}" -f $s
                if ($hex -eq '0x80090016') { throw "VBS key '$KeyName' not found (NTE_BAD_KEYSET)." }
                throw "NCryptOpenKey('$KeyName') failed $hex"
            }
        } else {
            # Remote verification: import the caller-supplied PUBLIC key blob to a
            # public-only handle (no private key needed). Blob type is chosen from the
            # BCRYPT magic ('RSA1' => RSA, otherwise ECC).
            $blobType = if ($PublicKeyBlob.Length -ge 4 -and [BitConverter]::ToUInt32($PublicKeyBlob,0) -eq 0x31415352) { 'RSAPUBLICBLOB' } else { 'ECCPUBLICBLOB' }
            $s=[VbsNative]::NCryptImportKey($prov,[IntPtr]::Zero,$blobType,[IntPtr]::Zero,[ref]$key,$PublicKeyBlob,[uint32]$PublicKeyBlob.Length,0)
            if ($s -ne 0) { throw ("NCryptImportKey(public $blobType) failed 0x{0:X8} (malformed public key blob?)" -f $s) }
        }

        # Verify: authority = NULL (self-contained VBS root), NO input parameter list
        # (the nonce is validated as part of the signed report, not passed here), and
        # request the claim-details output buffer.
        $pOut=$M::AllocHGlobal($M::SizeOf([type]([VbsNative+NCryptBufferDesc])))
        $M::StructureToPtr((New-Object VbsNative+NCryptBufferDesc),$pOut,$false)
        $status=[VbsNative]::NCryptVerifyClaim($key,[IntPtr]::Zero,$CLAIM_VBS,[IntPtr]::Zero,$blob,[uint32]$blob.Length,$pOut,$RETURN_DETAILS)
        if ($status -eq 0) {
            $outDesc=[VbsNative+NCryptBufferDesc]$M::PtrToStructure($pOut,[type]([VbsNative+NCryptBufferDesc]))
            $outBuffersPtr=$outDesc.pBuffers   # NCrypt-allocated; released in finally on every path
            for ($i=0; $i -lt $outDesc.cBuffers; $i++) {
                $nbPtr=[IntPtr]($outDesc.pBuffers.ToInt64() + $i*$M::SizeOf([type]([VbsNative+NCryptBuffer])))
                $nb=[VbsNative+NCryptBuffer]$M::PtrToStructure($nbPtr,[type]([VbsNative+NCryptBuffer]))
                if ($nb.BufferType -eq $ROOT_DETAILS -and $nb.cbBuffer -ge 24 -and $nb.pvBuffer -ne [IntPtr]::Zero) {
                    $kf=$M::ReadInt32($nb.pvBuffer,0)
                    $details=[PSCustomObject]@{
                        KeyFlags                = "0x{0:X}" -f $kf
                        CreatedInIsolation      = (($kf -band 0x1) -ne 0)   # NCRYPT_ISOLATED_KEY_FLAG_CREATED_IN_ISOLATION
                        TrustletId              = $M::ReadInt64($nb.pvBuffer,8)
                        TrustletSecurityVersion = $M::ReadInt32($nb.pvBuffer,16)
                        TrustletDebuggable      = ($M::ReadInt32($nb.pvBuffer,20) -ne 0)
                    }
                }
            }
        }
    } finally {
        # Free the NCrypt-allocated details buffer even if the parse loop above threw
        # (handle-leak hygiene; consistent with the finally-based cleanup elsewhere).
        if ($outBuffersPtr -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeBuffer($outBuffersPtr) }
        if ($pOut -ne [IntPtr]::Zero) { $M::FreeHGlobal($pOut) }
        if ($key  -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($key) }
        if ($prov -ne [IntPtr]::Zero) { [void][VbsNative]::NCryptFreeObject($prov) }
    }

    $valid = ($status -eq 0)
    $embeddedNonce=$null; $nonceMatch=$null
    if ($valid) {
        $embeddedNonce = Get-VbsKeyClaimNonce -ClaimBlob $blob
        if ($PSBoundParameters.ContainsKey('ExpectedNonce')) {
            $nonceMatch = ($null -ne $embeddedNonce) -and ($embeddedNonce.Length -eq $ExpectedNonce.Length)
            if ($nonceMatch) {
                for ($j=0; $j -lt $embeddedNonce.Length; $j++) {
                    if ($embeddedNonce[$j] -ne $ExpectedNonce[$j]) { $nonceMatch=$false; break }
                }
            }
            if (-not $nonceMatch) { $valid=$false }   # challenge mismatch -> not acceptable
        }
    }

    # .Accepted is the SECURE-BY-DEFAULT policy decision a relying party should act on --
    # NOT a synonym for signature validity (that is .Valid). By default it requires ALL of:
    #   * a genuine, non-tampered claim for this key (.Valid), AND
    #   * a fresh challenge that was actually supplied AND matched (replay protection), AND
    #   * the key was BORN in VBS (CreatedInIsolation -- rejects PFX imports), AND
    #   * a non-debuggable trustlet.
    # Each requirement can be individually relaxed with an -Allow* switch (fail-open only
    # when the caller explicitly opts in). This avoids a fail-open default (CWE-1188/636).
    $challengeVerified = $PSBoundParameters.ContainsKey('ExpectedNonce') -and ($nonceMatch -eq $true)
    $accepted = $valid
    if (-not $AllowMissingChallenge)   { $accepted = $accepted -and $challengeVerified }
    if (-not $AllowImportedKey)        { $accepted = $accepted -and [bool]($details -and $details.CreatedInIsolation) }
    if (-not $AllowDebuggableTrustlet) { $accepted = $accepted -and [bool]($details -and -not $details.TrustletDebuggable) }

    if (-not $valid) {
        $why = if ($nonceMatch -eq $false) { '; nonce mismatch' } else { '' }
        Write-Warning ("VBS attestation for $subjectLabel is INVALID (status 0x{0:X8}{1})." -f $status,$why)
    } elseif (-not $accepted) {
        $reasons = @()
        if (-not $AllowMissingChallenge   -and -not $challengeVerified)                              { $reasons += 'no fresh challenge verified (pass -ExpectedNonce, or -AllowMissingChallenge)' }
        if (-not $AllowImportedKey        -and -not ($details -and $details.CreatedInIsolation))     { $reasons += 'key not born-in-VBS / imported (or -AllowImportedKey)' }
        if (-not $AllowDebuggableTrustlet -and     ($details -and $details.TrustletDebuggable))      { $reasons += 'debuggable trustlet (or -AllowDebuggableTrustlet)' }
        Write-Warning ("VBS attestation for $subjectLabel is signature-VALID but NOT ACCEPTED by policy: " + ($reasons -join '; ') + '.')
    } else {
        Write-Host "VBS attestation for $subjectLabel is VALID and ACCEPTED." -ForegroundColor Green
    }

    [PSCustomObject]@{
        KeyName       = if ($hasName) { $KeyName } else { $null }
        SubjectSource = $subjectParams[0]
        Valid         = $valid
        Accepted      = $accepted
        Status        = "0x{0:X8}" -f $status
        Details       = $details
        EmbeddedNonce = if ($embeddedNonce) { [Convert]::ToBase64String($embeddedNonce) } else { $null }
        NonceMatch    = $nonceMatch
    }
}
