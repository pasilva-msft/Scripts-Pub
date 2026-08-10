<#
.SYNOPSIS
    Functional + security regression test harness for VbsKeyProtection.ps1.

.DESCRIPTION
    Exercises every public function and the VBS key attestation (v1.7.0) as pass/fail assertions,
    then cleans up ALL artifacts it creates (keys, certs, pending requests, temp
    files). Prints a final tally.

    Run this after any change to VbsKeyProtection.ps1 and before submitting a
    new version for a security scan, to catch regressions of past fixes.

.PARAMETER ModulePath
    Path to VbsKeyProtection.ps1. Defaults to the copy next to this script.

.NOTES
    Requires a VBS/VBS-capable host (Test-VbsKeyReady must return $true):
    Windows 11 / Server 2025 build >= 26052 with VBS running. Symlink-based tests
    are skipped automatically if symlink creation is not permitted.

    Author : Paulo da Silva

.EXAMPLE
    .\Test-VbsKeyProtection.ps1
    .\Test-VbsKeyProtection.ps1 -ModulePath C:\path\to\VbsKeyProtection.ps1
#>
[CmdletBinding()]
param(
    [string]$ModulePath = (Join-Path $PSScriptRoot 'VbsKeyProtection.ps1')
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference     = 'None'   # suppress ShouldProcess prompts for automation
if (-not (Test-Path -LiteralPath $ModulePath)) { throw "Module not found: $ModulePath" }
. $ModulePath

if (-not (Test-VbsKeyReady)) { throw "VBS is not available on this host (VBS/build prerequisites not met)." }

$prov = [System.Security.Cryptography.CngProvider]::new('Microsoft Software Key Storage Provider')
$sfx  = [guid]::NewGuid().ToString('N').Substring(0,8)
$script:pass = 0; $script:fail = 0
$script:keys   = New-Object System.Collections.Generic.HashSet[string]
$script:thumbs = New-Object System.Collections.Generic.HashSet[string]
$script:files  = New-Object System.Collections.Generic.HashSet[string]

function RegKey($n){ if($n){[void]$script:keys.Add($n)} ; $n }
function RegThumb($t){ if($t){[void]$script:thumbs.Add($t)} ; $t }
function RegFile($f){ if($f){[void]$script:files.Add($f)} ; $f }
function Ok($m){ $script:pass++; Write-Host ("  [PASS] {0}" -f $m) -ForegroundColor Green }
function Bad($m){ $script:fail++; Write-Host ("  [FAIL] {0}" -f $m) -ForegroundColor Red }
function Assert($cond,$m){ if($cond){Ok $m}else{Bad $m} }
function AssertThrows([scriptblock]$sb,$m,$pattern){
    try { & $sb; Bad "$m (expected throw, none)" }
    catch { if(-not $pattern -or $_.Exception.Message -match $pattern){ Ok "$m -> $($_.Exception.Message.Split([Environment]::NewLine)[0])" } else { Bad "$m (wrong error: $($_.Exception.Message))" } }
}
function New-SoftwareKey($name){
    $cp=[System.Security.Cryptography.CngKeyCreationParameters]::new(); $cp.Provider=$prov
    ([System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa,$name,$cp)).Dispose()
    RegKey $name
}
function New-TestPfx($subj,[switch]$Ecdsa){
    $a=@{ Subject=$subj; CertStoreLocation='Cert:\CurrentUser\My'; KeyExportPolicy='Exportable'; Provider='Microsoft Software Key Storage Provider' }
    if($Ecdsa){ $a['KeyAlgorithm']='ECDSA_nistP256' }
    $c=New-SelfSignedCertificate @a
    $tp=$c.Thumbprint
    $kn = if($Ecdsa){ [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c).Key.KeyName }
          else       { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c).Key.KeyName }
    $pw=ConvertTo-SecureString 'T-Pw-123!' -AsPlainText -Force
    $path=RegFile (Join-Path $env:TEMP ("vbst_{0}.pfx" -f [guid]::NewGuid().ToString('N')))
    Export-PfxCertificate -Cert $c -FilePath $path -Password $pw | Out-Null
    Remove-Item "Cert:\CurrentUser\My\$tp" -Force
    try { ([System.Security.Cryptography.CngKey]::Open($kn,$prov)).Delete() } catch {}   # remove source software container
    [pscustomobject]@{ Path=$path; Pw=$pw }
}

try {
  Write-Host "=== 1. Prereqs / version ===" -ForegroundColor Cyan
  Assert ((Test-VbsKeyReady) -eq $true) "Test-VbsKeyReady = True"
  Assert ($null -ne (Get-VbsKeyVersion).Version) "Get-VbsKeyVersion returns a version ($((Get-VbsKeyVersion).Version))"

  Write-Host "`n=== 2. New-VbsKey (+ -Bits ValidateRange, PreferFallback, Force) ===" -ForegroundColor Cyan
  $k=RegKey "vbs-t-rsa-$sfx"; $wv=$null
  New-VbsKey -Name $k -Algorithm RSA -Bits 2048 -Confirm:$false -WarningVariable wv | Out-Null
  Assert (-not $wv) "RSA 2048 key: no downgrade warning (VBS-isolated)"
  AssertThrows { New-VbsKey -Name "vbs-t-weak-$sfx" -Bits 1024 -Confirm:$false } "-Bits 1024 rejected" 'minimum allowed range of 2048'
  AssertThrows { New-VbsKey -Name "vbs-t-weak-$sfx" -Bits 512 -Confirm:$false } "-Bits 512 rejected" '2048'
  $k4=RegKey "vbs-t-rsa4096-$sfx"; New-VbsKey -Name $k4 -Bits 4096 -Confirm:$false | Out-Null
  Assert ((Test-VbsKeyUsable -Name $k4).CryptoUsable) "RSA 4096 key usable"
  $ck4=[System.Security.Cryptography.CngKey]::Open($k4,$prov); $bits4=[System.Security.Cryptography.RSACng]::new($ck4).KeySize; $ck4.Dispose()
  Assert ($bits4 -eq 4096) "4096-bit request produces a 4096-bit key (post-finalize size verification)"
  $ke=RegKey "vbs-t-ecc256-$sfx"; New-VbsKey -Name $ke -Algorithm ECDSA_P256 -Confirm:$false | Out-Null
  Assert ((Test-VbsKeyUsable -Name $ke).CryptoUsable) "ECDSA_P256 key usable"
  $ke3=RegKey "vbs-t-ecc384-$sfx"; New-VbsKey -Name $ke3 -Algorithm ECDSA_P384 -Confirm:$false | Out-Null
  Assert ((Test-VbsKeyUsable -Name $ke3).CryptoUsable) "ECDSA_P384 key usable"
  AssertThrows { New-VbsKey -Name $k -Confirm:$false } "duplicate name -> NTE_EXISTS" 'already exists'
  New-VbsKey -Name $k -Force -Confirm:$false | Out-Null; Ok "duplicate name + -Force overwrote"
  $auto=RegKey (New-VbsKey -Confirm:$false); Assert ($auto -match '^vbs-[0-9a-f\-]{36}$') "auto-generated vbs-<GUID> name"
  $kp=RegKey "vbs-t-pref-$sfx"; $wp=$null; New-VbsKey -Name $kp -PreferFallback -Confirm:$false -WarningVariable wp | Out-Null
  Assert (-not $wp) "-PreferFallback on VBS host: isolated, no downgrade warning"

  Write-Host "`n=== 3. Get-VbsKey ===" -ForegroundColor Cyan
  $list=@(Get-VbsKey)
  Assert (($list | Where-Object { $_.Name -eq $k4 }).Count -ge 1) "Get-VbsKey lists a created VBS key"

  Write-Host "`n=== 4. Test-VbsKeyUsable ===" -ForegroundColor Cyan
  $probe=Test-VbsKeyUsable -Name $ke
  Assert ($probe.Resolves -and $probe.CryptoUsable) "live key: Resolves + CryptoUsable"
  $probeN=Test-VbsKeyUsable -Name "vbs-does-not-exist-$sfx"
  Assert (-not $probeN.Resolves) "nonexistent key: Resolves=False"

  Write-Host "`n=== 5. Remove-VbsKey (+ -WhatIf) ===" -ForegroundColor Cyan
  $kr=RegKey "vbs-t-del-$sfx"; New-VbsKey -Name $kr -Confirm:$false | Out-Null
  Remove-VbsKey -Name $kr -WhatIf
  Assert ((Test-VbsKeyUsable -Name $kr).Resolves) "-WhatIf did NOT delete"
  Remove-VbsKey -Name $kr -Confirm:$false
  Assert (-not (Test-VbsKeyUsable -Name $kr).Resolves) "delete removed the key immediately"

  Write-Host "`n=== 6. New-VbsKeySelfSignedCertificate (+ post-binding, reuse checks) ===" -ForegroundColor Cyan
  $c1=New-VbsKeySelfSignedCertificate -Subject "CN=kgt-ss-$sfx" -KeyName (RegKey "vbs-t-ss-$sfx") -DnsName "kgt-$sfx.contoso.com"
  RegThumb $c1.Thumbprint; Assert ($c1.HasPrivateKey) "RSA self-signed cert created (post-binding isolation OK)"
  $c1e=New-VbsKeySelfSignedCertificate -Subject "CN=kgt-sse-$sfx" -KeyName (RegKey "vbs-t-sse-$sfx") -Algorithm ECDSA_P256
  RegThumb $c1e.Thumbprint; Assert ($c1e.HasPrivateKey) "ECDSA self-signed cert created"
  $kx=RegKey "vbs-t-reuse-$sfx"; New-VbsKey -Name $kx -Confirm:$false | Out-Null
  $c1r=New-VbsKeySelfSignedCertificate -Subject "CN=kgt-reuse-$sfx" -KeyName $kx -UseExistingKey
  RegThumb $c1r.Thumbprint; Assert ($c1r.HasPrivateKey) "-UseExistingKey (VBS) bound OK"
  New-SoftwareKey (RegKey "vbs-t-swreuse-$sfx") | Out-Null
  AssertThrows { New-VbsKeySelfSignedCertificate -Subject "CN=kgt-bad-$sfx" -KeyName "vbs-t-swreuse-$sfx" -UseExistingKey } "-UseExistingKey software key REFUSED" 'NOT VBS-isolated'
  AssertThrows { New-VbsKeySelfSignedCertificate -Subject "CN=x" -UseExistingKey } "-UseExistingKey without -KeyName throws" '-KeyName is required'
  Assert ($c1.KeyName -eq "vbs-t-ss-$sfx") "self-signed cert exposes -KeyName property"
  $cAuto=New-VbsKeySelfSignedCertificate -Subject "CN=kgt-auto-$sfx"
  RegThumb $cAuto.Thumbprint; RegKey $cAuto.KeyName
  Assert ($cAuto.KeyName -match '^vbs-[0-9a-fA-F-]{36}$') "self-signed auto-generates + returns vbs-<GUID> KeyName"

  Write-Host "`n=== 7. New-VbsKeyCsr (+ INF/SAN validation, certreq abs path, reuse) ===" -ForegroundColor Cyan
  $req1=RegFile (Join-Path $env:TEMP "vbst_csr_$sfx.req")
  $csrObj=New-VbsKeyCsr -Subject "CN=kgt-csr-$sfx,O=Contoso" -KeyName (RegKey "vbs-t-csr-$sfx") -OutputPath $req1 -DnsName "kgt-$sfx.contoso.com"
  Assert ((Test-Path $req1) -and (Get-Item $req1).Length -gt 0) "CSR created (signed via System32 certreq)"
  Assert ($csrObj.KeyName -eq "vbs-t-csr-$sfx") "CSR return exposes -KeyName property"
  $reqAuto=RegFile (Join-Path $env:TEMP "vbst_csrauto_$sfx.req")
  $csrAuto=New-VbsKeyCsr -Subject "CN=kgt-csrauto-$sfx" -OutputPath $reqAuto
  RegKey $csrAuto.KeyName
  Assert ($csrAuto.KeyName -match '^vbs-[0-9a-fA-F-]{36}$') "CSR auto-generates + returns vbs-<GUID> KeyName"
  $attAuto=New-VbsKeyAttestation -KeyName $csrAuto.KeyName 6>$null
  $vAuto=Test-VbsKeyAttestation -KeyName $csrAuto.KeyName -ClaimBase64 $attAuto.Claim 6>$null
  Assert ($vAuto.Valid) "auto-named CSR key is attestable via returned KeyName"
  AssertThrows { New-VbsKeyCsr -Subject 'CN=a"b' -KeyName (RegKey "vbs-t-inf1-$sfx") -OutputPath (RegFile (Join-Path $env:TEMP "vbst_inf1_$sfx.req")) } "Subject with quote rejected (INF injection)" 'illegal characters'
  AssertThrows { New-VbsKeyCsr -Subject "CN=ok-$sfx" -KeyName (RegKey "vbs-t-inf2-$sfx") -OutputPath (RegFile (Join-Path $env:TEMP "vbst_inf2_$sfx.req")) -DnsName 'bad host&name' } "bad DnsName rejected (SAN injection)" 'only host names are allowed'
  New-SoftwareKey (RegKey "vbs-t-swcsr-$sfx") | Out-Null
  AssertThrows { New-VbsKeyCsr -Subject "CN=kgt-swcsr-$sfx" -KeyName "vbs-t-swcsr-$sfx" -UseExistingKey -OutputPath (RegFile (Join-Path $env:TEMP "vbst_swcsr_$sfx.req")) } "-UseExistingKey software key REFUSED (CSR)" 'NOT VBS-isolated'

  Write-Host "`n=== 8. Import-VbsKeyPfx (+ ephemeral, -WhatIf, -DeleteSourcePfx, wrong pw) ===" -ForegroundColor Cyan
  $tW=New-TestPfx "CN=kgt-imp-wi-$sfx"
  $kBefore=@(Get-VbsKey).Count
  Import-VbsKeyPfx -PfxPath $tW.Path -Password $tW.Pw -KeyName (RegKey "vbs-t-impwi-$sfx") -WhatIf
  Assert ((@(Get-VbsKey).Count -eq $kBefore) -and -not (Get-ChildItem Cert:\CurrentUser\My | ?{ $_.Subject -like "*kgt-imp-wi-$sfx*" })) "-WhatIf import: no key, no cert"
  $tE=New-TestPfx "CN=kgt-imp-ep-$sfx"
  $ci=Import-VbsKeyPfx -PfxPath $tE.Path -Password $tE.Pw -KeyName (RegKey "vbs-t-impep-$sfx"); RegThumb $ci.Thumbprint
  $soft=@(Find-CertKeyContainers -Thumbprint $ci.Thumbprint | ?{ -not $_.VBS })
  Assert ($ci.HasPrivateKey -and $soft.Count -eq 0) "ephemeral import: VBS key, no residual software copy"
  $tEc=New-TestPfx "CN=kgt-imp-ec-$sfx" -Ecdsa
  $cie=Import-VbsKeyPfx -PfxPath $tEc.Path -Password $tEc.Pw -KeyName (RegKey "vbs-t-impec-$sfx"); RegThumb $cie.Thumbprint
  Assert ($cie.HasPrivateKey) "ECDSA import: bound to VBS key"
  $tP=New-TestPfx "CN=kgt-imp-pw-$sfx"
  AssertThrows { Import-VbsKeyPfx -PfxPath $tP.Path -Password (ConvertTo-SecureString 'WRONG' -AsPlainText -Force) -KeyName (RegKey "vbs-t-imppw-$sfx") } "wrong password rejected"
  $tD=New-TestPfx "CN=kgt-imp-del-$sfx"
  $cd=Import-VbsKeyPfx -PfxPath $tD.Path -Password $tD.Pw -KeyName (RegKey "vbs-t-impdel-$sfx") -DeleteSourcePfx; RegThumb $cd.Thumbprint
  Assert (-not (Test-Path $tD.Path)) "-DeleteSourcePfx: source deleted (identity matched)"
  # Finding 1: reject a weak imported key (RSA < 2048); -MinRsaKeySize override allows deliberate legacy import
  $weakMade=$false
  try { $wc=New-SelfSignedCertificate -Subject "CN=kgt-weak-$sfx" -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -Provider 'Microsoft Software Key Storage Provider' -KeyLength 1024 -EA Stop; $weakMade=$true }
  catch { Write-Host "  (1024-bit key creation blocked on this host - skipping weak-import test)" -ForegroundColor DarkYellow }
  if ($weakMade) {
    RegThumb $wc.Thumbprint
    $wkn=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($wc).Key.KeyName; RegKey $wkn
    $wpath=RegFile (Join-Path $env:TEMP "vbst_weak_$sfx.pfx"); $wpw=ConvertTo-SecureString 'T-Pw-123!' -AsPlainText -Force
    Export-PfxCertificate -Cert $wc -FilePath $wpath -Password $wpw | Out-Null
    Remove-Item "Cert:\CurrentUser\My\$($wc.Thumbprint)" -Force
    AssertThrows { Import-VbsKeyPfx -PfxPath $wpath -Password $wpw -KeyName (RegKey "vbs-t-weakimp-$sfx") } "weak RSA (1024) PFX import rejected" 'below the 2048-bit minimum'
    $overrodePast=$true
    try { $wok=Import-VbsKeyPfx -PfxPath $wpath -Password $wpw -KeyName (RegKey "vbs-t-weakok-$sfx") -MinRsaKeySize 1024; RegThumb $wok.Thumbprint }
    catch { if ($_.Exception.Message -match 'below the') { $overrodePast=$false } }
    Assert $overrodePast "-MinRsaKeySize 1024 override bypasses the strength gate"
  }

  Write-Host "`n=== 9. Find-CertKeyContainers (+ ECDSA, thumbprint validation) ===" -ForegroundColor Cyan
  Assert ((@(Find-CertKeyContainers -Thumbprint $c1.Thumbprint | ?{ $_.VBS })).Count -ge 1) "RSA cert: VBS container found"
  Assert ((@(Find-CertKeyContainers -Thumbprint $c1e.Thumbprint | ?{ $_.VBS })).Count -ge 1) "ECDSA cert: VBS container found"
  AssertThrows { Find-CertKeyContainers -Thumbprint '*' } "thumbprint '*' rejected" 'does not match'
  AssertThrows { Find-CertKeyContainers -Thumbprint 'ZZZZ' } "thumbprint non-hex rejected" 'does not match'

  Write-Host "`n=== 10. Remove-VbsKeyFileSecurely (reparse, identity, 0-byte) ===" -ForegroundColor Cyan
  $nf=RegFile (Join-Path $env:TEMP "vbst_sec_$sfx.bin"); [System.IO.File]::WriteAllBytes($nf,(New-Object byte[] 2048))
  Remove-VbsKeyFileSecurely -Path $nf; Assert (-not (Test-Path $nf)) "normal file overwritten + deleted"
  $zf=RegFile (Join-Path $env:TEMP "vbst_sec0_$sfx.bin"); New-Item -ItemType File -Path $zf | Out-Null
  Remove-VbsKeyFileSecurely -Path $zf; Assert (-not (Test-Path $zf)) "0-byte file deleted"
  $tgt=RegFile (Join-Path $env:TEMP "vbst_tgt_$sfx.txt"); [System.IO.File]::WriteAllText($tgt,'KEEP')
  $lnk=Join-Path $env:TEMP "vbst_lnk_$sfx.txt"; $made=$false
  try { New-Item -ItemType SymbolicLink -Path $lnk -Target $tgt -EA Stop | Out-Null; $made=$true } catch { Write-Host "  (symlink needs privilege - skipping reparse test)" -ForegroundColor DarkYellow }
  if($made){ RegFile $lnk
    AssertThrows { Remove-VbsKeyFileSecurely -Path $lnk } "reparse point (symlink) refused" 'reparse point'
    Assert ((Test-Path $tgt) -and [System.IO.File]::ReadAllText($tgt) -eq 'KEEP') "symlink target intact"
  }
  $df=RegFile (Join-Path $env:TEMP "vbst_decoy_$sfx.bin"); [System.IO.File]::WriteAllText($df,'DECOY')
  AssertThrows { Remove-VbsKeyFileSecurely -Path $df -VerifyIdentity -ExpectedVolumeSerial 1 -ExpectedFileIndexHigh 1 -ExpectedFileIndexLow 1 } "identity mismatch refused" 'identity changed'
  Assert (Test-Path $df) "decoy intact after identity-mismatch refusal"

  Write-Host "`n=== 11. Assert-VbsKeyExclusive (dual-scope + verified removal) ===" -ForegroundColor Cyan
  $rc=New-SelfSignedCertificate -Subject "CN=kgt-res-$sfx" -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -Provider 'Microsoft Software Key Storage Provider'
  RegThumb $rc.Thumbprint
  RegKey ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($rc).Key.KeyName)
  $preRes=@(Find-CertKeyContainers -Thumbprint $rc.Thumbprint | ?{ -not $_.VBS })
  Assert-VbsKeyExclusive -Thumbprint $rc.Thumbprint -KeepContainer 'vbs-nope' -Remove 3>$null
  $postRes=@(Find-CertKeyContainers -Thumbprint $rc.Thumbprint | ?{ -not $_.VBS })
  Assert ($preRes.Count -ge 1 -and $postRes.Count -eq 0) "residual audit removed software copy; re-audit confirms none remain"

  Write-Host "`n=== 12. Get-VbsKeyFileIdentity (internal) ===" -ForegroundColor Cyan
  $idf=RegFile (Join-Path $env:TEMP "vbst_id_$sfx.bin"); [System.IO.File]::WriteAllText($idf,'ID')
  $id1=Get-VbsKeyFileIdentity -Path $idf; $id2=Get-VbsKeyFileIdentity -Path $idf
  Assert ($id1.Vol -eq $id2.Vol -and $id1.IdxLow -eq $id2.IdxLow -and $id1.IdxHigh -eq $id2.IdxHigh) "file identity stable across calls"

  Write-Host "`n=== 13. VBS key attestation (New/Test-VbsKeyAttestation) ===" -ForegroundColor Cyan
  $ak=RegKey "vbs-t-att-$sfx"; New-VbsKey -Name $ak -Algorithm RSA -Bits 2048 1>$null 6>$null
  $nonce=[byte[]](1..16)
  $att=New-VbsKeyAttestation -KeyName $ak -Nonce $nonce 6>$null
  Assert ($att.ClaimBytes -gt 100 -and $att.ClaimType -eq 'VBS_ROOT') "attestation claim created (VBS_ROOT)"
  Assert ([bool]$att.Nonce) "nonce claim exposes Nonce (base64) in output"
  AssertThrows { New-VbsKeyAttestation -KeyName $ak -Nonce $null } "explicit empty -Nonce rejected (no silent drop)" 'empty/null'
  $va=Test-VbsKeyAttestation -KeyName $ak -ClaimBase64 $att.Claim -ExpectedNonce $nonce 6>$null
  Assert ($va.Valid -and $va.NonceMatch -eq $true) "claim VALID + embedded nonce matches challenge"
  Assert ($va.Details.CreatedInIsolation -eq $true -and $va.Details.TrustletDebuggable -eq $false) "claim details: created-in-isolation, non-debuggable trustlet"
  $vw=Test-VbsKeyAttestation -KeyName $ak -ClaimBase64 $att.Claim -ExpectedNonce ([byte[]](9,9,9)) 3>$null 6>$null
  Assert (-not $vw.Valid -and $vw.NonceMatch -eq $false) "wrong expected nonce -> INVALID"
  $raw=$att.ClaimRaw.Clone(); $raw[200]=$raw[200] -bxor 0xFF
  $vt=Test-VbsKeyAttestation -KeyName $ak -Claim $raw 3>$null 6>$null
  Assert (-not $vt.Valid -and $vt.Status -ne '0x00000000') "tampered claim -> INVALID signature"
  $an=New-VbsKeyAttestation -KeyName $ak 6>$null
  $vn=Test-VbsKeyAttestation -KeyName $ak -ClaimBase64 $an.Claim 6>$null
  Assert ($vn.Valid -and -not $vn.EmbeddedNonce) "no-nonce claim round-trips VALID"
  $cf=RegFile (Join-Path $env:TEMP "vbst_att_$sfx.bin")
  New-VbsKeyAttestation -KeyName $ak -Nonce $nonce -OutputPath $cf 1>$null 6>$null
  $vf=Test-VbsKeyAttestation -KeyName $ak -ClaimPath $cf -ExpectedNonce $nonce 6>$null
  Assert ((Test-Path $cf) -and $vf.Valid) "claim file round-trip VALID"
  $swa=New-SoftwareKey "vbs-t-attsw-$sfx"
  AssertThrows { New-VbsKeyAttestation -KeyName $swa } "attest non-VBS key refused" 'NOT VBS-isolated'
  # Remote verification: from the subject PUBLIC key blob only (no key by name)
  Assert ($att.PublicKeyBlob -and $att.KeyAlgorithm -eq 'RSA') "New- emits public key blob for remote verify"
  $vr=Test-VbsKeyAttestation -PublicKeyBlobBase64 $att.PublicKeyBlob -ClaimBase64 $att.Claim -ExpectedNonce $nonce 6>$null
  Assert ($vr.Valid -and $vr.SubjectSource -eq 'PublicKeyBlobBase64' -and $vr.NonceMatch -eq $true) "remote verify via public key blob VALID"
  $vrt=Test-VbsKeyAttestation -PublicKeyBlob $att.PublicKeyBlobRaw -Claim $raw 3>$null 6>$null
  Assert (-not $vrt.Valid) "remote verify: tampered claim -> INVALID"
  AssertThrows { Test-VbsKeyAttestation -KeyName $ak -PublicKeyBlob $att.PublicKeyBlobRaw -ClaimBase64 $att.Claim } "two subjects rejected" 'exactly one subject'
  AssertThrows { Test-VbsKeyAttestation -ClaimBase64 $att.Claim } "no subject rejected" 'exactly one subject'
  # Attestation-swap resistance: a claim for one key MUST NOT verify against a DIFFERENT key
  $ak2=RegKey "vbs-t-att2-$sfx"; New-VbsKey -Name $ak2 -Algorithm RSA -Bits 2048 1>$null 6>$null
  $att2=New-VbsKeyAttestation -KeyName $ak2 6>$null
  $swapR=Test-VbsKeyAttestation -PublicKeyBlobBase64 $att2.PublicKeyBlob -ClaimBase64 $att.Claim 3>$null 6>$null
  $swapL=Test-VbsKeyAttestation -KeyName $ak2 -ClaimBase64 $att.Claim 3>$null 6>$null
  Assert ((-not $swapR.Valid) -and (-not $swapL.Valid)) "attestation-swap resisted: claim rejected against a different key"
  # Get-VbsPublicKeyBlob + one-call RA verify (-Certificate / -CsrPath) with SECURE-BY-DEFAULT .Accepted
  $pkb=Get-VbsPublicKeyBlob -Certificate $c1
  Assert ($pkb -and $pkb.Length -gt 0 -and [Text.Encoding]::ASCII.GetString($pkb[0..3]) -eq 'RSA1') "Get-VbsPublicKeyBlob extracts RSA public blob from a cert"
  $attC1=New-VbsKeyAttestation -KeyName $c1.KeyName -Nonce $nonce 6>$null
  # born-in-VBS + fresh challenge, NO switches -> Accepted by default
  $rCert=Test-VbsKeyAttestation -Certificate $c1 -Claim $attC1.ClaimRaw -ExpectedNonce $nonce 6>$null 3>$null
  Assert ($rCert.Valid -and $rCert.Accepted -and $rCert.SubjectSource -eq 'Certificate') "one-call RA verify via -Certificate (secure default): Accepted"
  $reqA=RegFile (Join-Path $env:TEMP "vbst_attcsr_$sfx.req")
  $csrA=New-VbsKeyCsr -Subject "CN=attcsr-$sfx" -OutputPath $reqA 6>$null; RegKey $csrA.KeyName
  $attCsrA=New-VbsKeyAttestation -KeyName $csrA.KeyName -Nonce $nonce 6>$null
  $rCsr=Test-VbsKeyAttestation -CsrPath $reqA -Claim $attCsrA.ClaimRaw -ExpectedNonce $nonce 6>$null 3>$null
  Assert ($rCsr.Valid -and $rCsr.Accepted -and $rCsr.SubjectSource -eq 'CsrPath') "one-call RA verify via -CsrPath (secure default): Accepted"
  # Secure-by-default: NO challenge -> Valid but NOT Accepted (replay guard); -AllowMissingChallenge relaxes
  $rNoNonce=Test-VbsKeyAttestation -Certificate $c1 -Claim $attC1.ClaimRaw 3>$null 6>$null
  Assert ($rNoNonce.Valid -and -not $rNoNonce.Accepted) "no -ExpectedNonce => Valid but NOT Accepted (challenge required by default)"
  $rAllowNoNonce=Test-VbsKeyAttestation -Certificate $c1 -Claim $attC1.ClaimRaw -AllowMissingChallenge 6>$null 3>$null
  Assert ($rAllowNoNonce.Accepted) "-AllowMissingChallenge relaxes the challenge requirement -> Accepted"
  # Secure-by-default: an IMPORTED (not born-in-VBS) key is NOT Accepted; -AllowImportedKey relaxes
  $impPfx=New-TestPfx "CN=kgt-impatt-$sfx"
  $impCert=Import-VbsKeyPfx -PfxPath $impPfx.Path -Password $impPfx.Pw -KeyName (RegKey "vbs-t-impatt-$sfx"); RegThumb $impCert.Thumbprint
  $impKeyName=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($impCert).Key.KeyName
  $attImp=New-VbsKeyAttestation -KeyName $impKeyName -Nonce $nonce 6>$null
  $rImp=Test-VbsKeyAttestation -Certificate $impCert -Claim $attImp.ClaimRaw -ExpectedNonce $nonce 3>$null 6>$null
  Assert ($rImp.Valid -and -not $rImp.Accepted -and $rImp.Details.CreatedInIsolation -eq $false) "imported PFX key: Valid but NOT Accepted (not born-in-VBS)"
  $rImpAllow=Test-VbsKeyAttestation -Certificate $impCert -Claim $attImp.ClaimRaw -ExpectedNonce $nonce -AllowImportedKey 6>$null 3>$null
  Assert ($rImpAllow.Accepted) "-AllowImportedKey relaxes the born-in-VBS requirement -> Accepted"
}
finally {
  Write-Host "`n=== cleanup ===" -ForegroundColor Yellow
  foreach($t in $script:thumbs){ Remove-Item "Cert:\CurrentUser\My\$t" -Force -EA SilentlyContinue }
  Get-ChildItem Cert:\CurrentUser\My -EA SilentlyContinue | ?{ $_.Subject -match $sfx } | %{ Remove-Item $_.PSPath -Force -EA SilentlyContinue }
  Get-ChildItem Cert:\CurrentUser\Request -EA SilentlyContinue | ?{ $_.Subject -match $sfx } | %{ Remove-Item $_.PSPath -Force -EA SilentlyContinue }
  foreach($n in $script:keys){ try{ ([System.Security.Cryptography.CngKey]::Open($n,$prov)).Delete() }catch{} }
  foreach($f in $script:files){ Remove-Item -LiteralPath $f -Force -EA SilentlyContinue }
  Write-Host ("`n==================== RESULT: {0} passed, {1} failed ====================" -f $script:pass, $script:fail) -ForegroundColor $(if($script:fail -eq 0){'Green'}else{'Red'})
  if ($script:fail -gt 0) { exit 1 }
}
