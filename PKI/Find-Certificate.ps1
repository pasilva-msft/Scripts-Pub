#   This Sample Code is provided for the purpose of illustration only
#   and is not intended to be used in a production environment.  THIS
#   SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
#   WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
#   LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
#   FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
#   right to use and modify the Sample Code and to reproduce and distribute
#   the object code form of the Sample Code, provided that You agree:
#   (i) to not use Our name, logo, or trademarks to market Your software
#   product in which the Sample Code is embedded; (ii) to include a valid
#   copyright notice on Your software product in which the Sample Code is
#   embedded; and (iii) to indemnify, hold harmless, and defend Us and
#   Our suppliers from and against any claims or lawsuits, including
#   attorneys'' fees, that arise or result from the use or distribution
#   of the Sample Code.
#
#   Author: Paulo da Silva
#
#   Script to search for specified user certificate in one or all Certificate Authorities
#
#   History:
#   v1 - Initial version
#   v2 - Added parameters validation
#
#


function Find-Certificate () {
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "Server1.contoso.com\CA 1",
            "Server2.contoso.com\CA 2",
            "All"
        )]
        [String]$CA,
  
        [Parameter(Mandatory = $false)]
        [string]$UserName = "",
      
        [Parameter(Mandatory = $false)]
        [string]$SerialNumber = "",

        [Parameter(Mandatory = $false)]
        [string]$Thumbprint = ""
      
    )
  
    if ($PSBoundParameters.Count -eq 2) {
  
        # Declare variables
        $Found = 0
        $CAServerList = @("Server1.contoso.com\CA 1",
        "Server2.contoso.com\CA 2")

            if ((($PSBoundParameters.ContainsKey('UserName'))) -and (-not([string]::IsNullOrEmpty($UserName)))){
  
                if ($CA -eq "All") {
      
                    # Default user option is Y
                    Write-Host "This command will search for $($UserName) certificates on All ($($CAServerList.Count)) the Certificate Authorities" -ForegroundColor Yellow
                    Write-Host "Do you whish to proceed? (Y/n)" -ForegroundColor Yellow
                    $op = Read-Host
  
                    if ($op -eq "Y" -or $op -eq "") {
                        foreach ($CAServer in $CAServerList) {
                            Write-Host "Searching for $($UserName) in $($CAServer) Certificate Authority" -ForegroundColor Cyan
                            $Result = C:\windows\System32\certutil.exe -config "$($CAServer)" -view -restrict "RequesterName=$($UserName)" -out RequestID,SerialNumber,NotAfter,CertificateHash,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.Disposition csv
                            $Found = $Result.count
  
                            # If more than on line (header) is returned, it means we found a certificate
                            if ($Found -gt 1) {
                                $Result
                                Write-Host ""
                                $Found = 0
                            }
                            else {
                                Write-Host "No certificate was found on $($CAServer)" -ForegroundColor Yellow
                                Write-Host ""
                            }
                        }
                    }
                }
                else {
                    $Result = C:\windows\System32\certutil.exe -config "$($CA)" -view -restrict "RequesterName=$($UserName)" -out RequestID,SerialNumber,NotAfter,CertificateHash,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.Disposition csv
                    $Found = $Result.count
  
                    # If more than on line (header) is returned, it means we found a certificate
                    if ($Found -gt 1) {
                        $Result
                        Write-Host ""
                        $Found = 0
                    }
                    else {
                        Write-Host ""
                        Write-Host "No certificate was found on $($CA)" -ForegroundColor Yellow
                        Write-Host ""
                    }
                }
            } elseif ((($PSBoundParameters.ContainsKey('UserName'))) -and ([string]::IsNullOrEmpty($UserName))) {
                Write-Host ""
                Write-Host "User name is empty or null" -ForegroundColor Red
            }

            if ((($PSBoundParameters.ContainsKey('SerialNumber'))) -and (-not([string]::IsNullOrEmpty($SerialNumber)))){
  
                if ($CA -eq "All") {
      
                    # Default user option is Y
                    Write-Host "This command will search for $($SerialNumber) certificates on All ($($CAServerList.Count)) the Certificate Authorities" -ForegroundColor Yellow
                    Write-Host "Do you whish to proceed? (Y/n)" -ForegroundColor Yellow
                    $op = Read-Host
  
                    if ($op -eq "Y" -or $op -eq "") {
                        foreach ($CAServer in $CAServerList) {
                            Write-Host "Searching for $($SerialNumber) in $($CAServer) Certificate Authority" -ForegroundColor Cyan
                            $Result = C:\windows\System32\certutil.exe -config "$($CAServer)" -view -restrict "SerialNumber=$($SerialNumber)" -out RequestID,SerialNumber,NotAfter,CertificateHash,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.Disposition csv
                            $Found = $Result.count
  
                            # If more than on line (header) is returned, it means we found a certificate
                            if ($Found -gt 1) {
                                $Result
                                Write-Host ""
                                $Found = 0
                            }
                            else {
                                Write-Host "No certificate was found on $($CAServer)" -ForegroundColor Yellow
                                Write-Host ""
                            }
                        }
                    }
                }
                else {
                    $Result = C:\windows\System32\certutil.exe -config "$($CA)" -view -restrict "SerialNumber=$($SerialNumber)" -out RequestID,SerialNumber,NotAfter,CertificateHash,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.Disposition csv
                    $Found = $Result.count
  
                    # If more than on line (header) is returned, it means we found a certificate
                    if ($Found -gt 1) {
                        $Result
                        Write-Host ""
                        $Found = 0
                    }
                    else {
                        Write-Host ""
                        Write-Host "No certificate was found on $($CA)" -ForegroundColor Yellow
                        Write-Host ""
                    }
                }
            } elseif ((($PSBoundParameters.ContainsKey('SerialNumber'))) -and ([string]::IsNullOrEmpty($SerialNumber))) {
                Write-Host ""
                Write-Host "SerialNumber is empty or null" -ForegroundColor Red
            }

            if ((($PSBoundParameters.ContainsKey('Thumbprint'))) -and (-not([string]::IsNullOrEmpty($Thumbprint)))){
  
                if ($CA -eq "All") {
      
                    # Default user option is Y
                    Write-Host "This command will search for $($Thumbprint) certificates on All ($($CAServerList.Count)) the Certificate Authorities" -ForegroundColor Yellow
                    Write-Host "Do you whish to proceed? (Y/n)" -ForegroundColor Yellow
                    $op = Read-Host
  
                    if ($op -eq "Y" -or $op -eq "") {
                        foreach ($CAServer in $CAServerList) {
                            Write-Host "Searching for $($Thumbprint) in $($CAServer) Certificate Authority" -ForegroundColor Cyan
                            $Result = C:\windows\System32\certutil.exe -config "$($CAServer)" -view -restrict "CertificateHash=$($Thumbprint)" -out RequestID,SerialNumber,NotAfter,CertificateHash,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.Disposition csv
                            $Found = $Result.count
  
                            # If more than on line (header) is returned, it means we found a certificate
                            if ($Found -gt 1) {
                                $Result
                                Write-Host ""
                                $Found = 0
                            }
                            else {
                                Write-Host "No certificate was found on $($CAServer)" -ForegroundColor Yellow
                                Write-Host ""
                            }
                        }
                    }
                }
                else {
                    $Result = C:\windows\System32\certutil.exe -config "$($CA)" -view -restrict "CertificateHash=$($Thumbprint)" -out RequestID,SerialNumber,NotAfter,CertificateHash,Request.RevokedWhen,Request.RevokedEffectiveWhen,Request.RevokedReason,Request.Disposition csv
                    $Found = $Result.count
  
                    # If more than on line (header) is returned, it means we found a certificate
                    if ($Found -gt 1) {
                        $Result
                        Write-Host ""
                        $Found = 0
                    }
                    else {
                        Write-Host ""
                        Write-Host "No certificate was found on $($CA)" -ForegroundColor Yellow
                        Write-Host ""
                    }
                }
            } elseif ((($PSBoundParameters.ContainsKey('Thumbprint'))) -and ([string]::IsNullOrEmpty($Thumbprint))) {
                Write-Host ""
                Write-Host "Thumbprint is empty or null" -ForegroundColor Red
            }
  
        }
        else {
            Write-Host ""
            Write-Host "Unexpected number of arguments!" -ForegroundColor Yellow
            Write-Host "Usage: 'Find-Certificate -CA <choose from auto-complete options> [-UserName <CONTOSO\username>] [-SerialNumber 123123123] [-Thumbprint 7654345]'" -ForegroundColor Yellow
        }
  
    }
  
    Write-Host ""
    Write-Host "Usage: 'Find-Certificate -CA <choose from auto-complete options> [-UserName <CONTOSO\username>] [-SerialNumber 123123123] [-Thumbprint 7654345]'" -ForegroundColor Yellow