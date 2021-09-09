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
#   Script to check and mitigate PetitPotam attacks for Active Directory Certificate services (Microsoft Security Advisory 974926)
#
#   https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429
#
#   History:
#   v1 - Change IIS CES application to Kerberos only provider
#   v2 - Added new mitigations options for IIS CES application as suggested on above KB
#        Also added the ability to execute remotely on multiple servers
#   v3 - Added option to Check if PetitPotam mitigations are applied
#   v4 - Added mitigations to be applied on CAWE (Certification Authority Web Enrollment) aka /CertSrv
#   v5 - Added option to apply all mitigations at once
#   v5.1 - Fixed error when changing Authentication providers and enabling EPA on /CertSrv
#   v6 - Implemented a new code logic to detect more than one web site on same IIS box
#        Removed unused IISAdministration module
#   v6.1 - Checking if IIS Kernel-mode authentication is enabled and if custom identity is configured
#          If both are true script will change IIS Kernel-mode authentication to False
#        

# Declare variables
$ServerName = Get-Content C:\Temp\Servers.txt -ErrorAction SilentlyContinue #Change this with the server list you want, one server name per line

$SBEnableKerberosOnly = {
    function EnableKerberosOnly () {
    
        # Declare variables
        Import-Module WebAdministration
        $sitename = (Get-ChildItem 'IIS:\Sites').name
        $AppPools = Get-ChildItem "IIS:\AppPools\"
        $j = 0
        $Kerb = 0
        $NTLM = 0
        $Negotiate = 0
        $PKU2U = 0
        $CloudAP = 0
        
        Write-Host ""
        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow

        #Query IIS configuration
        foreach ($sitenames in $sitename) {
            # Checking how many Web Sites IIS has, otherwise things will broke since
            # if more than 1 Web Site is found an array is returned, otherwise a single object is returned
            if ($sitename.count -eq 1) {
                $IISdir = "IIS:\Sites\$($sitename)"
            }
            elseif ($sitename.count -gt 1) {
                $IISdir = "IIS:\Sites\$($sitename[$j])"
            }
                
            $sites = (Get-ChildItem "$($IISdir)" | Where-Object { $_.NodeType -eq "application" }).Name
            $IISDirWebSite = $IISdir.Split("\")[2]
            $PSPath = "MACHINE/WEBROOT/APPHOST/$($IISDirWebSite)"

        
            foreach ($site in $sites) {
                $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                Write-Host ""
                Write-Host "Site name: $($IISdirWebSite)/$($site)" -ForegroundColor Green
                Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
                $authstr = $auth.providers.collection.Value
                # Check if Kerberos is configured on CertSrv IIS Application
                if ($site -match "CES_Kerberos") {
                    # Check if there are no providers configured
                    if ($null -eq $authstr) {
                        Write-Host "No provider found on site: $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Adding Negotiate:Kerberos provider" -ForegroundColor Yellow
                        Add-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
                    }
                    else {
                        foreach ($authstrs in $authstr) {
                            # Check what providers are configured
                            if ($authstrs -eq "Negotiate:Kerberos") {
                                $Kerb = 1
                                Write-Host "Negotiate:Kerberos is already configured as authentication provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Green
                            }
                            if ($authstrs -eq "NTLM") {
                                $NTLM = 1
                            }
                            if ($authstrs -eq "Negotiate") {
                                $Negotiate = 1
                            }
                            if ($authstrs -eq "Negotiate:PKU2U") {
                                $PKU2U = 1
                            }
                            if ($authstrs -eq "Negotiate:CloudAP") {
                                $CloudAP = 1
                            }
                        }
                        # If Kerberos was not found on provider list, add Kerberos
                        if ($Kerb -eq 0) {
                            Write-Host "Adding Negotiate:Kerberos provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                            Add-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
                            $Kerb = 0
                        }
                        if ($NTLM -eq 1) {
                            Write-Host "Removing NTLM provider for site $($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'NTLM' }
                            $NTLM = 0
                        }
                        if ($Negotiate -eq 1) {
                            Write-Host "Removing Negotiate provider for site $($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate' }
                            $Negotiate = 0
                        }
                        if ($PKU2U -eq 1) {
                            Write-Host "Removing Negotiate:PKU2U provider for site $($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:PKU2U' }
                            $PKU2U = 0
                        }
                        if ($CloudAP -eq 1) {
                            Write-Host "Removing Negotiate:CloudAP provider for site $($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:CloudAP' } -verbose
                            $CloudAP = 0
                        }
                    }

                    # Checking providers after changing
                    $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                    Write-Host ""
                    Write-Host "Authentication providers after change" -ForegroundColor Cyan
                    Write-Host "Site name: $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green

                    # Check if IIS Kernel-mode authentication is enabled
                    $KernelModeEnabled = $null
                    Write-Host "-- Checking if Kernel-mode authentication is enabled for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""

                    $CheckKernelMode = Get-WebConfiguration -filter system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                    if ($CheckKernelMode.useKernelMode -eq "True") {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                        $KernelModeEnabled = $true
                    }
                    else {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    }
                                                
                    # Check what is CES Application Pool name, so can verify if custom identity is configured
                    $AppPoolCES = (Get-ItemProperty "$IISdir\$($site)").applicationPool
                    Write-Host "Application Pool configured for $($IISdirWebSite)/$($site) is $($AppPoolCES)" -ForegroundColor Yellow
                                                
                    foreach ($AppPool in $AppPools) {
                        if ($AppPool.name -eq $AppPoolCES) {
                            # If custom identity and IIS Kernel-mode authentication are enabled need to disable otherwise authentication won't work
                            if ($AppPool.processModel.identityType -eq "SpecificUser") {
                                if ($KernelModeEnabled) {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with custom identity $($AppPool.processModel.userName)" -ForegroundColor Yellow
                                    Write-Host "IIS Kernel-mode authentication and custom identity are enabled" -ForegroundColor Red
                                    Write-Host "Need to fix it, otherwise authentication will fail" -ForegroundColor Red
                                    Write-Host "Going to change IIS Kernel-mode authentication..." -ForegroundColor Green
                                    Set-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication" -name "useKernelMode" -value "False"
                                    $CheckKernelMode = Get-WebConfiguration -filter system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                                    Write-Host "Kernel-mode authentication configuration after change is $($CheckKernelMode.useKernelMode)" -ForegroundColor Green
                                }
                                else {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType) $($AppPool.processModel.userName), also known as custom identity" -ForegroundColor Yellow
                                }
                            }
                            else {
                                Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
                # Check if Kerberos is configured on CertSrv IIS Application
                elseif ($site -eq "CertSrv") {
                    # Check if there are no providers configured
                    if ($null -eq $authstr) {
                        Write-Host "No provider found on site: $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Adding Negotiate:Kerberos provider" -ForegroundColor Yellow
                        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
                    }
                    else {
                        foreach ($authstrs in $authstr) {
                            # Check what providers are configured
                            if ($authstrs -eq "Negotiate:Kerberos") {
                                $Kerb = 1
                                Write-Host "Negotiate:Kerberos is already configured as authentication provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Green
                            }
                            if ($authstrs -eq "NTLM") {
                                $NTLM = 1
                            }
                            if ($authstrs -eq "Negotiate") {
                                $Negotiate = 1
                            }
                            if ($authstrs -eq "Negotiate:PKU2U") {
                                $PKU2U = 1
                            }
                            if ($authstrs -eq "Negotiate:CloudAP") {
                                $CloudAP = 1
                            }
                        }
                        # If Kerberos was not found on provider list, add Kerberos
                        if ($Kerb -eq 0) {
                            Write-Host "Adding Negotiate:Kerberos provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                            Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
                            $Kerb = 0
                        }
                        if ($NTLM -eq 1) {
                            Write-Host "Removing NTLM provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'NTLM' }
                            $NTLM = 0
                        }
                        if ($Negotiate -eq 1) {
                            Write-Host "Removing Negotiate provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate' }
                            $Negotiate = 0
                        }
                        if ($PKU2U -eq 1) {
                            Write-Host "Removing Negotiate:PKU2U provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:PKU2U' }
                            $PKU2U = 0
                        }
                        if ($CloudAP -eq 1) {
                            Write-Host "Removing Negotiate:CloudAP provider for site $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                            Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:CloudAP' }
                            $CloudAP = 0
                        }
                    }

                    # Checking providers after changing
                    $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                    Write-Host ""
                    Write-Host "Authentication providers after change" -ForegroundColor Cyan
                    Write-Host "Site name: $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green

                    # Check if IIS Kernel-mode authentication is enabled
                    $KernelModeEnabled = $null
                    Write-Host "-- Checking if Kernel-mode authentication is enabled for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""

                    $CheckKernelMode = Get-WebConfiguration -filter system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                    if ($CheckKernelMode.useKernelMode -eq "True") {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                        $KernelModeEnabled = $true
                    }
                    else {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    }
                                                
                    # Check what is CertSrv Application Pool name, so can verify if custom identity is configured
                    $AppPoolCertSrv = (Get-ItemProperty "$IISdir\$($site)").applicationPool
                    Write-Host "Application Pool configured for $($IISdirWebSite)/$($site) is $($AppPoolCertSrv)" -ForegroundColor Yellow
                                                
                    foreach ($AppPool in $AppPools) {
                        if ($AppPool.name -eq $AppPoolCertSrv) {
                            # If custom identity and IIS Kernel-mode authentication are enabled need to disable otherwise authentication won't work
                            if ($AppPool.processModel.identityType -eq "SpecificUser") {
                                if ($KernelModeEnabled) {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with custom identity $($AppPool.processModel.userName)" -ForegroundColor Yellow
                                    Write-Host "IIS Kernel-mode authentication and custom identity are enabled" -ForegroundColor Red
                                    Write-Host "Need to fix it, otherwise authentication will fail" -ForegroundColor Red
                                    Write-Host "Going to change IIS Kernel-mode authentication..." -ForegroundColor Green
                                    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication" -name "useKernelMode" -value "False"
                                    $CheckKernelMode = Get-WebConfiguration -filter system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                                    Write-Host "Kernel-mode authentication configuration after change is $($CheckKernelMode.useKernelMode)" -ForegroundColor Green
                                }
                                else {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType) $($AppPool.processModel.userName), also known as custom identity" -ForegroundColor Yellow
                                }
                            }
                            else {
                                Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
                else {
                    Write-Host "Doing nothing on site: $($IISdirWebSite)/$($site)" -ForegroundColor Cyan
                }
            }
            $j++
        }
    }
    # Calling Function
    EnableKerberosOnly
}

$SBEnableEPAOnly = {
    function EnableEPAOnly () {
            

        Import-Module WebAdministration
        # Declare variables
        $sitename = (Get-ChildItem 'IIS:\Sites').name
        $j = 0
        $NoEPA = @"
<transport clientCredentialType="Windows" />
"@
        $EPA = @"
<transport clientCredentialType="Windows">
<extendedProtectionPolicy policyEnforcement="Always" />
</transport>
"@

        Write-Host ""  
        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow

        #Query IIS configuration
        foreach ($sitenames in $sitename) {
            # Checking how many Web Sites IIS has, otherwise things will broke since
            # if more than 1 Web Site is found an array is returned, otherwise a single object is returned
            if ($sitename.count -eq 1) {
                $IISdir = "IIS:\Sites\$($sitename)"
            }
            elseif ($sitename.count -gt 1) {
                $IISdir = "IIS:\Sites\$($sitename[$j])"
            }
                
            $sites = (Get-ChildItem "$($IISdir)" | Where-Object { $_.NodeType -eq "application" }).Name
            $IISDirWebSite = $IISdir.Split("\")[2]
            $PSPath = "MACHINE/WEBROOT/APPHOST/$($IISDirWebSite)"

            foreach ($site in $sites) {
                # Check for CES IIS application
                if ($site -match "CES_Kerberos") {
                    $CESConfigFolder = "$($env:windir)\systemdata\CES\$($site)"
                    $CESConfigFile = "$($env:windir)\systemdata\CES\$($site)\web.config"

                    # Checking for Extended Protection for Authentication (EPA) on WCF web.config file
                    Write-Host "-- Checking if Extended Protection for Authentication (EPA) is Required on WCF web.config file..." -ForegroundColor Yellow
                    Write-Host ""
                    $CESConfigFile = "$($env:windir)\systemdata\CES\$($site)\web.config"
                    $CESWebConfig = Get-Content $CESConfigFile
                    $CheckEPA = '<extendedProtectionPolicy policyEnforcement="Always" />'
                    $CheckEPABool = $false
                    foreach ($line in $CESWebConfig) {
                        if ($line.Trim() -eq $CheckEPA) {
                            Write-Host "Extended Protection for Authentication (EPA) is already configured on $($CESConfigFile) file" -ForegroundColor Green
                            Write-Host ""
                            $CheckEPABool = $true
                        }
                    }
                    if ($CheckEPABool -eq $false) {
                        Write-Host "Extended Protection for Authentication (EPA) is NOT configured on $($CESConfigFile) file" -ForegroundColor Red
                        Write-Host ""
                        if (-not(Test-Path -Path $CESConfigFolder\web.config.bkp)) {
                            Write-Host "Backing up original web.config file on $($CESConfigFolder) folder" -ForegroundColor Yellow
                            Copy-Item $CESConfigFile $CESConfigFolder\web.config.bkp
                            Write-Host "Enabling Extended Protection for Authentication (EPA) on WCF $($CESConfigFile) file" -ForegroundColor Yellow
                            Write-Host ""
                            (Get-Content $CESConfigFile) -replace $NoEPA, $EPA | Set-Content $CESConfigFile
                        }
                        else {
                            Write-Host "$CESConfigFolder\web.config.bkp backup file already exists" -ForegroundColor Yellow
                            Write-Host "Enabling Extended Protection for Authentication (EPA) on WCF $($CESConfigFile) file" -ForegroundColor Yellow
                            Write-Host ""
                            (Get-Content $CESConfigFile) -replace $NoEPA, $EPA | Set-Content $CESConfigFile
                        }
                    }
                
                    Write-Host "-- Checking if Extended Protection for Authentication (EPA) is configured to Require for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""

                    # Check current EPA configuration on IIS CES Application
                    $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                    if ($TokenChecking -eq "Require") {
                        Write-Host "Extended Protection for Authentication (EPA) is already configured to: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                        Write-Host ""
                    }
                    else {
                        Write-Host "Extended Protection for Authentication (EPA) is configured for: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                        Write-Host "Going to change to Require" -ForegroundColor Green
                        # Configure Extended Protection to required
                        Set-WebConfigurationProperty -pspath $PSPath -location $site -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking" -value "Require"
                        # Get current Extended Protection configuration
                        $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                        Write-Host "Extended Protection for Authentication (EPA) is now configured for: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    }

                } # Check for CertSrv IIS application
                elseif ($site -eq "CertSrv") {
                    Write-Host "-- Checking if Extended Protection for Authentication (EPA) is configured to Require for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""
                    # Check current EPA configuration
                    $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                    if ($TokenChecking -eq "Require") {
                        Write-Host "Extended Protection for Authentication (EPA) is already configured to: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                        Write-Host ""
                    }
                    else {
                        Write-Host "Extended Protection for Authentication (EPA) is configured for: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                        Write-Host "Going to change to Require" -ForegroundColor Green
                        # Configure Extended Protection to required
                        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking" -value "Require"
                        # Get current Extended Protection configuration
                        $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                        Write-Host "Extended Protection for Authentication (EPA) is now configured for: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "Doing nothing on site: $($IISdirWebSite)/$($site)" -ForegroundColor Cyan
                    Write-Host ""
                }
            }
            $j++
        }
    }
    # Calling Function
    EnableEPAOnly
}

$SBRequireSSL = {
    function RequireSSL () {
            

        Import-Module WebAdministration
        # Declare variables
        $sitename = (Get-ChildItem 'IIS:\Sites').name
        $j = 0
    
        Write-Host ""
        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow
        
        #Query IIS configuration
        foreach ($sitenames in $sitename) {
            # Checking how many Web Sites IIS has, otherwise things will broke since
            # if more than 1 Web Site is found an array is returned, otherwise a single object is returned
            if ($sitename.count -eq 1) {
                $IISdir = "IIS:\Sites\$($sitename)"
            }
            elseif ($sitename.count -gt 1) {
                $IISdir = "IIS:\Sites\$($sitename[$j])"
            }
                
            $sites = (Get-ChildItem "$($IISdir)" | Where-Object { $_.NodeType -eq "application" }).Name
            $IISDirWebSite = $IISdir.Split("\")[2]

            foreach ($site in $sites) {
                # Check for SSL on CES IIS Application
                if ($site -match "CES_Kerberos") {
                    Write-Host "-- Checking if SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""
                    $SSLRequired = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/access" -name "sslFlags"
                    if ($SSLRequired -eq "Ssl,Ssl128") {
                        Write-Host "SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site) for IIS application" -ForegroundColor Green
                        Write-Host ""
                    }
                    else {
                        Write-Host "SSL and SSL 128-bits are NOT Required for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Going to change to Require" -ForegroundColor Green
                        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,Ssl128"
                        $SSLRequired = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/access" -name "sslFlags"
                        Write-Host "New SSL configuration after change is $($SSLRequired) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                        Write-Host ""
                    }
                } # Check for SSL on CertSrv IIS Application
                elseif ($site -eq "CertSrv") {
                    Write-Host "-- Checking if SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""
                    $SSLRequired = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/access" -name "sslFlags"
                    if ($SSLRequired -eq "Ssl,Ssl128") {
                        Write-Host "SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site) for IIS application" -ForegroundColor Green
                        Write-Host ""
                    }
                    else {
                        Write-Host "SSL and SSL 128-bits are NOT Required for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Going to change to Require" -ForegroundColor Green
                        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,Ssl128"
                        $SSLRequired = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/access" -name "sslFlags"
                        Write-Host "New SSL configuration after change is $($SSLRequired) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "Doing nothing on site: $($IISdirWebSite)/$($site)" -ForegroundColor Cyan
                }
            }
            $j++
        }
    }
    # Calling Function
    RequireSSL
}

$SBCheckMitigations = {
    function CheckMitigations () {
            

        Import-Module WebAdministration
        # Declare variables
        $sitename = (Get-ChildItem 'IIS:\Sites').name
        $AppPools = Get-ChildItem "IIS:\AppPools\"
        $j = 0
    
        Write-Host ""
        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow

        #Query IIS configuration
        foreach ($sitenames in $sitename) {
            # Checking how many Web Sites IIS has, otherwise things will broke since
            # if more than 1 Web Site is found an array is returned, otherwise a single object is returned
            if ($sitename.count -eq 1) {
                $IISdir = "IIS:\Sites\$($sitename)"
            }
            elseif ($sitename.count -gt 1) {
                $IISdir = "IIS:\Sites\$($sitename[$j])"
            }
                        
            $sites = (Get-ChildItem "$($IISdir)" | Where-Object { $_.NodeType -eq "application" }).Name
            $IISDirWebSite = $IISdir.Split("\")[2]

            foreach ($site in $sites) {
                $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                Write-Host ""
                Write-Host "Site name: $($IISdirWebSite)/$($site)" -ForegroundColor Green
                Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
                Write-Host ""
                $authstr = $auth.providers.collection.Value
                # Check for mitigations on CES IIS Application
                if ($site -match "CES_Kerberos") {
                    # Check if there are no providers configured
                    if ($null -eq $authstr) {
                        Write-Host "No provider found for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host ""
                    }
                    else {
                        Write-Host "-- Checking what providers are configured  for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                        Write-Host ""
                        foreach ($authstrs in $authstr) {
                            # Check what providers are configured
                            if ($authstrs -eq "Negotiate:Kerberos") {
                                Write-Host "Negotiate:Kerberos is already configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Green
                                Write-Host ""
                            }
                            if ($authstrs -eq "NTLM") {
                                Write-Host "NTLM is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                            if ($authstrs -eq "Negotiate") {
                                Write-Host "Negotiate is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                            if ($authstrs -eq "Negotiate:PKU2U") {
                                Write-Host "Negotiate:PKU2U is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                            if ($authstrs -eq "Negotiate:CloudAP") {
                                Write-Host "Negotiate:CloudAP is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                        }
                    }

                    # Checking for Extended Protection for Authentication (EPA) on WCF web.config file
                    Write-Host "-- Checking if Extended Protection for Authentication (EPA) is Required on WCF web.config file..." -ForegroundColor Yellow
                    Write-Host ""
                    $CESConfigFile = "$($env:windir)\systemdata\CES\$($site)\web.config"
                    $CESWebConfig = Get-Content $CESConfigFile
                    $CheckEPA = '<extendedProtectionPolicy policyEnforcement="Always" />'
                    $CheckEPABool = $false
                    foreach ($line in $CESWebConfig) {
                        if ($line.Trim() -eq $CheckEPA) {
                            Write-Host "Extended Protection for Authentication (EPA) is already configured on $($CESConfigFile) file" -ForegroundColor Green
                            Write-Host ""
                            $CheckEPABool = $true
                        }
                    }
                    if ($CheckEPABool -eq $false) {
                        Write-Host "Extended Protection for Authentication (EPA) is NOT configured on $($CESConfigFile) file" -ForegroundColor Red
                        Write-Host ""
                    }

                    # Checking for Extended Protection for Authentication (EPA) on IIS CES application level
                    Write-Host "-- Checking if Extended Protection for Authentication (EPA) is Required on IIS CES application level..." -ForegroundColor Yellow
                    Write-Host ""
                    $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                    if ($TokenChecking -eq "Require") {
                        Write-Host "Extended Protection for Authentication (EPA) is configured to: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                        Write-Host ""
                    }
                    else {
                        Write-Host "Extended Protection for Authentication (EPA) is NOT configured as recommended for application $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Current configuration is: $($TokenChecking)" -ForegroundColor Red
                        Write-Host ""
                    }

                    # Checking if SSL and SSL 128-bits are Required
                    Write-Host "-- Checking if SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""
                    $SSL = Get-WebConfiguration -PSPath "$IISdir\$($site)" -filter "system.webServer/security/access"
                    if ($SSL.sslFlags -eq "Ssl,Ssl128") {
                        Write-Host "SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site) for CES IIS application" -ForegroundColor Green
                        Write-Host ""
                    }
                    elseif ($null -eq $SSL.sslFlags -or $SSL.sslFlags -eq "") {
                        Write-Host "SSL and SSL 128-bits are NOT Required for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Current SSL configuration is NULL for application $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host ""
                    }
                    else {
                        Write-Host "SSL and SSL 128-bits are NOT Required for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Current SSL configuration is: $($SSL.sslFlags) for application $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host ""
                    }

                    # Check if IIS Kernel-mode authentication is enabled
                    $KernelModeEnabled = $null
                    Write-Host "-- Checking if Kernel-mode authentication is enabled for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""

                    $CheckKernelMode = Get-WebConfiguration -filter system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                    if ($CheckKernelMode.useKernelMode -eq "True") {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                        $KernelModeEnabled = $true
                    }
                    else {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    }
                                                
                    # Check what is CES Application Pool name, so can verify if custom identity is configured
                    $AppPoolCES = (Get-ItemProperty "$IISdir\$($site)").applicationPool
                    Write-Host "Application Pool configured for $($IISdirWebSite)/$($site) is $($AppPoolCES)" -ForegroundColor Yellow
                                                
                    foreach ($AppPool in $AppPools) {
                        if ($AppPool.name -eq $AppPoolCES) {
                            # If custom identity and IIS Kernel-mode authentication are enabled need to disable otherwise authentication won't work
                            if ($AppPool.processModel.identityType -eq "SpecificUser") {
                                if ($KernelModeEnabled) {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with custom identity $($AppPool.processModel.userName)" -ForegroundColor Yellow
                                    Write-Host "IIS Kernel-mode authentication and custom identity are enabled" -ForegroundColor Red
                                    Write-Host "Need to fix it, otherwise authentication will fail" -ForegroundColor Red
                                }
                                else {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType) $($AppPool.processModel.userName), also known as custom identity" -ForegroundColor Yellow
                                }
                            }
                            else {
                                Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
                elseif ($site -eq "CertSrv") {
                    # Check if there are no providers configured
                    if ($null -eq $authstr) {
                        Write-Host "No provider found for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host ""
                    }
                    else {
                        Write-Host "-- Checking what providers are configured  for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                        Write-Host ""
                        foreach ($authstrs in $authstr) {
                            # Check what providers are configured
                            if ($authstrs -eq "Negotiate:Kerberos") {
                                Write-Host "Negotiate:Kerberos is already configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Green
                                Write-Host ""
                            }
                            if ($authstrs -eq "NTLM") {
                                Write-Host "NTLM is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                            if ($authstrs -eq "Negotiate") {
                                Write-Host "Negotiate is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                            if ($authstrs -eq "Negotiate:PKU2U") {
                                Write-Host "Negotiate:PKU2U is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                            if ($authstrs -eq "Negotiate:CloudAP") {
                                Write-Host "Negotiate:CloudAP is configured as authentication provider for $($IISdirWebSite)/$($site)" -ForegroundColor Red
                                Write-Host ""
                            }
                        }
                    }

                    # Checking for Extended Protection for Authentication (EPA) on IIS CES application level
                    Write-Host "-- Checking if Extended Protection for Authentication (EPA) is Required on IIS $($IISdirWebSite)/$($site) application level..." -ForegroundColor Yellow
                    Write-Host ""
                    $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($IISdirWebSite)/$($site)" -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                    if ($TokenChecking -eq "Require") {
                        Write-Host "Extended Protection for Authentication (EPA) is configured to: $($TokenChecking) for application $($IISdirWebSite)/$($site)" -ForegroundColor Green
                        Write-Host ""
                    }
                    else {
                        Write-Host "Extended Protection for Authentication (EPA) is NOT configured as recommended for application $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host "Current configuration is: $($TokenChecking)" -ForegroundColor Red
                        Write-Host ""
                    }

                    # Checking if SSL and SSL 128-bits are Required
                    Write-Host "-- Checking if SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""
                    $SSL = Get-WebConfiguration -PSPath "$IISdir\$($site)" -filter "system.webServer/security/access"
                    if ($SSL.sslFlags -eq "Ssl,Ssl128") {
                        Write-Host "SSL and SSL 128-bits are Required for $($IISdirWebSite)/$($site) IIS application" -ForegroundColor Green
                        Write-Host ""
                    }
                    elseif ($null -eq $SSL.sslFlags -or $SSL.sslFlags -eq "") {
                        Write-Host "SSL and SSL 128-bits are NOT Required for $($IISdirWebSite)/$($site) IIS application" -ForegroundColor Red
                        Write-Host "Current SSL configuration is NULL for application $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host ""
                    }
                    else {
                        Write-Host "SSL and SSL 128-bits are NOT Required for $($IISdirWebSite)/$($site) IIS application" -ForegroundColor Red
                        Write-Host "Current SSL configuration is: $($SSL.sslFlags) for application $($IISdirWebSite)/$($site)" -ForegroundColor Red
                        Write-Host ""
                    }
                        
                    # Check if IIS Kernel-mode authentication is enabled
                    $KernelModeEnabled = $null
                    Write-Host "-- Checking if Kernel-mode authentication is enabled for $($IISdirWebSite)/$($site)..." -ForegroundColor Yellow
                    Write-Host ""

                    $CheckKernelMode = Get-WebConfiguration -filter system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                    if ($CheckKernelMode.useKernelMode -eq "True") {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Yellow
                        $KernelModeEnabled = $true
                    }
                    else {
                        Write-Host "Kernel-mode authentication is configured as $($CheckKernelMode.useKernelMode) for $($IISdirWebSite)/$($site)" -ForegroundColor Green
                    }
                                                
                    # Check what is CertSrv Application Pool name, so can verify if custom identity is configured
                    $AppPoolCertSrv = (Get-ItemProperty "$IISdir\$($site)").applicationPool
                    Write-Host "Application Pool configured for $($IISdirWebSite)/$($site) is $($AppPoolCertSrv)" -ForegroundColor Yellow
                                                
                    foreach ($AppPool in $AppPools) {
                        #Write-Host "AppPool $($AppPool.name)" -ForegroundColor Cyan
                        if ($AppPool.name -eq $AppPoolCertSrv) {
                            # If custom identity and IIS Kernel-mode authentication are enabled need to disable otherwise authentication won't work
                            if ($AppPool.processModel.identityType -eq "SpecificUser") {
                                if ($KernelModeEnabled) {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with custom identity $($AppPool.processModel.userName)" -ForegroundColor Yellow
                                    Write-Host "IIS Kernel-mode authentication and custom identity are enabled" -ForegroundColor Red
                                    Write-Host "Need to fix it, otherwise authentication will fail" -ForegroundColor Red
                                }
                                else {
                                    Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType) $($AppPool.processModel.userName), also known as custom identity" -ForegroundColor Yellow
                                }
                            }
                            else {
                                Write-Host "IIS Application Pool $($AppPool.name) is configured with $($AppPool.processModel.identityType)" -ForegroundColor Yellow
                            }
                        }
                    }
                }
                else {
                    Write-Host "Doing nothing on site: $($IISdirWebSite)/$($site)" -ForegroundColor Cyan
                }
            }
            $j++
        }
    }
    # Calling function
    CheckMitigations
}


$SBResetIIS = {
    function ResetIIS () {
        iisreset /restart
    }
    # Calling Function
    ResetIIS
}

# Function to check if Servers.txt file exist and not empty
function CheckServerName ($ServerName) {
    if ($null -ne $ServerName) {
        Return $true
    }
    else {
        Return $false
    }
}



Write-Host "What would you like to do?" -ForegroundColor Cyan
Write-Host ""

Write-Host "1: Enable Kerberos authentication provider for CES and CertSrv applications" -ForegroundColor Green
Write-Host "2: Enable Extended Protection for Authentication (EPA) for CES and CertSrv applications" -ForegroundColor Green
Write-Host "3: Require TLS for CES and CertSrv applications" -ForegroundColor Green
Write-Host "4: Check if PetitPotam mitigations are applied for CES and CertSrv applications" -ForegroundColor Green
Write-Host "5: Apply ALL mitigations (Kerberos, EPA and Require TLS) for CES and CertSrv applications" -ForegroundColor Green
Write-Host "0: Exit script" -ForegroundColor Green
Write-Host ""

$op = Read-Host "Choose your option above"
Write-Host ""

switch ($op) {
    0 {
        Write-Host "Exiting script..."
        Write-Host ""
        Start-Sleep 2
        Break;
    }

    1 {  
        $CheckFile = CheckServerName $ServerName
        if ($CheckFile) {
            foreach ($server in $ServerName) {
                Write-Host ""
                Write-Host "Creating PSSession for: $($server)" -ForegroundColor Yellow
                $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue
                if ($null -ne $session) {
                    Invoke-Command -Session $session -ScriptBlock $SBEnableKerberosOnly -ArgumentList $server
                    Write-Host ""
                    Write-Host "Restarting IIS services..." -ForegroundColor Yellow
                    Invoke-Command -Session $session -ScriptBlock $SBResetIIS -ArgumentList $server
                    Write-Host ""
                    Write-Host "Removing PSSesion for: $($server)" -ForegroundColor Yellow
                    Remove-PSSession $session
                }
                else {
                    Write-Host ""
                    Write-Host "Could not connect to server: $($server)" -ForegroundColor Red
                }

            }
        }
        else {
            Write-Host "Servers file not found. A server list file must be provided. Default path is C:\Temp\Servers.txt" -ForegroundColor Red
        }
    }

    2 {
        $CheckFile = CheckServerName $ServerName
        if ($CheckFile) {
            foreach ($server in $ServerName) {
                Write-Host ""
                Write-Host "Creating PSSession for: $($server)" -ForegroundColor Yellow
                $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue
                if ($null -ne $session) {
                    Invoke-Command -Session $session -ScriptBlock $SBEnableEPAOnly -ArgumentList $server
                    Write-Host ""
                    Write-Host "Restarting IIS services..." -ForegroundColor Yellow
                    Invoke-Command -Session $session -ScriptBlock $SBResetIIS -ArgumentList $server
                    Write-Host ""
                    Write-Host "Removing PSSesion for: $($server)" -ForegroundColor Yellow
                    Remove-PSSession $session
                }
                else {
                    Write-Host ""
                    Write-Host "Could not connect to server: $($server)" -ForegroundColor Red
                }

            }
        }
        else {
            Write-Host "Servers file not found. A server list file must be provided. Default path is C:\Temp\Servers.txt" -ForegroundColor Red
        }
    }

    3 {
        $CheckFile = CheckServerName $ServerName
        if ($CheckFile) {
            foreach ($server in $ServerName) {
                Write-Host ""
                Write-Host "Creating PSSession for: $($server)" -ForegroundColor Yellow
                $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue
                if ($null -ne $session) {
                    Invoke-Command -Session $session -ScriptBlock $SBRequireSSL -ArgumentList $server
                    Write-Host ""
                    Write-Host "Restarting IIS services..." -ForegroundColor Yellow
                    Invoke-Command -Session $session -ScriptBlock $SBResetIIS -ArgumentList $server
                    Write-Host ""
                    Write-Host "Removing PSSesion for: $($server)" -ForegroundColor Yellow
                    Remove-PSSession $session
                }
                else {
                    Write-Host ""
                    Write-Host "Could not connect to server: $($server)" -ForegroundColor Red
                }

            }
        }
        else {
            Write-Host "Servers file not found. A server list file must be provided. Default path is C:\Temp\Servers.txt" -ForegroundColor Red
        }
    }

    4 {
        $CheckFile = CheckServerName $ServerName
        if ($CheckFile) {
            foreach ($server in $ServerName) {
                Write-Host ""
                Write-Host "Creating PSSession for: $($server)" -ForegroundColor Yellow
                $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue
                if ($null -ne $session) {
                    Invoke-Command -Session $session -ScriptBlock $SBCheckMitigations -ArgumentList $server
                    Write-Host ""
                    Write-Host "Removing PSSesion for: $($server)" -ForegroundColor Yellow
                    Remove-PSSession $session
                }
                else {
                    Write-Host ""
                    Write-Host "Could not connect to server: $($server)" -ForegroundColor Red
                }

            }
        }
        else {
            Write-Host "Servers file not found. A server list file must be provided. Default path is C:\Temp\Servers.txt" -ForegroundColor Red
        }
    }

    5 {
        $CheckFile = CheckServerName $ServerName
        if ($CheckFile) {
            foreach ($server in $ServerName) {
                Write-Host ""
                Write-Host "Creating PSSession for: $($server)" -ForegroundColor Yellow
                $session = New-PSSession -ComputerName $server -ErrorAction SilentlyContinue
                if ($null -ne $session) {
                    Invoke-Command -Session $session -ScriptBlock $SBEnableKerberosOnly -ArgumentList $server
                    Write-Host ""
                    Invoke-Command -Session $session -ScriptBlock $SBEnableEPAOnly -ArgumentList $server
                    Write-Host ""
                    Invoke-Command -Session $session -ScriptBlock $SBRequireSSL -ArgumentList $server
                    Write-Host ""
                    Write-Host "Restarting IIS services..." -ForegroundColor Yellow
                    Invoke-Command -Session $session -ScriptBlock $SBResetIIS -ArgumentList $server
                    Write-Host ""
                    Write-Host "Removing PSSesion for: $($server)" -ForegroundColor Yellow
                    Remove-PSSession $session
                }
                else {
                    Write-Host ""
                    Write-Host "Could not connect to server: $($server)" -ForegroundColor Red
                }

            }
        }
        else {
            Write-Host "Servers file not found. A server list file must be provided. Default path is C:\Temp\Servers.txt" -ForegroundColor Red
        }
    }

    Default {
        Write-Host ""
        Write-Host "Option $($op) invalid. Choose a valid option." -ForegroundColor Red
        Write-Host ""
        Start-Sleep 2
    }
}