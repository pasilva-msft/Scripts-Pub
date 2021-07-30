# This Sample Code is provided for the purpose of illustration only
# and is not intended to be used in a production environment.  THIS
# SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
# FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
# right to use and modify the Sample Code and to reproduce and distribute
# the object code form of the Sample Code, provided that You agree:
# (i) to not use Our name, logo, or trademarks to market Your software
# product in which the Sample Code is embedded; (ii) to include a valid
# copyright notice on Your software product in which the Sample Code is
# embedded; and (iii) to indemnify, hold harmless, and defend Us and
# Our suppliers from and against any claims or lawsuits, including
# attorneys'' fees, that arise or result from the use or distribution
# of the Sample Code.
#
#   Author: Paulo da Silva
#
#   Script to configure IIS CES application (Certificate Enrollment Web Services)
#   to use Negotiate:Kerberos and mitigate PetitPotam (Microsoft Security Advisory 974926)
#
#   https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429
#
#   History:
#   v1 - Change IIS CES application to Kerberos only provider
#   v2 - Added new mitigations options for IIS CES application as suggested on above KB
#        Also added the ability to execute remotely on multiple servers
#   v3 - Added option to Check if PetitPotam mitigations are applied

# Declare variables
$ServerName = Get-Content C:\Temp\Servers.txt -ErrorAction SilentlyContinue #Change this

$SBEnableKerberosOnly = {
    function EnableKerberosOnly () {
    
        Import-Module IISAdministration
        Import-Module WebAdministration
        $sites = (Get-ChildItem 'IIS:\Sites').collection.path
        $IISdir = "IIS:\Sites\Default Web Site"
        $DefaultWebSite = "Default Web Site"
        $Kerb = 0
        $NTLM = 0
        $Negotiate = 0
        $PKU2U = 0
        $CloudAP = 0

        # Query IIS configuration
        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow
        foreach ($site in $sites) {
            $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
            Write-Host ""
            Write-Host "Site name: $($site)" -ForegroundColor Green
            Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
            $authstr = $auth.providers.collection.Value
            # Add/Remove authentication providers
            if ($site -match "CES_Kerberos") {
                # Check if there are no providers configured
                if ($null -eq $authstr) {
                    Write-Host "No provider found" -ForegroundColor Red
                    Write-Host "Adding Negotiate:Kerberos provider" -ForegroundColor Yellow
                    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $DefaultWebSite/$site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
                }
                else {
                    foreach ($authstrs in $authstr) {
                        # Check what providers are configured
                        if ($authstrs -eq "Negotiate:Kerberos") {
                            $Kerb = 1
                            Write-Host "Negotiate:Kerberos is already configured as authentication provider" -ForegroundColor Yellow
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
                        Write-Host "Adding Negotiate:Kerberos provider" -ForegroundColor Yellow
                        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
                    }
                    if ($NTLM -eq 1) {
                        Write-Host "Removing NTLM provider" -ForegroundColor Yellow
                        Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'NTLM' }
                    }
                    if ($Negotiate -eq 1) {
                        Write-Host "Removing Negotiate provider" -ForegroundColor Yellow
                        Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate' }
                    }
                    if ($PKU2U -eq 1) {
                        Write-Host "Removing Negotiate:PKU2U provider" -ForegroundColor Yellow
                        Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:PKU2U' }
                    }
                    if ($CloudAP -eq 1) {
                        Write-Host "Removing Negotiate:CloudAP provider" -ForegroundColor Yellow
                        Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:CloudAP' }
                    }
                }

                # Checking providers after changing
                $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
                Write-Host ""
                Write-Host "Authentication providers after change" -ForegroundColor Cyan
                Write-Host "Site name: $($site)" -ForegroundColor Green
                Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
            }
            else {
                Write-Host "Doing nothing on site: $($site)" -ForegroundColor Cyan
            }
        }
    }
    # Calling Function
    EnableKerberosOnly
}

$SBEnableEPAOnly = {
    function EnableEPAOnly () {
        # Declare variables
        Import-Module IISAdministration
        Import-Module WebAdministration
        $sites = (Get-ChildItem 'IIS:\Sites').collection.path
        $DefaultWebSite = "Default Web Site"
        $NoEPA = @"
<transport clientCredentialType="Windows" />
"@
        $EPA = @"
<transport clientCredentialType="Windows">
<extendedProtectionPolicy policyEnforcement="Always" />
</transport>
"@
        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow
        #Query IIS configuration
        foreach ($site in $sites) {
            if ($site -match "CES_Kerberos") {
                $siteNormalized = $site.Split("/")[1]
                $CESConfigFolder = "$($env:windir)\systemdata\CES\$($siteNormalized)"
                $CESConfigFile = "$($env:windir)\systemdata\CES\$($siteNormalized)\web.config"

                if (-not(Test-Path -Path $CESConfigFolder\web.config.bkp)) {
                    Write-Host "Backing up original web.config file on $($CESConfigFolder) folder" -ForegroundColor Yellow
                    Copy-Item $CESConfigFile $CESConfigFolder\web.config.bkp
                    Write-Host "Replacing content on $($env:windir)\systemdata\CES\$($siteNormalized)\web.config file"
                    (Get-Content $CESConfigFile) -replace $NoEPA, $EPA | Set-Content $CESConfigFile
                }
                else {
                    Write-Host "$CESConfigFolder\web.config.bkp backup file already exists" -ForegroundColor Yellow
                    Write-Host "Replacing content on $($env:windir)\systemdata\CES\$($siteNormalized)\web.config file" -ForegroundColor Yellow
                    (Get-Content $CESConfigFile) -replace $NoEPA, $EPA | Set-Content $CESConfigFile
                }
                
                # Check current EPA configuration
                $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $DefaultWebSite/$site -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                if ($TokenChecking -eq "Require") {
                    Write-Host "Extended Protection for Authentication (EPA) is already configured to: $($TokenChecking) for application $($site)" -ForegroundColor Green
                }
                else {
                    Write-Host "Extended Protection for Authentication (EPA) is configured for: $($TokenChecking)" -ForegroundColor Yellow
                    Write-Host "Going to change to Require" -ForegroundColor Green
                    # Configure Extended Protection to required
                    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking" -value "Require"
                    # Get current Extended Protection configuration
                    $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $DefaultWebSite/$site -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                    Write-Host "Extended Protection for Authentication (EPA) is now configured for: $($TokenChecking) for application $($site)" -ForegroundColor Green
                }

            }
        }
    }
    # Calling Function
    EnableEPAOnly
}

$SBRequireSSL = {
    function RequireSSL () {
        # Declare variables
        Import-Module IISAdministration
        Import-Module WebAdministration
        $sites = (Get-ChildItem 'IIS:\Sites').collection.path
        $DefaultWebSite = "Default Web Site"

        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow
        #Query IIS configuration
        foreach ($site in $sites) {
            if ($site -match "CES_Kerberos") {
                Write-Host "Checking if SSL and SSL 128-bits are Required for $($site)" -ForegroundColor Yellow
                $SSLRequired = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $DefaultWebSite/$site -filter "system.webServer/security/access" -name "sslFlags"
                if ($SSLRequired -eq "Ssl,Ssl128") {
                    Write-Host "SSL and SSL 128-bits are Required for $($site) for CES IIS application" -ForegroundColor Green
                }
                else {
                    Write-Host "SSL and SSL 128-bits are NOT Required for $($site)" -ForegroundColor Red
                    Write-Host "Going to change to Require" -ForegroundColor Green
                    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $DefaultWebSite/$site -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,Ssl128"
                    $SSLRequired = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $DefaultWebSite/$site -filter "system.webServer/security/access" -name "sslFlags"
                    Write-Host "New SSL configuration after change is $($SSLRequired) for application $($site)" -ForegroundColor Green
                }
            }

        }
    }
    # Calling Function
    RequireSSL
}

$SBCheckMitigations = {
    function CheckMitigations () {
        Import-Module IISAdministration
        Import-Module WebAdministration
        $sites = (Get-ChildItem 'IIS:\Sites').collection.path
        $IISdir = "IIS:\Sites\Default Web Site"
        $DefaultWebSite = "Default Web Site"

        # Query IIS configuration
        Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow
        foreach ($site in $sites) {
            $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
            Write-Host ""
            Write-Host "Site name: $($site)" -ForegroundColor Green
            Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
            Write-Host ""
            $authstr = $auth.providers.collection.Value
            # Add/Remove authentication providers
            if ($site -match "CES_Kerberos") {
                # Check if there are no providers configured
                if ($null -eq $authstr) {
                    Write-Host "No provider found" -ForegroundColor Red
                    Write-Host ""
                }
                else {
                    Write-Host "Checking what providers are configured..." -ForegroundColor Yellow
                    Write-Host ""
                    foreach ($authstrs in $authstr) {
                        # Check what providers are configured
                        if ($authstrs -eq "Negotiate:Kerberos") {
                            Write-Host "Negotiate:Kerberos is already configured as authentication provider" -ForegroundColor Green
                            Write-Host ""
                        }
                        if ($authstrs -eq "NTLM") {
                            Write-Host "NTLM is configured as authentication provider" -ForegroundColor Red
                            Write-Host ""
                        }
                        if ($authstrs -eq "Negotiate") {
                            Write-Host "Negotiate is configured as authentication provider" -ForegroundColor Red
                            Write-Host ""
                        }
                        if ($authstrs -eq "Negotiate:PKU2U") {
                            Write-Host "Negotiate:PKU2U is configured as authentication provider" -ForegroundColor Red
                            Write-Host ""
                        }
                        if ($authstrs -eq "Negotiate:CloudAP") {
                            Write-Host "Negotiate:CloudAP is configured as authentication provider" -ForegroundColor Red
                            Write-Host ""
                        }
                    }
                }

                # Checking for Extended Protection for Authentication (EPA) on web.config file
                Write-Host "Checking if Extended Protection for Authentication (EPA) is Required on web.config file..." -ForegroundColor Yellow
                Write-Host ""
                $siteNormalized = $site.Split("/")[1]
                $CESConfigFile = "$($env:windir)\systemdata\CES\$($siteNormalized)\web.config"
                $CESWebConfig = Get-Content $CESConfigFile
                $CheckEPA = '<extendedProtectionPolicy policyEnforcement="Always" />'
                $CheckEPABool = $false
                foreach ($line in $CESWebConfig) {
                    if ($line -eq $CheckEPA) {
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
                Write-Host "Checking if Extended Protection for Authentication (EPA) is Required on IIS CES application level..." -ForegroundColor Yellow
                Write-Host ""
                $TokenChecking = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $DefaultWebSite/$site -filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -name "tokenChecking"
                if ($TokenChecking -eq "Require") {
                    Write-Host "Extended Protection for Authentication (EPA) is configured to: $($TokenChecking) for application $($site)" -ForegroundColor Green
                    Write-Host ""
                }
                else {
                    Write-Host "Extended Protection for Authentication (EPA) is NOT configured as recommended for application $($site)" -ForegroundColor Red
                    Write-Host "Current configuration is: $($TokenChecking)" -ForegroundColor Red
                    Write-Host ""
                }

                # Checking if SSL and SSL 128-bits are Required
                Write-Host "Checking if SSL and SSL 128-bits are Required for $($site)" -ForegroundColor Yellow
                Write-Host ""
                $SSL = Get-WebConfiguration -PSPath "$IISdir\$($site)" -filter "system.webServer/security/access"
                if ($SSL.sslFlags -eq "Ssl,Ssl128") {
                    Write-Host "SSL and SSL 128-bits are Required for $($site) for CES IIS application" -ForegroundColor Green
                    Write-Host ""
                }
                elseif ($null -eq $SSL.sslFlags -or $SSL.sslFlags -eq "") {
                    Write-Host "SSL and SSL 128-bits are NOT Required for $($site)" -ForegroundColor Red
                    Write-Host "Current SSL configuration is NULL for application $($site)" -ForegroundColor Red
                    Write-Host ""
                } else {
                    Write-Host "SSL and SSL 128-bits are NOT Required for $($site)" -ForegroundColor Red
                    Write-Host "Current SSL configuration is: $($SSL.sslFlags) for application $($site)" -ForegroundColor Red
                    Write-Host ""
                }
            }
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

Write-Host "What would you like to do on Certificate Enrollment Web Service (CES)?" -ForegroundColor Cyan
Write-Host ""

Write-Host "1: Enable Kerberos only" -ForegroundColor Green
Write-Host "2: Enable Extended Protection for Authentication (EPA) only" -ForegroundColor Green
Write-Host "3: Require TLS on CES IIS application" -ForegroundColor Green
Write-Host "4: Check if PetitPotam mitigations are applied" -ForegroundColor Green
Write-Host "5: Apply Kerberos, EPA and Require TLS mitigations on CES application" -ForegroundColor Green
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
            Write-Host "Servers file not found. A server list file must be provided" -ForegroundColor Red
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
            Write-Host "Servers file not found. A server list file must be provided" -ForegroundColor Red
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
            Write-Host "Servers file not found. A server list file must be provided" -ForegroundColor Red
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
            Write-Host "Servers file not found. A server list file must be provided" -ForegroundColor Red
        }
    }

    5 {
        Write-Host "Sorry! Not implemented yet :)" -ForegroundColor Yellow
    }

    Default {
        Write-Host ""
        Write-Host "Option $($op) invalid. Choose a valid option." -ForegroundColor Red
        Write-Host ""
        Start-Sleep 2
    }
}