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
#   to use Negotiate:Kerberos and mitigate PetitPotam
#


# Query IIS configuration
Import-Module IISAdministration
Import-Module WebAdministration
$sites = (Get-ChildItem 'IIS:\Sites').collection.path
$IISdir = "IIS:\Sites\Default Web Site"
$Kerb = 0

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
            Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
    
        }
        else {
            foreach ($authstrs in $authstr) {
                # Check if Kerberos is configured
                if ($authstrs -match "Kerberos") {
                    $Kerb = 1
                    Write-Host "Negotiate:Kerberos is already configured as authentication provider" -ForegroundColor Yellow
                    Write-Host ""
                }
            }
            # If Kerberos was not found on provider list, add Kerberos
            if ($Kerb -eq 0) {
                Write-Host
                Write-Host "Adding Negotiate:Kerberos provider" -ForegroundColor Yellow
                Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }
            }
        }
        Write-Host "Removing all others providers" -ForegroundColor Yellow
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate' }
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'NTLM' }
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:PKU2U' }
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:CloudAP' }
        $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
        Write-Host ""
        Write-Host "Authentication providers after change" -ForegroundColor Cyan
        Write-Host "Site name: $($site)" -ForegroundColor Green
        Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
    }
    else {
        #Write-Host ""
        Write-Host "Doing nothing on site: $($site)" -ForegroundColor Cyan
    }
}