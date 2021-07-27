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
            Write-Host "No provider found"
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