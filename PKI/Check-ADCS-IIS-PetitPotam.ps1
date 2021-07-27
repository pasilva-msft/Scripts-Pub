# Query IIS configuration
Import-Module IISAdministration
Import-Module WebAdministration
$sites = (Get-ChildItem 'IIS:\Sites').collection.path
$IISdir = "IIS:\Sites\Default Web Site"

Write-Host "Server name: $($env:COMPUTERNAME)" -ForegroundColor Yellow
foreach ($site in $sites) {
    $auth = Get-WebConfiguration -filter /system.webServer/security/authentication/windowsAuthentication -PSPath "$IISdir\$($site)"
    Write-Host ""
    Write-Host "Site name: $($site)" -ForegroundColor Green
    Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
    $authstr = $auth.providers.collection.Value
    # Add/Remove authentication providers
    if ($site -match "CES_Kerberos") {
        if ($authstr -notmatch "Negotiate:Kerberos") {
            Write-Host ""
            Write-Host "Adding Negotiate:Kerberos provider" -ForegroundColor Yellow
            Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -value @{value = 'Negotiate:Kerberos' }            
        }
        Write-Host "Negotiate:Kerberos is already configured as authentication provider" -ForegroundColor Yellow
        Write-Host "Removing all others providers" -ForegroundColor Yellow
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate' }
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'NTLM' }
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:PKU2U' }
        Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -location $site -filter "system.webServer/security/authentication/windowsAuthentication/providers" -name "." -AtElement @{value = 'Negotiate:CloudAP' }
        Write-Host ""
        Write-Host "Authentication providers after change" -ForegroundColor Yellow
        Write-Host "Site name: $($site)" -ForegroundColor Green
        Write-Host "Auth: " $auth.providers.collection.Value -ForegroundColor Green
    }
    else {
        #Write-Host ""
        Write-Host "Doing nothing on site: $($site)" -ForegroundColor Cyan
    }
}