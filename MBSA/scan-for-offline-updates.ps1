
<#
    .SYNOPSIS
		Powershell Script to Install Updates Based on the Type of update
	.DESCRIPTION
        Using the WIndows Update API, Each update has a specific Root category. By selecting with Type of Update you want, you can avoid installing unwanted updates
	.PARAMETER Path
		The full path AND name where the script is located.
	.PARAMETER Reboot
        If a reboot is required for an update, the system will restart.
	.PARAMETER ScanOnly
		As implies, It does not download or install updates, just lists the available ones based on criteria 
	.PARAMETER ProxyAddress
        *THIS PARAMETER IS STILL BETA!!!* Instead of using the default windows update API, use another endpoint for updates. 
    .PARAMETER UpdateTypes
        RootCategories that are associated with windows updates. Choose the types you wish to filter for. 
    .EXAMPLE
		    & '.\Invoke-WindowsUpdates.ps1' -Reboot -UpdateTypes Definition, Critical, Security -Path '.\Invoke-WindowsUpdates.ps1'
    .Notes
        Author: Leotus Richard
        website: http://outboxedsolutions.azurewebsites.net/
	https://gallery.technet.microsoft.com/scriptcenter/Simple-Windows-Update-Tool-3a505873

        Version History
        1.0.0 Initial Release

        1.0.1 Adjusted script, SCANONLY is default $true to prevent accidental windows installation.  

        Upcoming Features
            - Report generator
            - email functionality
            - Improve WSUS/Proxy functionality *BETA*

1. Critical - A broadly released fix for a specific problem addressing a critical, non-security related bug.
2. Definition – A broadly-released and frequent software update containing additions to a product's definition database. Definition databases are often used to detect objects with specific attributes, such as malicious code, phishing Web sites, or junk e-mail.
3. Drivers – A software component necessary to control or regulate another device
4. FeaturePacks - New product functionality that is first distributed outside the context of a product release, and usually included in the next full product release.
5. Security – A broadly released fix for a product-specific security-related vulnerability. Security vulnerabilities are rated based on their severity which is indicated in the Microsoft® security bulletin as critical, important, moderate, or low.
6. ServicePacks - A tested, cumulative set of all hotfixes, security updates, critical updates and updates, as well as additional fixes for problems found internally since the release of the product. Service packs may also contain a limited number of customer-requested design changes or features
7. Tools - A utility or feature that aids in accomplishing a task or set of tasks.
8. UpdateRollups - A tested, cumulative set of hotfixes, security updates, critical updates, and updates packaged together for easy deployment. A rollup generally targets a specific area, such as security, or a component of a product, such as Internet Information Services "IIS".
9. Updates - A broadly released fix for a specific problem addressing a noncritical, non-security-related bug.
10. Microsoft – Microsoft related applications that need updates, occasionally you see Office thrown in here, expression, etc.…
11. ALL - I made this one up. But it’s self-explanatory.
#>
[CmdletBinding()]
param(
$Path = (Get-Location),
[switch]$Reboot, 
[switch]$ScanOnly = $true, 
[string]$ProxyAddress,
[String[]][ValidateSet("Critical","Definition", "Drivers", "FeaturePacks", "Security", "ServicePacks", "Tools", "UpdateRollups", "Updates", "Microsoft", "ALL")]$UpdateTypes

)
    $AvailableUpdates = @()
    $UpdateIds = @()
    $UpdateTypes

    Write-Host "Checking for elevation... " -NoNewline
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    if (($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) -eq $false){
        $ArgumentList = "-noprofile -noexit -file `"{0}`" -Path `"$Path`""
        If ($ScanOnly) {$ArgumentList = $ArgumentList + " -ScanOnly"}
        If ($reboot) {$ArgumentList = $ArgumentList + " -Reboot"}
        If ($ProxyAddress){$ArgumentList = $ArgumentList + " -ProxyAddress $ProxyAddress"}
        If ($UpdateTypes) {$ArgumentList = $ArgumentList + " -UpdateTypes $UpdateTypes"}

    Write-Host "elevating"
    Start-Process powershell.exe -Verb RunAs -ArgumentList ($ArgumentList -f ($myinvocation.MyCommand.Definition))

    Write-Host "Exiting, please refer to console window" -ForegroundColor DarkRed
        break
        }

    if ($Reboot) {
        Write-Host "The computer will reboot if needed after installation is complete."
        Write-Host
    }
    if ($ScanOnly) {
        Write-Host "Running in scan only mode."
        Write-Host
    }

    Write-Verbose "Creating Update Session"
    $Session = New-Object -com "Microsoft.Update.Session"


    if ($ProxyAddress -ne $null) {
    Write-Verbose "Setting Proxy"
        $Proxy = New-Object -com "Microsoft.Update.WebProxy"
        $Session.WebProxy.Address = $Proxyaddress
        $Session.WebProxy.AutoDetect = $FALSE
        $Session.WebProxy.BypassProxyOnLocal = $TRUE
    }

    Write-Verbose "Creating Update Type Array"
    foreach($UpdateType in $UpdateTypes)
    {
        $UpdateID
        switch ($UpdateType)
        {
        "Critical" {$UpdateID = 0}
        "Definition"{$UpdateID = 1}
        "Drivers"{$UpdateID = 2}
        "FeaturePacks"{$UpdateID = 3}
        "Security"{$UpdateID = 4}
        "ServicePacks"{$UpdateID = 5}
        "Tools"{$UpdateID = 6}
        "UpdateRollups"{$UpdateID = 7}
        "Updates"{$UpdateID = 8}
        "Microsoft"{$UpdateID = 9}
        default {$UpdateID=99}
        }
        $UpdateIds += $UpdateID
    }

    Write-Host "Searching for updates..."
    $Search = $Session.CreateUpdateSearcher()
    $SearchResults = $Search.Search("IsInstalled=0 and IsHidden=0")
    Write-Host "There are " $SearchResults.Updates.Count "TOTAL updates available."

    if($UpdateIds -eq 99)
    {
        $AvailableUpdates = $SearchResults.Updates
    }
    else{
        
        foreach($UpdateID in $UpdateIds)
        {
            $AvailableUpdates += $SearchResults.RootCategories.Item($UpdateID).Updates
        }
    }

    Write-Host "Updates selected for installation"
    $AvailableUpdates | ForEach-Object {
    
        if (($_.InstallationBehavior.CanRequestUserInput) -or ($_.EulaAccepted -eq $FALSE)) {
            Write-Host $_.Title " *** Requires user input and will not be installed." -ForegroundColor Yellow
        }
        else {
            Write-Host $_.Title -ForegroundColor Green
        }
    }

    # Exit script if no updates are available
    if ($ScanOnly) {
        Write-Host "Exiting...";
        break
    }
    if($AvailableUpdates.count -lt 1){
        Write-Host "No results meet your criteria. Exiting";
        break
    }
    
    Write-Verbose "Creating Download Selection"
    $DownloadCollection = New-Object -com "Microsoft.Update.UpdateColl"

    $AvailableUpdates | ForEach-Object {
        if ($_.InstallationBehavior.CanRequestUserInput -ne $TRUE) {
            $DownloadCollection.Add($_) | Out-Null
            }
        }

    Write-Verbose "Downloading Updates"
    Write-Host "Downloading updates..."
    $Downloader = $Session.CreateUpdateDownloader()
    $Downloader.Updates = $DownloadCollection
    $Downloader.Download()

    Write-Host "Download complete."

    Write-Verbose "Creating Installation Object"
    $InstallCollection = New-Object -com "Microsoft.Update.UpdateColl"
    $AvailableUpdates | ForEach-Object {
	    if ($_.IsDownloaded) {
		    $InstallCollection.Add($_) | Out-Null
        }
    }

    Write-Verbose "Installing Updates"
    Write-Host "Installing updates..."
    $Installer = $Session.CreateUpdateInstaller()
    $Installer.Updates = $InstallCollection
    $Results = $Installer.Install()
    Write-Host "Installation complete."
    Write-Host


    # Reboot if needed
    if ($Results.RebootRequired) {
        if ($Reboot) {
            Write-Host "Rebooting..."
            Restart-Computer ## add computername here
        }
        else {
	        Write-Host "Please reboot."
        }
    }
    else {
	    Write-Host "No reboot required."
    }
