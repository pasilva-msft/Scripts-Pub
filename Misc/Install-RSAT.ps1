
# V1 - 02/11/2021
$i=1

Write-Host "Checking for RSAT tools not installed... this may take a while"

$RSAT = Get-WindowsCapability -Online | Where-Object {$_.Name -like "*rsat*" -and $_.State -eq "NotPresent"}
$TotalItems = $RSAT.Length
if ($TotalItems -eq 0){
    Write-Host ""
    Write-Host "All Remote Server Administration Tools (RSAT) are already installed" -ForegroundColor Yellow
} else {
    Write-Host ""
    foreach ($item in $RSAT){
        Write-Host "Installing" $item.Name -ForegroundColor Cyan
        Write-Host "This is $($i) of total $($TotalItems)" -ForegroundColor Cyan
        Add-WindowsCapability -Name $item.Name -Online
        $i++
    }
}

Write-Host ""
Write-Host "Checking for Hyper-V tools not installed... this may take a while"

$HVTools = Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -like "*hyper*" -and $_.State -eq "Disabled"}

if ($HVTools.FeatureName -eq "Microsoft-Hyper-V-Tools-All" -and $HVTools.State -eq "Disabled"){
    Write-Host ""
    Write-Host "Installing Hyper-V tools..."
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Tools-All -Online -All
} else {
    Write-Host ""
    Write-Host "Hyper-V tools are already installed" -ForegroundColor Yellow
    Write-Host ""
}