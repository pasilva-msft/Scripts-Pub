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