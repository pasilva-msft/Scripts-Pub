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
#   Author: Paulo da Silva (pasilva@microsoft.com)
#


$OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
$OSCaption = (Get-CimInstance Win32_OperatingSystem).Caption
$ServerName = "Fabrikam.com"
$ServerShareName = "Netlogon"
$FolderName = "DisableSMB"
$OutputFile = "\\$ServerName\$ServerShareName\$FolderName\$env:ComputerName.log"

$date = Get-Date
Write-Output "Getting date and time: $date" | Out-File $OutputFile

# Detection logic for Windows 10
if ($OSCaption -like "*Windows 10*"){
    Write-Output "OS Name is: $OSCaption" | Out-File $OutputFile -Append
    Write-Output "OS Version is: $OSVersion" | Out-File $OutputFile -Append
   
   # Detect if SMB is Enabled
    $DetectSMBStatus = (Get-WindowsOptionalFeature –Online –FeatureName SMB1Protocol).state
        if ($DetectSMBStatus -eq "Enabled"){
        
        # Disable smbv1
        Write-Output "SMBv1 enabled. Disabling SMBv1" | Out-File $OutputFile -Append
        $disableSmbv1 = Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        $disabledStatus = ($disableSmbv1).RestartNeeded
            
            # Check if removal was successful or not
            if ($?) { 
                Write-Output "SMBv1 is successfully disabled. Reboot required status: $disabledStatus" | Out-File $OutputFile -Append
        
            } else {
                Write-Output "SMBv1 could not be disabled. Please Sign in to server to check more details." | Out-File $OutputFile -Append
            }
        
        } else {
    Write-Output "SMBv1 status is: $DetectSMBStatus" | Out-File $OutputFile -Append

        }
    
}

# Detection logic for Windows Server 2016
if ($OSCaption -like "*Windows Server 2016*"){
    Write-Output "OS Name is: $OSCaption" | Out-File $OutputFile -Append
    Write-Output "OS Version is: $OSVersion" | Out-File $OutputFile -Append
   
   # Detect if SMB is Enabled
    $DetectSMBStatus = (Get-WindowsFeature FS-SMB1).Installed
        if ($DetectSMBStatus -eq "True"){
        
        # Disable smbv1
        Write-Output "SMBv1 enabled. Desabling SMBv1" | Out-File $OutputFile -Append
        $disableSmbv1 = Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
        $disabledStatus = ($disableSmbv1).RestartNeeded
            
            # Check if removal was successful or not
            if ($?) { 
                Write-Output "SMBv1 is successfully disabled. Reboot required status: $disabledStatus" | Out-File $OutputFile -Append
        
            } else {
                Write-Output "SMBv1 could not be disabled. Please Sign in to server to check more details." | Out-File $OutputFile -Append
            }
        
        } else {
    Write-Output "SMBv1 status is: $DetectSMBStatus" | Out-File $OutputFile -Append

    }
  
}

# Detection logic for Windows Server 2012 R2
if ($OSCaption -like "*Windows Server 2012 R2*" -and $OSVersion -like "*.9600"){
        Write-Output "OS Name is: $OSCaption" | Out-File $OutputFile -Append
        Write-Output "OS Version is: $OSVersion" | Out-File $OutputFile -Append
    
        # Detect if SMB is Enabled
        $DetectSMBStatus = (Get-WindowsFeature FS-SMB1).Installed
            if ($DetectSMBStatus -eq "True"){
        
            # Disable smbv1
            Write-Output "SMBv1 enabled. Desabling SMBv1" | Out-File $OutputFile -Append
            $disableSmbv1 = Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
            $disabledStatus = ($disableSmbv1).RestartNeeded
            
                # Check if removal was successful or not
                if ($?) { 
                    Write-Output "SMBv1 is successfully disabled. Reboot required status: $disabledStatus" | Out-File $OutputFile -Append
        
                } else {
                    Write-Output "SMBv1 could not be disabled. Please Sign in to server to check more details." | Out-File $OutputFile -Append
                }
        
            } else {
        Write-Output "SMBv1 status is: $DetectSMBStatus" | Out-File $OutputFile -Append

         }

}

# Detection logic for Windows Server 2012
if ($OSCaption -like "*Windows Server 2012*" -and $OSVersion -like "*.9200"){
        Write-Output "OS Name is: $OSCaption" | Out-File $OutputFile -Append
        Write-Output "OS Version is: $OSVersion" | Out-File $OutputFile -Append
   
        # Detect if SMB is Enabled
        $DetectSMBStatus = (Get-SmbServerConfiguration).EnableSMB1Protocol
            if ($DetectSMBStatus -eq "True"){
        
            # Disable smbv1
            Write-Output "SMBv1 enabled. Desabling SMBv1" | Out-File $OutputFile -Append
            $disableSmbv1 = Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            $disabledStatus = (Get-SmbServerConfiguration).EnableSMB1Protocol
            
                # Check if removal was successful or not
                if ($?) { 
                    Write-Output "SMBv1 is successfully disabled. NO Reboot required status: $disabledStatus" | Out-File $OutputFile -Append
        
                } else {
                    Write-Output "SMBv1 could not be disabled. Please Sign in to server to check more details." | Out-File $OutputFile -Append
                }
        
            } else {
        Write-Output "SMBv1 status is: $DetectSMBStatus" | Out-File $OutputFile -Append

        }
    }