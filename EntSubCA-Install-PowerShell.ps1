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


# Import required modules
Import-Module ServerManager
Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
Import-Module ADCSDeployment
Import-Module ADCSAdministration

# Set CA configuration variables
$CACNName="Fabrikam EnterpriseSubordinateCA"
$CAType="EnterpriseSubordinateCA"	#Specifies the type of certification authority to install. The possible values are: EnterpriseRootCA, EnterpriseSubordinateCA, StandaloneRootCA, or StandaloneSubordinateCA.
$CryptoProviderName="RSA#Microsoft Software Key Storage Provider"	#The name of the cryptographic service provider (CSP) or key storage provider (KSP) that is used to generate or store the private key for the CA.
$HashAlgorithmName="SHA256"	#Specifies the signature hash algorithm used by the certification authority.
$KeyLength=4096	# Specifies the bit length for new certification authority key. Options: 2048, 4096
$CADistinguishedNameSuffix="OU=IT,O=Fabrikam,C=BR"
$LogDirectory="C:\Windows\System32\CertLog"	#Change Default directory if needed. Default: C:\Windows\System32\CertLog
$DatabaseDirectory="C:\Windows\System32\CertLog"	#Change Default directory if needed. Default: C:\Windows\System32\CertLog


# Check if folder exists. If not, creates
If (-not(Test-Path $LogDirectory -PathType Container)){
 New-Item -Path $LogDirectory -ItemType Directory
}
If (-not(Test-Path $DatabaseDirectory -PathType Container)){
 New-Item -Path $DatabaseDirectory -ItemType Directory
}

Install-ADcsCertificationAuthority -CACommonName $CACNName -CAType $CAType `
-CryptoProviderName $CryptoProviderName -HashAlgorithmName $HashAlgorithmName `
-KeyLength $KeyLength -CADistinguishedNameSuffix $CADistinguishedNameSuffix `
-LogDirectory $LogDirectory -DatabaseDirectory $DatabaseDirectory -OverwriteExistingDatabase `
-OverwriteExistingCAinDS -OverwriteExistingKey -Force

# Remove ADCS configuration
#Uninstall-AdcsCertificationAuthority -force

# Uninstall ADCS bits
#Uninstall-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
