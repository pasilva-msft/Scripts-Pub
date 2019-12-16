@echo off
rem This Sample Code is provided for the purpose of illustration only
rem and is not intended to be used in a production environment.  THIS
rem SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
rem WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
rem LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
rem FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
rem right to use and modify the Sample Code and to reproduce and distribute
rem the object code form of the Sample Code, provided that You agree:
rem (i) to not use Our name, logo, or trademarks to market Your software
rem product in which the Sample Code is embedded; (ii) to include a valid
rem copyright notice on Your software product in which the Sample Code is
rem embedded; and (iii) to indemnify, hold harmless, and defend Us and
rem Our suppliers from and against any claims or lawsuits, including
rem attorneys'' fees, that arise or result from the use or distribution
rem of the Sample Code.
rem

rem The following variables may be used when defining CDP
rem and AIA URLs.
rem %1 = SERVERDNSNAME
rem %2 = SERVERSHORTNAME
rem %3 = SANITIZEDCANAME
rem %4 = CERTFILENAMESUFFIX
rem %5 = DOMAINDN
rem %6 = CONFIGDN
rem %7 = SANITIZEDCANAMEHASH
rem %8 = CRLFILENAMESUFFIX
rem %9 = CRLDELTAFILENAMESUFFIX
rem %10 = DSCRLATTRIBUTE
rem %11 = DSCACERTATTRIBUTE
rem %12 = DSUSERCERTATTRIBUTE
rem %13 = DSKRACERTATTRIBUTE
rem %14 = DSCROSSCERTPAIRATTRIBUTE

rem Each URL is prefaced by a value that indicates which
rem checkboxes are enabled for each distinct URL. The value is
rem the sum of the values assigned to each individual checkbox.

rem The following values are assigned for the CRL check boxes
rem ServerPublish = 1
rem AddtoCertCDP = 2
rem AddtoFreshestCRK = 4
rem AddtoCRLCDP = 8
rem ServerPublishDelta = 64

rem The following values are assigned for the AIA check boxes
rem ServerPublish = 1
rem AddtoCertCDP = 2
rem AddtoCertOCSP = 32

rem Set variables
set CDPAIAHTTPUrls=pki.fabrikam.com
set DSCfgDN=DC=fabrikam,DC=com
set CRLPeriUnits=1
rem Options: Years, Months, Weeks, Days and Hours
set CRLPeri=Years
set CRLOverUnits=2
rem Options: Years, Months, Weeks, Days and Hours
set CRLOverlapPeri=Weeks

rem  Enable All CA Auditing Events for the Root
rem  NOTE: Audit Policy for object access also needs to
rem  be configured (secpol.msc or GPO)

certutil -setreg CA\AuditFilter 127
auditpol /set /subcategory:"Certification Services" /failure:enable /success:enable


rem Declare Configuration NC
certutil -setreg ca\DSConfigDN CN=Configuration,%DSCfgDN%

rem Define CRL Publication Intervals
Certutil -setreg CA\CRLPeriodUnits %CRLPeriUnits%
Certutil -setreg CA\CRLPeriod "%CRLPeri%"
Certutil -setreg CA\CRLOverlapUnits %CRLOverUnits%
Certutil -setreg CA\CRLOverlapPeriod "%CRLOverlapPeri%"
Certutil -setreg CA\CRLDeltaPeriodUnits 0
Certutil -setreg CA\CRLDeltaPeriod "Days"

rem Modify the CDP Extension URLs
Certutil -setreg CA\CRLPublicationURLs "1:%windir%\System32\CertSrv\CertEnroll\%%3%%8%%9.crl\n2:http://%CDPAIAHTTPUrls%/CertData/%%3%%8%%9.crl"

Timeout /T 10

rem Modify the AIA Extension URLs
certutil -setreg CA\CACertPublicationURLs "1:%WINDIR%\system32\CertSrv\CertEnroll\%%1_%%3%%4.crt\n2:http://%CDPAIAHTTPUrls%/CertData/%%3%%4.crt"

Timeout /T 10

rem Set Validity Period for Issued Certificates
certutil -setreg CA\ValidityPeriodUnits 10 
certutil -setreg CA\ValidityPeriod "Years"

rem Restart Certificate Services
net stop certsvc & net start certsvc

Timeout /T 20

rem Issue a new CRL (Certificate Revocation List)
Certutil -crl
