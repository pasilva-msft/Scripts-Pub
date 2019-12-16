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


rem Define CRL Publication Intervals
rem Certutil -setreg CA\CRLPeriodUnits 7
rem Certutil -setreg CA\CRLPeriod "Days"
rem Certutil -setreg CA\CRLDeltaPeriodUnits 1
rem Certutil -setreg CA\CRLDeltaPeriod "Days"

rem  Set variables
rem Options: Years, Months, Weeks, Days and Hours
set CDPAIAHTTPUrls=pki.fabrikam.com
set IISServer=myIIS.fabrikam.com\CertData$
set IISServer2=myIIS2.fabrikam.com\CertData$


Timeout /T 10

rem Apply the required CDP Extension URLs
rem  NOTE: When using the FILE protocol, ensure the CA has right permissions to the 
rem  target UNC destination. The Cert Publishers Group can be used.
Certutil -setreg CA\CRLPublicationURLs "65:%windir%\system32\CertSrv\CertEnroll\%%3%%8%%9.crl\n6:http://%CDPAIAHTTPUrls%/CertData/%%3%%8%%9.crl\n65:file://\\%IISServer%\%%3%%8%%9.crl\n65:file://\\%IISServer2%\%%3%%8%%9.crl"

Timeout /T 10

rem  Apply the required AIA Extension URLs
Certutil -setreg CA\CACertPublicationURLs "1:%windir%\system32\CertSrv\CertEnroll\%%1_%%3%%4.crt\n2:http://%CDPAIAHTTPUrls%/CertData/%%3%%4.crt"

Timeout /T 10

rem  Enable All Auditing Events for the lab issuing CA
Certutil -setreg CA\AuditFilter 127

Timeout /T 10

rem  Set Maximum Validity for Issued Certificates
Certutil -setreg CA\ValidityPeriodUnits 2
Certutil -setreg CA\ValidityPeriod "Years"

Timeout /T 10

rem  Restart Certificate services
net stop certsvc & net start certsvc

Timeout /T 20

rem Issue a new CRL (Certificate Revocation List)
Certutil -crl
