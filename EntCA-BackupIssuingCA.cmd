@echo off
echo This Sample Code is provided for the purpose of illustration only
echo and is not intended to be used in a production environment.  THIS
echo SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
echo WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
echo LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
echo FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
echo right to use and modify the Sample Code and to reproduce and distribute
echo the object code form of the Sample Code, provided that You agree:
echo (i) to not use Our name, logo, or trademarks to market Your software
echo product in which the Sample Code is embedded; (ii) to include a valid
echo copyright notice on Your software product in which the Sample Code is
echo embedded; and (iii) to indemnify, hold harmless, and defend Us and
echo Our suppliers from and against any claims or lawsuits, including
echo attorneys'' fees, that arise or result from the use or distribution
echo of the Sample Code.
echo Source: https://blogs.technet.microsoft.com/pki/2010/04/20/disaster-recovery-procedures-for-active-directory-certificate-services-adcs/
echo.
echo.
echo **********************************************************************
echo * IMPORTANT NOTE: Make sure CERTIFICATION AUTHORITY PRIVATE KEY is backed up separately!!!
echo **********************************************************************
echo.

set backupdb=c:\backupSubordinate

Echo Backup Certification Authority Database, Templates and CSP
c:

del %backupdb%\*.* /s /q
rd %backupdb% /s /q
echo.
Echo Backing up the Certification Authority Database
certutil -backupdb %backupdb%
echo.
Echo Backing up the registry keys
reg export HKLM\System\CurrentControlSet\Services\CertSvc\Configuration %backupdb%\regkeyCertSvcConfiguration.reg
reg export HKLM\System\CurrentControlSet\Services\CertSvc %backupdb%\regkeyCertSvc.reg
Certutil -v -getreg CA > %backupdb%\CertSvcConfiguration.txt
Certutil -v –getreg CA\CSP > %backupdb%\CSP.txt
echo.
Echo Documenting all certificate templates published at the CA
Certutil –catemplates > %backupdb%\CATemplates.txt
Echo.
Echo Copying CAPolicy.inf
copy %windir%\CAPolicy.inf %backupdb% /v /y
Echo.
Echo Copying Policy.inf
copy %windir%\Policy.inf %backupdb% /v /y
echo.
echo **********************************************************************
echo * IMPORTANT NOTE: Make sure CERTIFICATION AUTHORITY PRIVATE KEY is backed up separately!!!
echo **********************************************************************
pause