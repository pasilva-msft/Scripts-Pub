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
rem   Author: Paulo da Silva and Marcus Ferreira
rem
echo Checking for Admin privileges
whoami /priv | findstr /i SeDebugPrivilege > nul
echo.

if ERRORLEVEL 1 ( 

echo ********************************************************
echo * This script must be run with elevated rights
echo ********************************************************
echo.
color 0c
pause
goto :nomorework ) 

echo Running elevated. Great! Continuing script execution
color 0a
echo.
echo ***************************************************
echo ************   Create Custom Request   ************
echo ***************************************************
echo.

if not "%SANEQUCN%" == "" set SANEQUCN=
if not "%SAN%" == "" set SAN=
set CryptoProvider=Microsoft Software Key Storage Provider

:createrequest

rem ** Collect data to create CSR (Certificate Signing Request)
echo Type Common Name for this request. Ex: SERVER.CONTOSO.COM
echo Do not use wildcard on CommonName (Ex: *.contoso.com)
echo Use wildcard on SAN (Subject Alternative Name)
set /p CommonName=

set SANEQUCN=%CommonName%

echo Whish to create multiple CSRs using same data? Ex: YES or NO
set /p multiplecerts=

rem echo Certificado de multiplos dominios? Ex: Exchange, Skype, SharePoint, etc... (YES or NO)
rem set /p SAN-OP=

rem if /I %SAN-OP% EQU NO goto CreateINF

echo If SAN is the same as Common Name, leave it blank, otherwise type Subject Alternative Name (SAN).
echo Follow this example: "&DNS=computer1.contoso.com&DNS=computer2.contoso.com&DNS=*.contoso.com"
set /p SAN=

echo Will private key be exportable? Ex: TRUE or FALSE
set /p ExportableKey=

echo Which Crypto Provider to use? KSP (CNG) or CSP (Legacy Provider)? Options: KSP or CSP
set /p CryptoProvider=

if /I %CryptoProvider% equ KSP (
	set CryptoProviderINF=Microsoft Software Key Storage Provider
)

if /I %CryptoProvider% equ CSP (
	set CryptoProviderINF=Microsoft RSA SChannel Cryptographic Provider
	rem set ProviderType= 12
)

REM echo Will CSR send to internal Certification Authority? (YES or NO)
REM set /p UseCertTmplt=

REM if /I %UseCertTmplt% EQU NO goto CreateINF

REM echo What is Certificate Template name (no spaces)? Ex: WebServer
REM set /p CertTemplate=

:CreateINF

if exist %temp%\requestINF.inf del %temp%\requestINF.inf /q
set requestINF=%temp%\requestINF.inf

rem ** Creating INF file based on infomation provided above

echo [Version] > %requestINF%
echo Signature="$Windows NT$" >> %requestINF%

echo.  >> %requestINF%
echo [NewRequest]  >> %requestINF%
echo Subject = "CN=%CommonName%,O = Contoso,L = Manaus,S = Amazonas,C = BR"    ; For a wildcard use "CN=*.CONTOSO.COM" for example  >> %requestINF%
rem ; For an empty subject use the following line instead or remove the Subject line entierely 
rem ; Subject = 
echo Exportable = %ExportableKey%                   ; Possible values: TRUE or FALSE >> %requestINF%
echo KeyLength = 2048                    ; Common key sizes: 512, 1024, 2048, 4096, 8192, 16384 >> %requestINF%
echo KeySpec = 1                         ; AT_KEYEXCHANGE >> %requestINF%
echo KeyUsage = 0xA0                     ; Digital Signature, Key Encipherment >> %requestINF%
echo MachineKeySet = True                ; The key belongs to the local computer account >> %requestINF%
echo ProviderName = %CryptoProviderINF% >> %requestINF%
echo KeyAlgorithm = RSA >> %requestINF%
rem echo ProviderType = %ProviderType% >> %requestINF%
echo SMIME = FALSE >> %requestINF%
echo RequestType = PKCS10 >> %requestINF%
echo HashAlgorithm = Sha256 >> %requestINF%
echo.  >> %requestINF%
rem ; At least certreq.exe shipping with Windows Vista/Server 2008 is required to interpret the [Strings] and [Extensions] sections below

echo [Strings] >> %requestINF%
echo szOID_SUBJECT_ALT_NAME2 = "2.5.29.17" >> %requestINF%
echo szOID_ENHANCED_KEY_USAGE = "2.5.29.37" >> %requestINF%
echo szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1" >> %requestINF%
echo szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2" >> %requestINF%

echo.  >> %requestINF%
echo [Extensions] >> %requestINF%
echo %%szOID_SUBJECT_ALT_NAME2%% = "{text}DNS=%SANEQUCN%%SAN%" >> %requestINF%
echo %%szOID_ENHANCED_KEY_USAGE%% = "{text}%%szOID_PKIX_KP_SERVER_AUTH%%,%%szOID_PKIX_KP_CLIENT_AUTH%%" >> %requestINF%

echo.  >> %requestINF%
echo 2.5.29.19 = "{text}ca=0"       ; Basic Constraints >> %requestINF%

echo.  >> %requestINF%
REM echo [RequestAttributes] >> %requestINF%
REM if /I %UsaCertTmplt% EQU NO goto CreateCSR

REM echo CertificateTemplate= %CertTemplate% >> %requestINF%

Echo.
echo Which folder you want to save CSR? Ex: C:\Temp
set /p user-path=

if not exist %user-path% mkdir %user-path%

if /I %multiplecerts% EQU YES goto loopreq

echo Creating CSR... This may take a few minutes...
Set randomnumber=%random%

certreq -new %requestINF% %user-path%\Request_%CommonName%_%randomnumber%.csr
echo Request (CSR) created successfully on folder %user-path%\Request_%CommonName%_%randomnumber%.csr

:createnewreq
echo.
echo Whish to create a new request? Ex: YES or NO
set /p newreq=
if /I %newreq% equ YES (
	goto multiplereqs
) Else (
	goto nomorework
)

:multiplereqs
echo Use same data? Ex: YES or NO
set /p data=

if /I %data% equ NO (
	goto createrequest
) Else (
	goto loopreq
)
goto nomorework

:loopreq
echo How many requests? Ex: 10
set /p qnt-req=

set count=1
set randomnumber=%random%
setlocal EnableDelayedExpansion
FOR /L %%i IN (1,1,%qnt-req%) DO (
	echo Request !count!
	certreq -new %requestINF% "%user-path%\Request_%CommonName%_%randomnumber%_!count!.csr"
	set /a count=!count!+1
)
setlocal DisableDelayedExpansion

echo Request (CSR) created successfully on folder %user-path%

goto createnewreq

:nomorework
REM clean up
rem if exist %temp%\requestINF.inf del %temp%\requestINF.inf /q