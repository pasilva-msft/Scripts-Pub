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
rem   Author: Paulo da Silva
rem
rem User certificate
certreq -v -config https://ndes.fabrikam.com/certsrv/mscep/mscep.dll/pkiclient.exe -username <user> -p <pass> -new c:\tools\req.inf c:\tools\req.req

certreq -v -config https://ndes.fabrikam.com/certsrv/mscep/mscep.dll/pkiclient.exe -username <user> -p <pass> -submit c:\tools\req.req c:\tools\Cert.cer

certreq -v -accept c:\tools\Cert.cer

rem Machine Certificate
certreq -v -machine -config https://ndes.fabrikam.com/certsrv/mscep/mscep.dll/pkiclient.exe -username <user> -p <pass> -new c:\tools\req.inf c:\tools\req.req

certreq -v -AdminForceMachine -config https://ndes.fabrikam.com/certsrv/mscep/mscep.dll/pkiclient.exe -username <user> -p <pass> -submit c:\tools\req.req c:\tools\Cert.cer

certreq -v -accept c:\tools\Cert.cer

[NewRequest]
Subject = "CN=computer.fabrikam.com"
RequestType = SCEP
KeyLength = 2048
ChallengePassword = <pass>