' This Sample Code is provided for the purpose of illustration only
' and is not intended to be used in a production environment.  THIS
' SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
' WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
' LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
' FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
' right to use and modify the Sample Code and to reproduce and distribute
' the object code form of the Sample Code, provided that You agree:
' (i) to not use Our name, logo, or trademarks to market Your software
' product in which the Sample Code is embedded; (ii) to include a valid
' copyright notice on Your software product in which the Sample Code is
' embedded; and (iii) to indemnify, hold harmless, and defend Us and
' Our suppliers from and against any claims or lawsuits, including
' attorneys'' fees, that arise or result from the use or distribution
' of the Sample Code.
' Source: https://docs.microsoft.com/pt-br/windows/desktop/Wua_Sdk/using-wua-to-scan-for-updates-offline
' Download URL (wsusscn2.cab): http://go.microsoft.com/fwlink/?linkid=74689

Set UpdateSession = CreateObject("Microsoft.Update.Session")
Set UpdateServiceManager = CreateObject("Microsoft.Update.ServiceManager")
Set UpdateService = UpdateServiceManager.AddScanPackageService("Offline Sync Service", "C:\Users\pasilva\Downloads\wsusscn2.cab", 1)
Set UpdateSearcher = UpdateSession.CreateUpdateSearcher()

WScript.Echo "Searching for updates..." & vbCRLF

UpdateSearcher.ServerSelection = 3 ' ssOthers

UpdateSearcher.ServiceID = UpdateService.ServiceID

Set SearchResult = UpdateSearcher.Search("IsInstalled=0")

Set Updates = SearchResult.Updates

If searchResult.Updates.Count = 0 Then
    WScript.Echo "There are no applicable updates."
    WScript.Quit
End If

WScript.Echo "List of applicable items on the machine when using wssuscan.cab:" & vbCRLF

For I = 0 to searchResult.Updates.Count-1
    Set update = searchResult.Updates.Item(I)
    WScript.Echo I + 1 & "> " & update.Title
Next

WScript.Quit