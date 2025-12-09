::::::::::::::::::::::::::::::::::::::::::
:: Automatcially check & get admin rights
::::::::::::::::::::::::::::::::::::::::::
@echo off
CLS
ECHO.
ECHO =====================================
ECHO Running Admin shell
ECHO =====================================

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%'=='0' (goto gotPrivileges) else (goto getPrivileges)

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO.
ECHO *************************************
ECHO Invoking UAC for Privilege Escalation
ECHO *************************************

ECHO Set UAC = CreateObject^("Shell.Application"^) > %vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " " >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul & shift /1)

::::::::::::::::::::::::::::::::::::::::::
:: START
::::::::::::::::::::::::::::::::::::::::::
ECHO.

SETLOCAL
CALL :GETPARENT PARENT
IF /I "%PARENT%" == "powershell" GOTO :ISPOWERSHELL
IF /I "%PARENT%" == "pwsh" GOTO :ISPWSH
ENDLOCAL

GOTO :ISPOWERSHELL

:GETPARENT
SET "PSCMD=$ppid=$pid;while($i++ -lt 3 -and ($ppid=(Get-CimInstance Win32_Process -Filter ('ProcessID='+$ppid)).ParentProcessId)) {}; (Get-Process -ErrorAction Ignore -ID $ppid).Name"

for /f "tokens=*" %%i in ('powershell -noprofile -command "%PSCMD%"') do SET %1=%%i

GOTO :EOF

:ISPOWERSHELL
SET PSEXE=powershell.exe
GOTO :EXECUTEPS

:ISPWSH
SET PSEXE=pwsh.exe
GOTO :EXECUTEPS

:EXECUTEPS
REM Check PowerShell execution policy (cannot be "Restricted")
ECHO Checking PowerShell execution policy...
%PSEXE% -NoProfile -Command "Try {$PSEXE = @(); If (Get-Command 'powershell.exe' -ErrorAction SilentlyContinue) {$PSEXE += 'powershell.exe'}; If (Get-Command 'pwsh.exe' -ErrorAction SilentlyContinue) {$PSEXE += 'pwsh.exe'}; ForEach ($Item in $PSEXE) {$Command = $Item + ' -NoProfile -Command {$PSVersionTable.PSVersion}'; $PSVersion = (Invoke-Expression -Command $Command); $FormattedVer = -join $PSVersion.Major,$PSVersion.Minor -join '.'; $Command = $Item + ' -NoProfile -Command {Get-ExecutionPolicy}'; $ExecPol = (Invoke-Expression -Command $Command).Value; If ($ExecPol -ne 'Restricted') {Write-Host 'PowerShell'$FormattedVer' Execution Policy : '$ExecPol' (Supported)' -ForegroundColor Green} Else {Write-Host 'PowerShell'$FormattedVer' Execution Policy : '$ExecPol' (Not supported)' -ForegroundColor Yellow; Write-Host ''; Write-Host 'PowerShell execution policy cannot be set to Restricted.  Please change with Set-ExecutionPolicy command.' -ForegroundColor Yellow; Write-Host 'Supported execution policies include AllSigned, RemoteSigned, or Unrestricted' -ForegroundColor Yellow; Write-Host ''}}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

ECHO.
REM Check for blocked files
ECHO Checking for blocked files...
%PSEXE% -NoProfile -Command "Try {$Blocked = $false; $Parent = Split-Path -Parent (Get-Location); $Content = Get-ChildItem $Parent -Recurse; ForEach ($Item in $Content) {If (Get-Item $Item.FullName -Stream * | Where-Object Stream -eq Zone.Identifier) {$Blocked = $true; Break}}; If ($Blocked -eq $true) {Write-Host 'File detected with the block attribute set.  Please run the following PowerShell command to correct:' -ForegroundColor Yellow; Write-Host ''; $Parent = [Char]34+$Parent+[Char]34; Write-Host 'Get-ChildItem' $Parent '-Recurse | Unblock-File' -ForegroundColor Cyan} Else {Write-Host 'No blocked files found' -ForegroundColor Green}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

ECHO.
ECHO Checking certificates...
REM Check for DoD Root CA 6 certificate
%PSEXE% -NoProfile -Command "Try {If (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq 'd37ecf61c0b4ed88681ef3630c4e2fc787b37aef') {Write-Host 'DoD Root CA 6 : Imported (Local Machine\Root)' -ForegroundColor Green} Else {Write-Host 'DoD Root CA 6 : Not imported (Local Machine\Root)' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

REM Check for DOD ID CA-72 certificate
%PSEXE% -NoProfile -Command "Try {If (Get-ChildItem Cert:\LocalMachine\CA | Where-Object Thumbprint -eq 'ce68b25fa532d959935aeb2c29e1358531903535') {Write-Host 'DOD ID CA-72  : Imported (Local Machine\CA)' -ForegroundColor Green} Else {Write-Host 'DOD ID CA-72  : Not imported (Local Machine\CA)' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

REM Check for CS.NAVAL SURFACE WARFARE CENTER CRANE DIVISION.001 certificate
%PSEXE% -NoProfile -Command "Try {If (Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object Thumbprint -eq '1c90ccc1c69525b37befb5fe139d8939e72eadb8') {Write-Host 'CS.NAVAL SURFACE WARFARE CENTER CRANE DIVISION.001 : Imported (Local Machine\Trusted Publishers)' -ForegroundColor Green} Else {Write-Host 'CS.NAVAL SURFACE WARFARE CENTER CRANE DIVISION.001 : Not imported (Local Machine\Trusted Publishers)' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

REM Check for expired CS.NSWCCD.001 certificate
%PSEXE% -NoProfile -Command "Try {If (Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object Thumbprint -eq 'D95F944E33528DC23BEE8672D6D38DA35E6F0017') {Write-Host 'CS.NSWCCD.001 : Expired (Local Machine\Trusted Publishers) - Please remove' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

ECHO.
PAUSE
EXIT /B