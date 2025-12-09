# SQL Initialization
if ([enum]::getvalues([System.Management.Automation.ActionPreference]) -contains 'ignore') {
    $ea_ignore = [System.Management.Automation.ActionPreference]::Ignore
}
else {
    $ea_ignore = [System.Management.Automation.ActionPreference]::SilentlyContinue
}

function Remove-DirectoryRecurse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (Test-Path $Path) {
            # Recursively get all files in $Path and check for file locks.
            Get-ChildItem -Path $Path -File -Recurse | ForEach-Object {
                if (-not(Wait-FileUnlock -Path $_.FullName -NoWait)) {
                    Wait-FileUnlock -Path $_.FullName -OutConsole -ErrorAction Stop | Out-Null
                }
            }

            # Recursively delete $Path
            [System.IO.Directory]::Delete($Path, $true)
        }
        else {
            throw "Path '$($Path)' not found."
        }
    }
    catch {
        throw $_
    }
}

function Split-Trim {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text,
        [string]$Separator = ',',
        [switch]$Unique
    )
    process {
        $parts = $Text -split [regex]::Escape($Separator) |
                 ForEach-Object { $_.Trim() } |
                 Where-Object { $_ -ne '' }

        if ($Unique) { $parts | Select-Object -Unique } else { $parts }
    }
}

Function Test-IsAdministrator {
    [CmdletBinding()]
    Param ()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Out-CenterString {
    param(
        [Parameter(Mandatory)] [string]$Text,
        [int]$Width = 90
    )
    return $Text.PadLeft(($Width + $Text.Length) / 2).PadRight($Width)
}

Function New-ValidationObject {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet($True, $False)]
        [bool]$Valid,

        [Parameter(Mandatory = $true)]
        [string]$Results
    )

    $ValidationResults = @{
        Valid   = $Valid
        Results = $Results
    }

    Return $ValidationResults
}

Function Get-FullHostName {
<#
.SYNOPSIS
    Returns an object containing short, long, and FQDN variants of the
    local hostname on any supported OS, without relying on DNS queries.
.EXAMPLE
    PS> Get-HostnameInfo

    ShortName  : COMPUTERWITHRE
    FullName  : ComputerWithReallyLongName1
    DomainName : corp.example
    FQDN       : ComputerWithReallyLongName1.corp.example
#>
    [CmdletBinding()]
    param ()

    # Helper: read the first matching line in a file
    function Get-FirstMatch {
        param ([string]$Path, [string]$Pattern)
        if (Test-Path $Path) {
            $m = Select-String -Path $Path -Pattern $Pattern -AllMatches |
                 Select-Object -First 1
            if ($m) { return $m.Matches[0].Groups[1].Value }
        }
    }

    if ($OSPlatform -eq "Windows") {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        $FullName   = $cs.DNSHostName            # full label, <63 chars
        $domainName = if ($cs.PartOfDomain) { $cs.Domain } else { $null }
        $shortName  = [Environment]::MachineName # 15-char NetBIOS

        $FQDN = if ($domainName) { "$FullName.$domainName" } else { $FullName }
    }
    else {
        # --- Linux / macOS path ---
        $FullName = & hostnamectl --static 2>$null
        if (-not $FullName) {
            foreach ($p in '/etc/hostname','/proc/sys/kernel/hostname') {
                if (Test-Path $p) {
                    $FullName = (Get-Content -Raw $p).Trim()
                    break
                }
            }
        }
        if (-not $FullName) {
            $FullName = "LOCALHOST"
        }

        # First 'search' or 'domain' directive in resolv.conf
        $domainName = Get-FirstMatch -Path '/etc/resolv.conf' `
                                     -Pattern '^\s*(?:search|domain)\s+(\S+)'

        $FullName = (($FullName).split("."))[0] #simplify the hostname to not be FQDN
        $shortName  = if ($FullName.Length -gt 15) {
                          $FullName.Substring(0,15)
                      } else { $FullName }

        $FQDN = if ($FullName -notmatch $domainName) { "$FullName.$domainName" } else { $FullName }
    }

    [pscustomobject]@{
        ShortName  = $shortName
        FullName   = $FullName
        DomainName = $domainName
        FQDN       = $FQDN
    }
}


Function Search-Files {
    # Use robocopy to search for files.  Faster than Get-ChildItem -Recurse in testing.
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $false)]
        [Array]$File = "*",

        [Parameter(Mandatory = $false)]
        [Array]$ExcludePath
    )

    If (Test-Path $Path) {
        # Robocopy doesn't like trailing backslashes unless a drive letter so strip it here
        $Path = Convert-Path -Path $($Path -replace '(?:^((?:[a-z]:)?\\)\\*$)|(.*?)(?:\\+)$', '$1$2')

        # Enclose $Path in quotes if it contains white space
        If ($Path -match "\s") {
            $Path = '"' + $Path + '"'
        }
        $RCArgs = "$Path $env:windir\Temp\null $('"{0}"' -f ($File -join '" "')) /S /L /FP /XJ /NDL /NJH /NJS /NC /NP /NS /R:0 /W:0"
        If ($ExcludePath) {
            $RCArgs += " /XD $('"{0}"' -f ($ExcludePath -join '" "'))"
        }

        $Result = (Start-ProcessWithOutput -FileName "robocopy.exe" -Arguments $RCArgs).StdOut.Split("`n").Trim()
        Return $Result | Where-Object {$_ -ne ""}
    }
}

Function Test-IsFileSearchRequired {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$ModulePath,

        [Parameter(Mandatory = $false)]
        [Array]$SelectVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeVuln
    )

    Try {
        $FileSearchReq = $true
        $FileSearchVulns = @()

        # Temporarily import scan module for access to Vuln functions
        If ($PowerShellVersion -lt [Version]"7.0") {
            Import-Module $ModulePath -ErrorAction Stop
        }
        Else {
            Import-Module $ModulePath -SkipEditionCheck -ErrorAction Stop
        }

        # Get list of commands that require 'Evaluate-STIG_FilesToScan\.txt' and unload module
        $FileSearchCommands = Get-Command -Module $(Split-Path -Path $ModulePath -Leaf) | Where-Object ScriptBlock -Match "Evaluate-STIG_FilesToScan\.txt"
        Remove-Module $(Split-Path -Path $ModulePath -Leaf) -Force

        If ($FileSearchCommands) {
            # Start with adding the Vuln to $FileSearchVulns if selected and needs a file search
            If ($SelectVuln) {
                ForEach ($Vuln in $SelectVuln) {
                    If ("Get-$($Vuln.Replace('-',''))" -in $FileSearchCommands.Name) {
                        $FileSearchVulns += $Vuln
                    }
                }
            }
            Else {
                $FileSearchVulns = $FileSearchCommands.Name -replace "Get-V","V-"
            }
        }

        If ($ExcludeVuln) {
            # Remove excluded vulns from $FileSearchVulns even if previously added (-ExcludeVuln overrules -SelectVuln)
            ForEach ($Vuln in $ExcludeVuln) {
                If ($Vuln -in $FileSearchVulns) {
                    $FileSearchVulns = $FileSearchVulns | Where-Object {$_ -ne $Vuln}
                }
            }
        }

        # If $FileSearchVulns is empty, then no file search is required
        If (-Not($FileSearchVulns)) {
            $FileSearchReq = $false
        }

        Return $FileSearchReq
    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Start-ProcessWithOutput ($FileName, $Arguments) {
    # Start a process and get the output.  Start-Process cannot do this without redirecting stdout/stderr to a file.
    $Output = [System.Collections.Generic.List[System.Object]]::new()

    $ProcInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcInfo.FileName = $FileName
    $ProcInfo.Arguments = $Arguments
    $ProcInfo.RedirectStandardError = $true
    $ProcInfo.RedirectStandardOutput = $true
    $ProcInfo.UseShellExecute = $false
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcInfo
    $Process.Start() | Out-Null

    $NewObj = [PSCustomObject]@{
        StdOut   = $Process.StandardOutput.ReadToEnd()
        StdErr   = $Process.StandardError.ReadToEnd()
        ExitCode = $Process.ExitCode
    }
    $Output.Add($NewObj)

    Return $Output
}

Function Get-SupportedProducts {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ES_Path
    )

    [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $OutList = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Node in $STIGList.List.STIG) {
        If (-Not(Test-Path (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent))) {
            $STIGVersion = "XCCDF missing"
        }
        Else {
            [xml]$Content = Get-Content (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent)
            $STIGVer = $Content.Benchmark.Version
            $STIGRel = ((($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Benchmark')[0].Trim() -split ' ')[1].Trim()
            $STIGVersion = "V$($STIGVer)R$($STIGRel)"
            $STIGDate = (($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Date:')[1].Trim()
        }

        $NewObj = [PSCustomObject]@{
            Name       = $Node.Name
            Shortname  = $Node.ShortName
            Version    = $STIGVersion
            Date       = $STIGDate
            DISAStatus = $Node.DisaStatus
        }
        $OutList.Add($NewObj)
    }
    Return $OutList
}

Function Get-ApplicableProducts {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$ES_Path,

        [Parameter(Mandatory = $false)]
        [Bool]$AllowDeprecated = $false,

        [Parameter(Mandatory = $false)]
        [Switch]$NoProgress = $false
    )

    [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $OutList = New-Object System.Collections.Generic.List[System.Object]

    # Build list of STIGs to check based on -AllowDeprecated
    If (-Not($AllowDeprecated)) {
        $STIGsToCheck = $STIGList.List.STIG | Where-Object DISAStatus -NE "Deprecated"
    }
    Else {
        $STIGsToCheck = $STIGList.List.STIG
    }

    $ProgressId = 1
    $ProgressActivity = "Checking STIG applicability"
    $TotalSteps = ($STIGsToCheck).Count
    $CurrentStep = 1
    ForEach ($Node in ($STIGsToCheck | Where-Object {$OSPlatform -in ($_.ApplicableOS -split ",").Trim() -and $_.AssetType -eq "Other"})) {
        If (-Not($NoProgress)) {
            Write-Progress -Id 1 -Activity $ProgressActivity -Status $Node.Name -PercentComplete ($CurrentStep / $TotalSteps * 100)
        }
        $CurrentStep++
        If ($Node.DetectionCode -and (Invoke-Expression $Node.DetectionCode) -eq $true) {
            If (-Not(Test-Path (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent))) {
                $STIGVersion = "XCCDF missing"
            }
            Else {
                [xml]$Content = Get-Content (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent)
                $STIGVer = $Content.Benchmark.Version
                $STIGRel = ((($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Benchmark')[0].Trim() -split ' ')[1].Trim()
                $STIGVersion = "V$($STIGVer)R$($STIGRel)"
                $STIGDate = (($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Date:')[1].Trim()
            }

            $NewObj = [PSCustomObject]@{
                Name       = $Node.Name
                Shortname  = $Node.ShortName
                Version    = $STIGVersion
                Date       = $STIGDate
                DISAStatus = $Node.DisaStatus
            }
            $OutList.Add($NewObj)
        }
    }
    If (-Not($NoProgress)) {
        Write-Progress -Id $ProgressId -Activity $ProgressActivity -Completed
    }
    Return $OutList
}

Function Get-FileUpdatesFromRepo {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $PS_Path,

        [Parameter(Mandatory = $false)]
        [String] $Proxy,

        [Parameter(Mandatory = $false)]
        [String] $LocalSource
    )

    Try {
        # Check for updated content with upstream
        $Result = Start-EvalSTIGUpdate -PS_Path $PS_Path -Proxy $Proxy -LocalSource $LocalSource

        # If newer 'Updating' module is found remove current and import
        if ($Result.UpdateRequired) {
            Remove-Module Updating -Force -ErrorAction Stop
            $UpdateModule = $(Split-Path -Path (Get-ChildItem $Update_tmp -Filter "*Updating.psm1" -Recurse).FullName -Parent)
            if ($UpdateModule) {
                if ($PowerShellVersion -lt [Version]"7.0") {
                    Import-Module $UpdateModule -ErrorAction Stop
                }
                else {
                    Import-Module $UpdateModule -SkipEditionCheck -ErrorAction Stop
                }
            }
            else {
                throw "'Updating' module not found in '$Update_tmp'.  Unable to continue."
            }
            # ...and run again to apply update
            $Result = Start-EvalSTIGUpdate -PS_Path $PS_Path -Proxy $Proxy -LocalSource $LocalSource -ResumeUpdate
        }
        Write-Host $Result.Message
    }
    Catch {
        Throw $_
    }
}

Function Get-Creds {
    <#
.NOTES
Author: Joshua Chase
Last Modified: 09 September 2019
Version: 1.1.0
C# signatures obtained from PInvoke.
#>
    [cmdletbinding()]
    Param()
    $Code = @"
using System;
using System.Text;
using System.Security;
using System.Management.Automation;
using System.Runtime.InteropServices;
public class Credentials
{
    private const int CREDUIWIN_GENERIC = 1;
    private const int CREDUIWIN_CHECKBOX = 2;
    private const int CREDUIWIN_AUTHPACKAGE_ONLY = 16;
    private const int CREDUIWIN_IN_CRED_ONLY = 32;
    private const int CREDUIWIN_ENUMERATE_ADMINS = 256;
    private const int CREDUIWIN_ENUMERATE_CURRENT_USER = 512;
    private const int CREDUIWIN_SECURE_PROMPT = 4096;
    private const int CREDUIWIN_PACK_32_WOW = 268435456;
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern uint CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
        int authError,
        ref uint authPackage,
        IntPtr InAuthBuffer,
        uint InAuthBufferSize,
        out IntPtr refOutAuthBuffer,
        out uint refOutAuthBufferSize,
        ref bool fSave,
        int flags);
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
        IntPtr pAuthBuffer,
        uint cbAuthBuffer,
        StringBuilder pszUserName,
        ref int pcchMaxUserName,
        StringBuilder pszDomainName,
        ref int pcchMaxDomainame,
        StringBuilder pszKey,
        ref int pcchMaxKey);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }
    public static PSCredential getPSCred()
    {
        bool save = false;
        int authError = 0;
        uint result;
        uint authPackage = 0;
        IntPtr outCredBuffer;
        uint outCredSize;
        PSCredential psCreds = null;
        var credui = new CREDUI_INFO
                                {
                                    pszCaptionText = "Enter your credentials",
                                    pszMessageText = "These credentials will be used for Evaluate-STIG remote scans"
                                };
        credui.cbSize = Marshal.SizeOf(credui);
        while (true) //Show the dialog again and again, until Cancel is clicked or the entered credentials are correct.
        {
            //Show the dialog
            result = CredUIPromptForWindowsCredentials(ref credui,
            authError,
            ref authPackage,
            IntPtr.Zero,
            0,
            out outCredBuffer,
            out outCredSize,
            ref save,
            CREDUIWIN_ENUMERATE_CURRENT_USER);
            if (result != 0) break;
            var usernameBuf = new StringBuilder(100);
            var keyBuf = new StringBuilder(100);
            var domainBuf = new StringBuilder(100);
            var maxUserName = 100;
            var maxDomain = 100;
            var maxKey = 100;
            if (CredUnPackAuthenticationBuffer(1, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, keyBuf, ref maxKey))
            {
                Marshal.ZeroFreeCoTaskMemUnicode(outCredBuffer);
                var key = new SecureString();
                foreach (char c in keyBuf.ToString())
                {
                    key.AppendChar(c);
                }
                keyBuf.Clear();
                key.MakeReadOnly();
                psCreds = new PSCredential(usernameBuf.ToString(), key);
                GC.Collect();
                break;
            }

            else authError = 1326; //1326 = 'Logon failure: unknown user name or bad password.'
        }
        return psCreds;
    }
}
"@

    Add-Type -TypeDefinition $Code -Language CSharp

    Write-Output ([Credentials]::getPSCred())
}

Function Get-RunspaceData {
    [cmdletbinding()]
    param(
        [System.Collections.ArrayList]$Runspaces,

        [switch]$Wait,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Cisco", "Remote", "VCenter")]
        [String]$Usage
    )
    $RunspacesCount = ($Runspaces | Measure-Object).Count
    $RunspacesCompleteCount = 0

    Do {
        $more = $false
        Foreach ($runspace in $runspaces) {
            If ($runspace.Runspace.State.isCompleted) {
                $runspace.Job.dispose()
                $runspace.Runspace = $null
                $runspace.Job = $null
            }
            ElseIf ($null = $runspace.Runspace) {
                $more = $true
            }
        }
        If ($more -AND $PSBoundParameters['Wait']) {
            Start-Sleep -Milliseconds 100
        }
        #Clean out unused runspace jobs
        $temphash = $runspaces.clone()
        $temphash | Where-Object {
            $Null -eq $_.runspace
        } | ForEach-Object {
            $RunspacesCompleteCount++
            $Runspaces.remove($_)
        }

        Switch ($Usage) {
            'VCenter' {
                $ProgSplat = @{
                    Activity         = "Running VCenter Scans: $ProgressActivity"
                    Status           = ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count))
                    PercentComplete  = ($RunspacesCompleteCount / $RunspacesCount * 100)
                    CurrentOperation = "Remaining: $($Runspaces.VMName -join ", ")"
                }
                Write-Progress @ProgSplat
            }
            "Cisco" {
                Write-Progress -Activity "Running Cisco Config Scans: $ProgressActivity" -Status ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count)) -PercentComplete ($RunspacesCompleteCount / $RunspacesCount * 100) -CurrentOperation "Remaining: $($Runspaces.Hostname -join ", ")"
            }
            "Remote" {
                $RunningRunspaces = @((Get-Runspace | Where-Object RunspaceStateInfo -notlike "*Closed*").ConnectionInfo.ComputerName | Sort-Object -Unique | ForEach-Object { ($_).Split('.')[0] })
                Write-Progress -Activity "Running Remote Scans: $ProgressActivity" -Status ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count)) -PercentComplete ($RunspacesCompleteCount / $RunspacesCount * 100) -CurrentOperation "Scanning: $RunningRunspaces"
            }
        }
    } while ($more -AND $PSBoundParameters['Wait'])

    Switch ($Usage) {
        'VCenter' {
            Write-Progress -Activity "Running VCenter Scans: $ProgressActivity" -Completed
        }
        "Cisco" {
            Write-Progress -Activity "Running Cisco Config Scans: $ProgressActivity" -Completed
        }
        "Remote" {
            Remove-Variable RunningRunspaces
            Write-Progress -Activity "Running Remote Scans: $ProgressActivity" -Completed
        }
    }
}

Function Get-FileEncoding {
    <# http://franckrichard.blogspot.com/2010/08/powershell-get-encoding-file-type.html
    https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/get-text-file-encoding
    http://unicode.org/faq/utf_bom.html
    http://en.wikipedia.org/wiki/Byte_order_mark

    Modified by Dan Ireland March 2021
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$Path
    )

    $Encoding = "ASCII (no BOM)"

    $BOM = New-Object -TypeName System.Byte[](4)
    $File = New-Object System.IO.FileStream($Path, 'Open', 'Read')
    $null = $File.Read($BOM, 0, 4)
    $File.Close()
    $File.Dispose()

    # EF BB BF (UTF8 with BOM)
    If ($BOM[0] -eq 0xef -and $BOM[1] -eq 0xbb -and $BOM[2] -eq 0xbf -and $BOM[3] -eq 0x23) {
        $Encoding = "UTF-8 with BOM"
    }

    # FE FF  (UTF-16 Big-Endian)
    ElseIf ($BOM[0] -eq 0xfe -and $BOM[1] -eq 0xff) {
        $Encoding = "UTF-16 BE"
    }

    # FF FE  (UTF-16 Little-Endian)
    ElseIf ($BOM[0] -eq 0xff -and $BOM[1] -eq 0xfe) {
        $Encoding = "UTF-16 LE"
    }

    # 00 00 FE FF (UTF32 Big-Endian)
    ElseIf ($BOM[0] -eq 0 -and $BOM[1] -eq 0 -and $BOM[2] -eq 0xfe -and $BOM[3] -eq 0xff) {
        $Encoding = "UTF32 Big-Endian"
    }

    # FE FF 00 00 (UTF32 Little-Endian)
    ElseIf ($BOM[0] -eq 0xfe -and $BOM[1] -eq 0xff -and $BOM[2] -eq 0 -and $BOM[3] -eq 0) {
        $Encoding = "UTF32 Little-Endian"
    }

    # 2B 2F 76 (38 | 38 | 2B | 2F)
    ElseIf ($BOM[0] -eq 0x2b -and $BOM[1] -eq 0x2f -and $BOM[2] -eq 0x76 -and ($BOM[3] -eq 0x38 -or $BOM[3] -eq 0x39 -or $BOM[3] -eq 0x2b -or $BOM[3] -eq 0x2f)) {
        $Encoding = "UTF7"
    }

    # F7 64 4C (UTF-1)
    ElseIf ($BOM[0] -eq 0xf7 -and $BOM[1] -eq 0x64 -and $BOM[2] -eq 0x4c ) {
        $Encoding = "UTF-1"
    }

    # DD 73 66 73 (UTF-EBCDIC)
    ElseIf ($BOM[0] -eq 0xdd -and $BOM[1] -eq 0x73 -and $BOM[2] -eq 0x66 -and $BOM[3] -eq 0x73) {
        $Encoding = "UTF-EBCDIC"
    }

    # 0E FE FF (SCSU)
    ElseIf ( $BOM[0] -eq 0x0e -and $BOM[1] -eq 0xfe -and $BOM[2] -eq 0xff ) {
        $Encoding = "SCSU"
    }

    # FB EE 28  (BOCU-1)
    ElseIf ( $BOM[0] -eq 0xfb -and $BOM[1] -eq 0xee -and $BOM[2] -eq 0x28 ) {
        $Encoding = "BOCU-1"
    }

    # 84 31 95 33 (GB-18030)
    ElseIf ($BOM[0] -eq 0x84 -and $BOM[1] -eq 0x31 -and $BOM[2] -eq 0x95 -and $BOM[3] -eq 0x33) {
        $Encoding = "GB-18030"
    }

    Return $Encoding
}

Function Wait-FileUnlock {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Yes", "No", "Never")]
        [String]$GetLockingProcess = "No",

        [Parameter(Mandatory = $false)]
        [ValidateSet("OpenRead", "OpenWrite")]
        [String]$OpenType = "OpenRead",

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$RetrySeconds = 10,

        [Parameter(Mandatory = $false)]
        [switch]$OutConsole,

        [Parameter(Mandatory = $false)]
        [switch]$NoWait
    )

    Function Get-FileLockProcess {
        # Derived from https://github.com/pldmgg/misc-powershell/blob/master/MyFunctions/PowerShellCore_Compatible/Get-FileLockProcess.ps1

        <#
        .SYNOPSIS
        Check which process is locking a file

        .DESCRIPTION
        On Windows, Get-FileLockProcess takes a path to a file and returns a System.Collections.Generic.List of
        System.Diagnostic.Process objects (one or more processes could have a lock on a specific file, which is why
        a List is used).

        On Linux, this function returns a PSCustomObject with similar properties.

        .NOTES
        Windows solution credit to: https://stackoverflow.com/a/20623311

        .PARAMETER FilePath
        This parameter is MANDATORY.

        This parameter takes a string that represents a full path to a file.

        .EXAMPLE
        # On Windows...
        PS C:\Users\testadmin> Get-FileLockProcess -FilePath "$HOME\Downloads\call_activity_2017_Nov.xlsx"

        Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
        -------  ------    -----      -----     ------     --  -- -----------
        1074      51    50056      86984       5.86   2856   2 EXCEL

        .EXAMPLE
        # On Linux/MacOS
        PS /home/pdadmin/Downloads> Get-FileLockProcess -FilePath "/home/pdadmin/Downloads/test.txt"

        COMMAND  : bash
        PID      : 244585
        USER     : pdadmin
        FD       : 3w
        TYPE     : REG
        DEVICE   : 253,2
        SIZE/OFF : 0
        NODE     : 100798534
        NAME     : /home/pdadmin/Downloads/test.txt
        #>

        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [string]$FilePath
        )

        If (-Not(Test-Path $FilePath)) {
            Throw "The path $FilePath was not found! Halting!"
        }

        If ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $($PSVersionTable.PSVersion.Major -le 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
            $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

            $AssembliesFullInfo = $CurrentlyLoadedAssemblies | Where-Object {$_.GetName().Name -in @(
                    "Microsoft.CSharp",
                    "mscorlib",
                    "System",
                    "System.Collections",
                    "System.Core",
                    "System.IO",
                    "System.Linq",
                    "System.Runtime",
                    "System.Runtime.Extensions",
                    "System.Runtime.InteropServices",
                    "System.Diagnostics.Process", # Added to support Powershell 7
                    "System.ComponentModel.Primitives" # Added to support Powershell 7
                )
            }
            $AssembliesFullInfo = $AssembliesFullInfo | Where-Object {$_.IsDynamic -eq $False}
            $ReferencedAssemblies = $AssembliesFullInfo.FullName | Sort-Object | Get-Unique

            $usingStatementsAsString = @"
                using Microsoft.CSharp;
                using System.Collections.Generic;
                using System.Collections;
                using System.IO;
                using System.Linq;
                using System.Runtime.InteropServices;
                using System.Runtime;
                using System;
                using System.Diagnostics;
"@

            $TypeDefinition = @"
                $usingStatementsAsString

                namespace MyCore.Utils
                {
                    static public class FileLockUtil
                    {
                        [StructLayout(LayoutKind.Sequential)]
                        struct RM_UNIQUE_PROCESS
                        {
                            public int dwProcessId;
                            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
                        }

                        const int RmRebootReasonNone = 0;
                        const int CCH_RM_MAX_APP_NAME = 255;
                        const int CCH_RM_MAX_SVC_NAME = 63;

                        enum RM_APP_TYPE
                        {
                            RmUnknownApp = 0,
                            RmMainWindow = 1,
                            RmOtherWindow = 2,
                            RmService = 3,
                            RmExplorer = 4,
                            RmConsole = 5,
                            RmCritical = 1000
                        }

                        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                        struct RM_PROCESS_INFO
                        {
                            public RM_UNIQUE_PROCESS Process;

                            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
                            public string strAppName;

                            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
                            public string strServiceShortName;

                            public RM_APP_TYPE ApplicationType;
                            public uint AppStatus;
                            public uint TSSessionId;
                            [MarshalAs(UnmanagedType.Bool)]
                            public bool bRestartable;
                        }

                        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
                        static extern int RmRegisterResources(uint pSessionHandle,
                                                            UInt32 nFiles,
                                                            string[] rgsFilenames,
                                                            UInt32 nApplications,
                                                            [In] RM_UNIQUE_PROCESS[] rgApplications,
                                                            UInt32 nServices,
                                                            string[] rgsServiceNames);

                        [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
                        static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

                        [DllImport("rstrtmgr.dll")]
                        static extern int RmEndSession(uint pSessionHandle);

                        [DllImport("rstrtmgr.dll")]
                        static extern int RmGetList(uint dwSessionHandle,
                                                    out uint pnProcInfoNeeded,
                                                    ref uint pnProcInfo,
                                                    [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
                                                    ref uint lpdwRebootReasons);

                        /// <summary>
                        /// Find out what process(es) have a lock on the specified file.
                        /// </summary>
                        /// <param name="path">Path of the file.</param>
                        /// <returns>Processes locking the file</returns>
                        /// <remarks>See also:
                        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa373661(v=vs.85).aspx
                        /// http://wyupdate.googlecode.com/svn-history/r401/trunk/frmFilesInUse.cs (no copyright in code at time of viewing)
                        ///
                        /// </remarks>
                        static public List<Process> WhoIsLocking(string path)
                        {
                            uint handle;
                            string key = Guid.NewGuid().ToString();
                            List<Process> processes = new List<Process>();

                            int res = RmStartSession(out handle, 0, key);
                            if (res != 0) throw new Exception("Could not begin restart session.  Unable to determine file locker.");

                            try
                            {
                                const int ERROR_MORE_DATA = 234;
                                uint pnProcInfoNeeded = 0,
                                    pnProcInfo = 0,
                                    lpdwRebootReasons = RmRebootReasonNone;

                                string[] resources = new string[] { path }; // Just checking on one resource.

                                res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);

                                if (res != 0) throw new Exception("Could not register resource.");

                                //Note: there's a race condition here -- the first call to RmGetList() returns
                                //      the total number of process. However, when we call RmGetList() again to get
                                //      the actual processes this number may have increased.
                                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

                                if (res == ERROR_MORE_DATA)
                                {
                                    // Create an array to store the process results
                                    RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                                    pnProcInfo = pnProcInfoNeeded;

                                    // Get the list
                                    res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                                    if (res == 0)
                                    {
                                        processes = new List<Process>((int)pnProcInfo);

                                        // Enumerate all of the results and add them to the
                                        // list to be returned
                                        for (int i = 0; i < pnProcInfo; i++)
                                        {
                                            try
                                            {
                                                processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                                            }
                                            // catch the error -- in case the process is no longer running
                                            catch (ArgumentException) { }
                                        }
                                    }
                                    else throw new Exception("Could not list processes locking resource.");
                                }
                                else if (res != 0) throw new Exception("Could not list processes locking resource. Failed to get size of result.");
                            }
                            finally
                            {
                                RmEndSession(handle);
                            }

                            return processes;
                        }
                    }
                }
"@

            $CheckMyCoreUtilsFileLockUtilLoaded = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.FileLockUtil*"}
            If ($null -eq $CheckMyCoreUtilsFileLockUtilLoaded) {
                Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition
            }
            Else {
                Write-Verbose "The Namespace MyCore.Utils Class FileLockUtil is already loaded and available!"
            }

            $Result = [MyCore.Utils.FileLockUtil]::WhoIsLocking($FilePath)
        }
        If ($null -ne $PSVersionTable.Platform -and $PSVersionTable.Platform -ne "Win32NT") {
            $lsofOutput = lsof -w $FilePath # -w to squelch warning messages
            if ($lsofOutput){
                Function Get-lsofStrings ($lsofOutput, $Index) {
                    $($lsofOutput[$Index] -split " " | ForEach-Object {
                            If (-Not([String]::IsNullOrWhiteSpace($_))) {
                                $_
                            }
                        }).Trim()
                }

                $lsofOutputHeaders = Get-lsofStrings -lsofOutput $lsofOutput -Index 0
                $lsofOutputValues = Get-lsofStrings -lsofOutput $lsofOutput -Index 1

                $Result = [pscustomobject]@{}
                For ($i = 0; $i -lt $lsofOutputHeaders.Count; $i++) {
                    $Result | Add-Member -MemberType NoteProperty -Name $lsofOutputHeaders[$i] -Value $lsofOutputValues[$i]
                }
            }
            else{
                $Result = $null
            }
        }

        Return $Result
    } # End Function Get-FileLockProcess {

    Try {
        If ($GetLockingProcess -eq "Yes") {
            Return Get-FileLockProcess -FilePath $Path
        }
        Else {
            $null = Get-ChildItem -Path $Path -ErrorAction Stop
            $Unlocked = $false
            Try {
                [System.IO.File]::$OpenType($Path).Close()
                $Unlocked = $true
                $Result = $true
            }
            Catch {
                If ($NoWait) {
                    # Just return $false as the output to quickly notify that the file is currently locked
                    Return $false
                }

                $i = 1
                While ($i -le $MaxRetries -and $Unlocked -ne $true) {
                    If ($OutConsole) {
                        Write-Host "$($Path) is locked by another process.  Retrying..." -ForegroundColor Yellow
                    }
                    $i++
                    Start-Sleep -Seconds $RetrySeconds
                    Try {
                        [System.IO.File]::$OpenType($Path).Close()
                        $Unlocked = $true
                        $Result = $true
                    }
                    Catch {
                        $Result = $_
                    }
                }
            }

            If ($Unlocked) {
                Return $Result
            }
            Else {
                If (($GetLockingProcess -ne "Never") -and ((-Not($IsLinux)) -or (Get-Command lsof -ErrorAction SilentlyContinue))) {
                    $LockingProcess = Wait-FileUnlock -Path "$Path" -GetLockingProcess Yes
                }

                If ($LockingProcess) {
                    # Add locking process info to read-only $Result
                    # https://learn-powershell.net/2016/06/27/quick-hits-writing-to-a-read-only-property/
                    $Msg = "$($Result.Exception.Message) Locking process: $($LockingProcess.ProcessName) [PID $($LockingProcess.Id)]"
                    $Field = $Result.Exception.GetType().GetField("_message", "static,nonpublic,instance")
                    $Field.SetValue($Result.Exception, $Msg)
                    if ($OutConsole) {
                        Write-Host $Msg -ForegroundColor Yellow
                    }
                }

                Throw $Result
            }
        }
    }
    Catch {
        Throw $_
    }
}

Function Initialize-Archiving {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Compress", "Expand")]
        [String]$Action,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$DestinationPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Fastest", "NoCompression", "Optimal")]
        [String]$CompressionLevel = "Optimal",

        [Parameter(Mandatory = $false)]
        [Switch]$Force,

        [Parameter(Mandatory = $false)]
        [Switch]$Update
    )

    # Create runspace pool to include required modules.
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.ImportPSModule('Microsoft.PowerShell.Archive')
    $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList 'Wait-FileUnlock', ${Function:Wait-FileUnlock}
    $SessionState.Commands.Add($SessionStateFunction)
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $SessionState, $Host)
    $RunspacePool.Open()

    Switch ($Action) {
        "Compress" {
            $Command = "Get-ChildItem -Path '$Path' -File -Recurse -ErrorAction Stop | ForEach-Object {[Void](Wait-FileUnlock -Path " + '$_.FullName' + " -ErrorAction Stop)}; Compress-Archive -Path '$Path' -DestinationPath '$DestinationPath' -CompressionLevel $CompressionLevel -ErrorAction Stop"
            If ($Force) {
                $Command = $Command + " -Force"
            }
            If ($Update) {
                $Command = $Command + " -Update"
            }
        }
        "Expand" {
            $Command = "[Void](Wait-FileUnlock -Path '$Path' -ErrorAction Stop); Expand-Archive -Path '$Path' -DestinationPath '$DestinationPath' -ErrorAction Stop"
            If ($Force) {
                $Command = $Command + " -Force"
            }
        }
    }

    Try {
        $Result = Invoke-CodeWithTimeout -CommandString $Command -Timeout 5 -RunspacePool $RunspacePool
        If (($Result | Measure-Object).count -gt 1){
            $Result = $Result[-1] #Required to remove STDOUT from "Returned" results (Issue 1841)
        }
        If ($Result.Keys -contains "CodeFail") {
            Throw "CodeFail"
        }
        $RunspacePool.Close()
        $RunspacePool.Dispose()

        Return "Success"
    }
    Catch {
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        Return $Result.ErrorData
    }
}

Function Initialize-FileXferToRemote {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $NETBIOS,

        [Parameter(Mandatory = $true)]
        [String] $RemoteTemp,

        [Parameter(Mandatory = $false)]
        [String] $OutputPath,

        [Parameter(Mandatory = $false)]
        [String] $AFPath,

        [Parameter(Mandatory = $false)]
        [String] $Remote_Log,

        [Parameter(Mandatory = $false)]
        [String] $LogComponent,

        [Parameter(Mandatory = $false)]
        [String] $OSPlatform,

        [Parameter(Mandatory = $false)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $false)]
        [String] $ScriptRoot,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession] $Session
    )

    Try {
        # Put Wait-FileUnlock function into a variable to be passed to remote as remote will not have this function in memory
        $WaitUnlockFunc = ${Function:Wait-FileUnlock}

        Write-Log -Path $Remote_Log -Message "Copying Evaluate-STIG archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Wait-FileUnlock -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath ESCONTENT.ZIP) -ErrorAction Stop
        Copy-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath ESCONTENT.ZIP) -Destination $(Join-Path -Path $RemoteTemp -ChildPath \) -Force -ToSession $Session -ErrorAction Stop

        Write-Log -Path $Remote_Log -Message "Expanding Evaluate-STIG archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock {param($RemoteTemp) Set-Item Function:Wait-FileUnlock $Using:WaitUnlockFunc; Wait-FileUnlock -Path $(Join-Path -Path $RemoteTemp -ChildPath ESCONTENT.ZIP) -GetLockingProcess Never -ErrorAction Stop; Import-Module Microsoft.PowerShell.Archive -ErrorAction Stop; $Global:ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath ESCONTENT.ZIP) -DestinationPath $RemoteTemp -Force -ErrorAction Stop} -Session $Session -ArgumentList $RemoteTemp -ErrorAction Stop

        If (($AFPath.TrimEnd('\')).TrimEnd('/') -ne (Join-Path -Path $ScriptRoot -ChildPath "AnswerFiles")) {
            # If AnswerFiles folder doesn't exist, create it
            Invoke-Command -ScriptBlock {param($RemoteTemp) If (-Not(Test-Path $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles))) {$null = New-Item -Path $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles) -ItemType Directory -Force -ErrorAction Stop}} -Session $Session -ArgumentList $RemoteTemp -ErrorAction Stop

            Write-Log -Path $Remote_Log -Message "Copying answer file archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Invoke-Command -ScriptBlock {param($RemoteTemp) Remove-Item -Path $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles | Join-Path -ChildPath *.xml) -Force -ErrorAction Stop} -Session $Session -ArgumentList $RemoteTemp -ErrorAction Stop
            If (Test-Path -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath AFILES.ZIP)) {
                Wait-FileUnlock -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath AFILES.ZIP) -ErrorAction Stop
                Copy-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath AFILES.ZIP) -Destination $(Join-Path -Path $RemoteTemp -ChildPath \) -Force -ToSession $Session -ErrorAction Stop
                Write-Log -Path $Remote_Log -Message "Expanding answer file archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Invoke-Command -ScriptBlock {param($RemoteTemp) Set-Item Function:Wait-FileUnlock $Using:WaitUnlockFunc; Wait-FileUnlock -Path $(Join-Path -Path $RemoteTemp -ChildPath AFILES.ZIP) -GetLockingProcess Never -ErrorAction Stop; Import-Module Microsoft.PowerShell.Archive -ErrorAction Stop; $Global:ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath AFILES.ZIP) -DestinationPath $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles) -Force -ErrorAction Stop} -Session $Session -ArgumentList $RemoteTemp -ErrorAction Stop
            }
        }
    }
    Catch {
        Throw $_
    }
}

Function Initialize-FileXferFromRemote {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $NETBIOS,

        [Parameter(Mandatory = $true)]
        [String] $RemoteTemp,

        [Parameter(Mandatory = $false)]
        [String] $OutputPath,

        [Parameter(Mandatory = $false)]
        [String] $Remote_Log,

        [Parameter(Mandatory = $false)]
        [String] $LogComponent,

        [Parameter(Mandatory = $false)]
        [String] $OSPlatform,

        [Parameter(Mandatory = $false)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $false)]
        [String] $ScriptRoot,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession] $session
    )

    Try {
        # Put Wait-FileUnlock function into a variable to be passed to remote as remote will not have this function in memory
        $WaitUnlockFunc = ${Function:Wait-FileUnlock}

        Write-Log -Path $Remote_Log -Message "Compressing Evaluate-STIG results" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock {param($RemoteTemp, $NETBIOS) Compress-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath $NETBIOS) -DestinationPath $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath "$($NETBIOS).ZIP") -CompressionLevel Optimal -Force -ErrorAction Stop} -Session $Session -ArgumentList $RemoteTemp, $NETBIOS -ErrorAction Stop

        Write-Log -Path $Remote_Log -Message "Copying Evaluate-STIG results archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock {param($RemoteTemp) Set-Item Function:Wait-FileUnlock $Using:WaitUnlockFunc; Wait-FileUnlock -Path $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath "$($NETBIOS).ZIP") -GetLockingProcess Never -ErrorAction Stop} -Session $Session -ArgumentList $RemoteTemp -ErrorAction Stop
        Copy-Item -Path $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath "$($NETBIOS).ZIP") -Destination $RemoteWorkingDir -Force -FromSession $Session -ErrorAction Stop

        Write-Log -Path $Remote_Log -Message "Expanding Evaluate-STIG results archive to $OutputPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        $Result = Initialize-Archiving -Action Expand -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "$($NETBIOS).ZIP") -DestinationPath $OutputPath -Force -ErrorAction Stop
        If ($Result -ne "Success") {
            Throw $Result
        }

        Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "$($NETBIOS).ZIP") -Force -ErrorAction Stop
    }
    Catch {
        Throw $_
    }
}

Function Test-STIGDependencyFiles {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$RootPath,

        [Parameter(Mandatory = $true)]
        [psobject]$STIGData,

        [Parameter(Mandatory = $true)]
        [psobject]$LogPath,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform
    )

    $Pass = $true
    $FailedFiles = @{}
    $DependentFiles = @(
        $(Join-Path -Path $RootPath -ChildPath "StigContent" | Join-Path -ChildPath $STIGData.StigContent),
        $(Join-Path -Path $RootPath -ChildPath "Modules" | Join-Path -ChildPath $STIGData.PsModule | Join-Path -ChildPath "$($STIGData.PsModule).psd1"),
        $(Join-Path -Path $RootPath -ChildPath "Modules" | Join-Path -ChildPath $STIGData.PsModule | Join-Path -ChildPath "$($STIGData.PsModule).psm1")
    )
    ForEach ($File in $DependentFiles) {
        If (-Not(Test-Path $File)) {
            $Pass = $false
            $FailedFiles.Add($File,"NotFound")
        }
    }

    If ($Pass -ne $true) {
        Switch ($STIGData.Classification) {
            {$_ -in @("UNCLASSIFIED")} {
                Write-Log -Path $LogPath -Message "ERROR: $($STIGData.Shortname) failed dependency file check.  STIG will not be scanned." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                ForEach ($Key in $FailedFiles.Keys) {
                    Write-Log -Path $LogPath -Message "ERROR: $($Key) - $($FailedFiles.$Key)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                }
                Write-Log -Path $LogPath -Message "Please run '.\Evaluate-STIG.ps1 -Update' to restore this module or download the 'Evaluate-STIG_$($EvaluateStigVersion).zip from one of these locations:" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (NIPR) https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/releases" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            DEFAULT {
                Write-Log -Path $LogPath -Message "WARNING: $($STIGData.Shortname) failed dependency file check.  STIG will not be scanned." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                ForEach ($Key in $FailedFiles.Keys) {
                    Write-Log -Path $LogPath -Message "WARNING: $($Key) - $($FailedFiles.$Key)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
                Write-Log -Path $LogPath -Message "Please download this CUI add-on module from:" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
            }
        }
    }

    Return $Pass
}

Function Test-XmlSignature {
    # Based on code sample from https://stackoverflow.com/questions/56986378/validate-signature-on-signed-xml

    Param (
        [xml]$checkxml,
        [switch]$Force
    )

    Try {
        # Grab signing certificate from document
        $rawCertBase64 = $checkxml.DocumentElement.Signature.KeyInfo.X509Data.X509Certificate

        If (-not $rawCertBase64) {
            $Valid = 'Unable to locate signing certificate in signed document'
        }
        Else {
            $rawCert = [convert]::FromBase64String($rawCertBase64)
            $signingCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $rawCert)

            Add-Type -AssemblyName system.security
            [System.Security.Cryptography.Xml.SignedXml]$signedXml = New-Object System.Security.Cryptography.Xml.SignedXml -ArgumentList $checkxml
            $XmlNodeList = $checkxml.GetElementsByTagName("Signature")
            If ($XmlNodeList[0]) {
                $signedXml.LoadXml([System.Xml.XmlElement] ($XmlNodeList[0]))
                $Valid = $signedXml.CheckSignature($signingCertificate, $Force)
            }
            Else {
                $Valid = 'Unable to locate signature in signed document'
            }
        }
        Return $Valid
    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Test-XmlValidation {
    # Based on code samples from https://stackoverflow.com/questions/822907/how-do-i-use-powershell-to-validate-xml-files-against-an-xsd

    Param (
        [Parameter(Mandatory = $true)]
        [String] $XmlFile,

        [Parameter(Mandatory = $true)]
        [String] $SchemaFile
    )

    Try {
        Get-ChildItem $XmlFile -ErrorAction Stop | Out-Null
        Get-ChildItem $SchemaFile -ErrorAction Stop | Out-Null

        $XmlErrors = New-Object System.Collections.Generic.List[System.Object]
        [Scriptblock] $ValidationEventHandler = {
            If ($_.Exception.LineNumber) {
                $Message = "$($_.Exception.Message) Line $($_.Exception.LineNumber), position $($_.Exception.LinePosition)."
            }
            Else {
                $Message = ($_.Exception.Message)
            }

            $NewObj = [PSCustomObject]@{
                Message = $Message
            }
            $XmlErrors.Add($NewObj)
        }

        $ReaderSettings = New-Object -TypeName System.Xml.XmlReaderSettings
        $ReaderSettings.ValidationType = [System.Xml.ValidationType]::Schema
        $ReaderSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessIdentityConstraints -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings
        If ((Split-Path $SchemaFile -Leaf) -eq "xccdf_1.2.xsd") {
            $ReaderSettings.Schemas.Add("http://checklists.nist.gov/xccdf/1.2", $SchemaFile) | Out-Null
        }
        Else {
            $ReaderSettings.Schemas.Add($null, $SchemaFile) | Out-Null
        }
        $readerSettings.add_ValidationEventHandler($ValidationEventHandler)

        Try {
            $Reader = [System.Xml.XmlReader]::Create($XmlFile, $ReaderSettings)
            While ($Reader.Read()) {
            }
        }
        Catch {
            $NewObj = [PSCustomObject]@{
                Message = ($_.Exception.Message)
            }
            $XmlErrors.Add($NewObj)
        }
        Finally {
            $Reader.Close()
        }

        If ($XmlErrors) {
            Return $XmlErrors
        }
        Else {
            Return $true
        }
    }
    Catch {
        Return $_.Exception.Message
        Exit 3
    }
}

Function Test-JsonValidation {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $JsonFile,

        [Parameter(Mandatory = $true)]
        [String] $SchemaFile
    )

    Try {
        Get-ChildItem $JsonFile -ErrorAction Stop | Out-Null
        Get-ChildItem $SchemaFile -ErrorAction Stop | Out-Null

        $Json = Get-Content -Path $JsonFile -Raw
        $Schema = Get-Content -Path $SchemaFile -Raw
        If ([Version]$PSVersionTable.PSVersion -ge [Version]"7.0") {
            Return (Test-Json -Json $Json -Schema $Schema -ErrorAction Stop)
        }
        Else {
            Return "PowerShell $($PSVersionTable.PSVersion -join ".") not supported for Json validation"
        }
    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Invoke-ScanCleanup {
    # Run scan cleanup processes
    Param (
        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent
    )

    $ES_Hive_Tasks = @("Eval-STIG_SaveHive", "Eval-STIG_LoadHive", "Eval-STIG_UnloadHive") # Potential scheduled tasks for user hive actions

    # Platform specific tasks
    Switch ($OSPlatform) {
        "Windows" {
            # Unload temporary user hive
            If (Test-Path Registry::HKU\Evaluate-STIG_UserHive) {
                [System.GC]::Collect()
                Try {
                    Start-Sleep -Seconds 5
                    Write-Log -Path $LogPath -Message "Unloading hive HKU:\Evaluate-STIG_UserHive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    $Result = Start-Process -FilePath REG -ArgumentList "UNLOAD HKU\Evaluate-STIG_UserHive" -Wait -PassThru -WindowStyle Hidden
                    If ($Result.ExitCode -ne 0) {
                        Throw
                    }
                }
                Catch {
                    # REG command failed so attempt to do as SYSTEM
                    Write-Log -Path $LogPath -Message "WARNING: Failed to unload hive. Trying as SYSTEM." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                    Try {
                        $Result = Invoke-TaskAsSYSTEM -TaskName $ES_Hive_Tasks[2] -FilePath REG -ArgumentList "UNLOAD HKU\Evaluate-STIG_UserHive" -MaxRunInMinutes 1
                        If ($Result.LastTaskResult -ne 0) {
                            Throw "Failed to unload user hive."
                        }
                    }
                    Catch {
                        Write-Log -Path $LogPath -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                }
            }
        }
        "Linux"{
            # Place holder for Linux cleanup tasks
        }
    }

    # Remove temporary files
    Try {
        $TempFiles = Get-Item -Path $WorkingDir\* -Exclude Evaluate-STIG.log,Bad_CKL -Force
        If ($TempFiles) {
            Write-Log -Path $LogPath -Message "Removing temporary files" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            ForEach ($Item in $TempFiles) {
                $null = Remove-Item -Path $Item.FullName -Recurse -Force -ErrorAction Stop
            }
        }
    }
    Catch {
        Write-Log -Path $LogPath -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    }
}

Function Write-SummaryReport {
    Param (
        [Parameter(Mandatory = $true)]
        [PsObject]$AssetData,

        [Parameter(Mandatory = $true)]
        [hashtable]$RiskScoreObject,

        [Parameter(Mandatory = $true)]
        [PsObject]$ScanResult,

        [Parameter(Mandatory = $true)]
        [String]$OutputPath,

        [Parameter(Mandatory = $false)]
        [String]$ProcessedUser,

        [Parameter(Mandatory = $false)]
        [Switch]$Detail,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux", "Cisco")]
        [String]$Platform,

        [Parameter(Mandatory = $true)]
        [String] $ScanStartDate,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Unclassified", "Classified")]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$Marking
    )

    $ResultsFile = Join-Path -Path $OutputPath -ChildPath "SummaryReport.xml"
    [Xml]$SummaryResults = New-Object System.Xml.XmlDocument

    # Create declaration
    $Dec = $SummaryResults.CreateXmlDeclaration("1.0", "UTF-8", $null)
    $SummaryResults.AppendChild($dec) | Out-Null

    # Create Root element
    $Root = $SummaryResults.CreateNode("element", "Summary", $null)

    if ($Marking) {
        $MarkingHeader = $SummaryResults.CreateComment("                                                                                          $Marking                                                                                          ")
        $null = $SummaryResults.InsertBefore($MarkingHeader, $SummaryResults.Summary)
    }

    # Build ComputerData
    $ComputerData = [ordered]@{
        Name               = $($AssetData.HostName)
        Manufacturer       = $($AssetData.Manufacturer)
        Model              = $($AssetData.Model)
        SerialNumber       = $($AssetData.SerialNumber)
        BIOSVersion        = $($AssetData.BIOSVersion)
        OSName             = $($AssetData.OSName)
        OSVersion          = $($AssetData.OSVersion)
        OSArchitecture     = $($AssetData.OSArchitecture)
        CPUArchitecture    = $($AssetData.CPUArchitecture)
        NetworkAdapters    = $($AssetData.ActiveAdapters)
        DiskDrives         = ""
        DistinguishedName  = ""
        ScannedUserProfile = $ProcessedUser
    }

    # Update ComputerData
    Switch ($Platform) {
        "Windows" {
            $W32DiskDrive = Get-CimInstance Win32_DiskDrive | Select-Object *
            $DistinguishedName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine")."Distinguished-Name"
            If (-Not($DistinguishedName)) {
                $DistinguishedName = "Not a domain member"
            }

            $ComputerData.DiskDrives = ($W32DiskDrive | Sort-Object Index | ForEach-Object { @{'Disk' = [ordered]@{
                            Index         = ($_.Index | Out-String).Trim()
                            DeviceID      = ($_.DeviceID | Out-String).Trim()
                            Size          = ("$([Math]::Round($_.Size / 1Gb, 2)) GB" | Out-String).Trim()
                            Caption       = ($_.Caption | Out-String).Trim()
                            SerialNumber  = ($_.SerialNumber | Out-String).Trim()
                            MediaType     = ($_.MediaType | Out-String).Trim()
                            InterfaceType = ($_.InterfaceType | Out-String).Trim()
                        }
                    } }
                )
            $ComputerData.DistinguishedName  = $DistinguishedName
            $ComputerData.ScannedUserProfile = $ProcessedUser
        }
        "Linux" {
            $DistinguishedName = "Not a domain member"
            Try {
                $LVM_Data = @((lvscan).Split('[\r\n]+'))
                $W32DiskDrive = $LVM_Data
            }
            Catch {
                $Disk_Data = @((lsblk -nlo "NAME,SIZE,MOUNTPOINT").Split('[\r\n]+'))
                $W32DiskDrive = $Disk_Data | ForEach-Object { @{
                        Index    = "'//$($_ | awk '{print $1}')/'"
                        DeviceID = "'//$($_ | awk '{print $3}')'"
                        Size     = "[$($_ | awk '{print $2}')]"
                    }
                }
            }

            $ComputerData.DiskDrives  = ($W32DiskDrive | Sort-Object Index | ForEach-Object { @{'Disk' = [ordered]@{
                            Index    = ($_ | cut -d '/' -f 3 | Out-String).Trim()
                            DeviceID = ($_ | cut -d "'" -f 2 | cut -d '/' -f 4 | Out-String).Trim()
                            Size     = ($_ | cut -d "]" -f 1 | cut -d "[" -f 2 | Out-String).Trim()
                        }
                    } }
            )
            $ComputerData.DistinguishedName  = $DistinguishedName
            $ComputerData.ScannedUserProfile = $ProcessedUser
        }
    }

    # Create Computer element
    $Computer = $SummaryResults.CreateNode("element", "Computer", $null)
    $ScanDate = $SummaryResults.CreateNode("element", "ScanDate", $null)
    $EvalSTIGVer = $SummaryResults.CreateNode("element", "EvalSTIGVer", $null)
    $ESScanType = $SummaryResults.CreateNode("element", "ScanType", $null)
    $ScanDate.InnerText = $($ScanStartDate)
    $Computer.AppendChild($ScanDate) | Out-Null
    $EvalSTIGVer.InnerText = $ESVersion
    $Computer.AppendChild($EvalSTIGVer) | Out-Null
    $ESScanType.InnerText = $ScanType
    $Computer.AppendChild($ESScanType) | Out-Null
    if ($Marking) {
        $ESMarking = $SummaryResults.CreateNode("element", "Marking", $null)
        $ESMarking.InnerText = $Marking
        $Computer.AppendChild($ESMarking) | Out-Null
    }
    ForEach ($Key in $ComputerData.Keys) {
        $Element = $SummaryResults.CreateNode("element", $($Key), $null)
        If ($Key -eq "NetworkAdapters") {
            ForEach ($Adapter in $ComputerData.NetworkAdapters) {
                $NetworkElement = $SummaryResults.CreateNode("element", "Adapter", $null)
                $NetworkElement.SetAttribute("InterfaceIndex", $Adapter.InterfaceIndex)

                $Caption = $SummaryResults.CreateNode("element", "Caption", $null)
                $Caption.InnerText = $Adapter.Caption
                $NetworkElement.AppendChild($Caption) | Out-Null

                $MACAddress = $SummaryResults.CreateNode("element", "MACAddress", $null)
                $MACAddress.InnerText = $Adapter.MACAddress
                $NetworkElement.AppendChild($MACAddress) | Out-Null

                $IPv4Addresses = $SummaryResults.CreateNode("element", "IPv4Addresses", $null)
                $IPv4Addresses.InnerText = $Adapter.IPv4Address -join ", "
                $NetworkElement.AppendChild($IPv4Addresses) | Out-Null

                $IPv6Addresses = $SummaryResults.CreateNode("element", "IPv6Addresses", $null)
                $IPv6Addresses.InnerText = $Adapter.IPv6Address -join ", "
                $NetworkElement.AppendChild($IPv6Addresses) | Out-Null

                $Element.AppendChild($NetworkElement) | Out-Null
            }
        }
        ElseIf ($Key -eq "DiskDrives") {
            ForEach ($Disk in $ComputerData.DiskDrives.Disk) {
                $DiskElement = $SummaryResults.CreateNode("element", "Disk", $null)
                $DiskElement.SetAttribute("Index", $Disk.Index)

                $DeviceID = $SummaryResults.CreateNode("element", "DeviceID", $null)
                $DeviceID.InnerText = $Disk.DeviceID
                $DiskElement.AppendChild($DeviceID) | Out-Null

                $Size = $SummaryResults.CreateNode("element", "Size", $null)
                $Size.InnerText = $Disk.Size
                $DiskElement.AppendChild($Size) | Out-Null

                $Caption = $SummaryResults.CreateNode("element", "Caption", $null)
                $Caption.InnerText = $Disk.Caption
                $DiskElement.AppendChild($Caption) | Out-Null

                $SerialNumber = $SummaryResults.CreateNode("element", "SerialNumber", $null)
                $SerialNumber.InnerText = $Disk.SerialNumber
                $DiskElement.AppendChild($SerialNumber) | Out-Null

                $MediaType = $SummaryResults.CreateNode("element", "MediaType", $null)
                $MediaType.InnerText = $Disk.MediaType
                $DiskElement.AppendChild($MediaType) | Out-Null

                $InterfaceType = $SummaryResults.CreateNode("element", "InterfaceType", $null)
                $InterfaceType.InnerText = $Disk.InterfaceType
                $DiskElement.AppendChild($InterfaceType) | Out-Null

                $Element.AppendChild($DiskElement) | Out-Null
            }
        }
        Else {
            $Element.InnerText = ($ComputerData.$Key)
        }

        $Computer.AppendChild($Element) | Out-Null
    }

    # Create Score element
    $ScoreElement = $SummaryResults.CreateNode("element", "Score", $null)
    ForEach ($Key in $RiskScoreObject.Keys | Sort-Object) {
        $RiskNode = $SummaryResults.CreateNode("element", $Key, $null)
        $RiskNode.InnerText = $RiskScoreObject.$Key
        $ScoreElement.AppendChild($RiskNode) | Out-Null
    }
    $Computer.AppendChild($ScoreElement) | Out-Null

    $Root.AppendChild($Computer) | Out-Null

    # Create Results element
    $Results = $SummaryResults.CreateNode("element", "Results", $null)

    ForEach ($Item in $ScanResult) {
        # Create node for result
        $ResultNode = $SummaryResults.CreateNode("element", "Result", $null)
        $ResultNode.SetAttribute("STIG", $Item.STIGInfo.STIGID) | Out-Null
        $ResultNode.SetAttribute("Version", $Item.STIGInfo.Version) | Out-Null
        $ResultNode.SetAttribute("Release", $Item.STIGInfo.Release) | Out-Null
        $ResultNode.SetAttribute("Site", $Item.TargetData.Site) | Out-Null
        $ResultNode.SetAttribute("Instance", $Item.TargetData.Instance) | Out-Null
        $ResultNode.SetAttribute("ShortName", $Item.ESData.STIGShortName) | Out-Null
        $ResultNode.SetAttribute("StartTime", $Item.ESData.StartTime) | Out-Null
        $ResultNode.SetAttribute("EvalScore", $Item.STIGInfo.EvalScore) | Out-Null

        $SeverityList = @("high", "medium", "low")
        ForEach ($Severity in $SeverityList) {
            Switch ($Severity) {
                "high" {$Cat = "CAT_I"}
                "medium" {$Cat = "CAT_II"}
                "low" {$Cat = "CAT_III"}
            }
            # Create CAT node
            $CatNode = $SummaryResults.CreateNode("element", $Cat, $null)

            # Get CAT totals
            [hashtable]$StatusTotals = @{ }
            $AllCat = $Item.VulnResults | Where-Object Severity -EQ $Severity
            $StatusTotals.NR = ($AllCat | Where-Object Status -EQ "Not_Reviewed" | Measure-Object).Count
            $StatusTotals.NF = ($AllCat | Where-Object Status -EQ "NotAFinding" | Measure-Object).Count
            $StatusTotals.O = ($AllCat | Where-Object Status -EQ "Open" | Measure-Object).Count
            $StatusTotals.NA = ($AllCat | Where-Object Status -EQ "Not_Applicable" | Measure-Object).Count
            $StatusTotals.Total = ($AllCat | Measure-Object).Count

            # Populate CAT node
            $CatNode.SetAttribute("Total", $StatusTotals.Total) | Out-Null
            $CatNode.SetAttribute("Not_Applicable", $StatusTotals.NA) | Out-Null
            $CatNode.SetAttribute("Open", $StatusTotals.O) | Out-Null
            $CatNode.SetAttribute("NotAFinding", $StatusTotals.NF) | Out-Null
            $CatNode.SetAttribute("Not_Reviewed", $StatusTotals.NR) | Out-Null

            If ($Detail) {
                # Create Vuln node and populate
                ForEach ($Vuln in $AllCat) {
                    # Initialize AFMod Variables
                    $AFStatusChange = $Vuln.STIGMan.AFMod
                    If ($Vuln.STIGMan.OldStatus) {
                        $PreAFStatus = $(Convert-Status -InputObject $Vuln.STIGMan.OldStatus -Output CKL)
                    }
                    Else {
                        $PreAFStatus = ""
                    }

                    $VulnNode = $SummaryResults.CreateNode("element", "Vuln", $null)
                    $VulnNode.SetAttribute("RuleTitle", $Vuln.RuleTitle) | Out-Null
                    $VulnNode.SetAttribute("Status", $Vuln.Status) | Out-Null
                    $VulnNode.SetAttribute("ID", $Vuln.GroupID) | Out-Null
                    Switch ($Vuln.SeverityOverride) {
                        "high" {$SeverityOverride = "CAT_I"}
                        "medium" {$SeverityOverride = "CAT_II"}
                        "low" {$SeverityOverride = "CAT_III"}
                        DEFAULT {$SeverityOverride = ""}
                    }
                    $VulnNode.SetAttribute("Override", $SeverityOverride) | Out-Null
                    $VulnNode.SetAttribute("Justification", $Vuln.Justification) | Out-Null
                    $VulnNode.SetAttribute("AFStatusChange", $AFStatusChange) | Out-Null
                    $VulnNode.SetAttribute("PreAFStatus", $PreAFStatus) | Out-Null
                    $CatNode.AppendChild($VulnNode) | Out-Null
                }
            }
            $ResultNode.AppendChild($CatNode) | Out-Null
        }
        $Results.AppendChild($ResultNode) | Out-Null
    }

        $Root.AppendChild($Results) | Out-Null
    $SummaryResults.AppendChild($Root) | Out-Null
    if ($Marking) {
        $MarkingFooter = $SummaryResults.CreateComment("                                                                                          $Marking                                                                                          ")
        $null = $SummaryResults.InsertAfter($MarkingFooter, $SummaryResults.Summary)
    }
    $SummaryResults.Save($ResultsFile)
}

Function Write-Tattoo {
    Param (
        [Parameter(Mandatory = $true)]
        [PsObject]$AssetData,

        [Parameter(Mandatory = $true)]
        [String]$LastCommand,

        [Parameter(Mandatory = $true)]
        [PsObject]$ScanObjects,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String]$STIGLog
    )

    Switch ($OSPlatform) {
        "Windows" {
            $TattooPath = "HKLM:\SOFTWARE\Evaluate-STIG"
            If (-Not(Test-Path -Path $TattooPath)) {
                $null = New-Item -Path $TattooPath -Force
            }
            Write-Log -Path $STIGLog -Message "Creating 'Version' value under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-ItemProperty -Path $TattooPath -Name Version -Value $ESVersion -PropertyType String -Force

            Write-Log -Path $STIGLog -Message "Creating 'LastCommand' value under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-ItemProperty -Path $TattooPath -Name LastCommand -Value $LastCommand -PropertyType String -Force

            Write-Log -Path $STIGLog -Message "Creating 'LastRun' value under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-ItemProperty -Path $TattooPath -Name LastRun -Value $(Get-Date -Format FileDateTime) -PropertyType String -Force

            Write-Log -Path $STIGLog -Message "Creating 'FullScan' value under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-ItemProperty -Path $TattooPath -Name FullScan -Value $([int]$AssetData.ScanSummary.FullScan) -PropertyType DWord -Force

            Write-Log -Path $STIGLog -Message "Creating 'ApplicableSTIGs' value under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-ItemProperty -Path $TattooPath -Name ApplicableSTIGs -Value ($AssetData.ScanSummary.ApplicableSTIGs).ShortName -PropertyType MultiString -Force

            $FormattedProcessed = @()
            ForEach ($STIG in $AssetData.ScanSummary.ProcessedSTIGs) {
                $FormattedProcessed += "$($STIG.Shortname) $($STIG.Flags)"
            }
            Write-Log -Path $STIGLog -Message "Creating 'ProcessedSTIGs' value under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-ItemProperty -Path $TattooPath -Name ProcessedSTIGs -Value $FormattedProcessed -PropertyType MultiString -Force

            Write-Log -Path $STIGLog -Message "Creating 'Score' values under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-Item -Path $(Join-Path $TattooPath -ChildPath Score) -Force
            ForEach ($Key in $AssetData.ScanSummary.Score.Keys) {
                Switch ($Key) {
                    "CountRetrievalSuccess" {
                        $null = New-ItemProperty -Path $(Join-Path $TattooPath -ChildPath Score) -Name $Key -Value $AssetData.ScanSummary.Score.$Key -PropertyType DWord -Force
                    }
                    default {
                        $null = New-ItemProperty -Path $(Join-Path $TattooPath -ChildPath Score) -Name $Key -Value $AssetData.ScanSummary.Score.$Key -PropertyType String -Force
                    }
                }
            }

            Write-Log -Path $STIGLog -Message "Creating 'Results' values under HKLM:\SOFTWARE\Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = New-Item -Path $(Join-Path $TattooPath -ChildPath Results) -Force
            $ScanObjects | ForEach-Object {
                $ShortNameRegKey = $(Join-Path $TattooPath -ChildPath Results | Join-Path -ChildPath $_.ESData.STIGShortName)
                $null = New-Item -Path $ShortNameRegKey -Force
                $null = New-ItemProperty -Path $ShortNameRegKey -Name Version -Value $_.STIGInfo.Version -PropertyType DWord -Force
                $null = New-ItemProperty -Path $ShortNameRegKey -Name Release -Value $_.STIGInfo.Release -PropertyType DWord -Force
                $null = New-ItemProperty -Path $ShortNameRegKey -Name ReleaseDate -Value $_.STIGInfo.ReleaseDate -PropertyType String -Force
                $null = New-ItemProperty -Path $ShortNameRegKey -Name EvalScore -Value $_.STIGInfo.EvalScore -PropertyType String -Force
                $null = New-ItemProperty -Path $ShortNameRegKey -Name CATI_OpenNRTotal -Value $_.STIGInfo.CATI_OpenNRTotal -PropertyType DWord -Force
                $null = New-ItemProperty -Path $ShortNameRegKey -Name CATII_OpenNRTotal -Value $_.STIGInfo.CATII_OpenNRTotal -PropertyType DWord -Force
                $null = New-ItemProperty -Path $ShortNameRegKey -Name CATIII_OpenNRTotal -Value $_.STIGInfo.CATIII_OpenNRTotal -PropertyType DWord -Force
            }
        }
        "Linux" {
            $TattooPath = "/etc/Evaluate-STIG"
            Write-Log -Path $STIGLog -Message "Creating 'Version' value in $TattooPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "Version: $ESVersion" | Out-File $TattooPath

            Write-Log -Path $STIGLog -Message "Creating 'LastCommand' value in $TattooPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "LastCommand: $LastCommand" | Out-File $TattooPath -Append

            Write-Log -Path $STIGLog -Message "Creating 'LastRun' value in $TattooPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "LastRun: $(Get-Date -Format FileDateTime)" | Out-File $TattooPath -Append

            Write-Log -Path $STIGLog -Message "Creating 'FullScan' value in $TattooPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "FullScan: $([int]$AssetData.ScanSummary.FullScan)" | Out-File $TattooPath -Append

            Write-Log -Path $STIGLog -Message "Creating 'ApplicableSTIGs' value in $TattooPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "ApplicableSTIGs: $($AssetData.ScanSummary.ApplicableSTIGs.ShortName -join ',')" | Out-File $TattooPath -Append

            Write-Log -Path $STIGLog -Message "Creating 'ProcessedSTIGs' value in $TattooPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "ProcessedSTIGs: $($AssetData.ScanSummary.ProcessedSTIGs.ShortName -join ',')" | Out-File $TattooPath -Append

            Write-Log -Path $STIGLog -Message "Creating 'Score' values in /etc/Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "Score:" | Out-File /etc/Evaluate-STIG -Append
            ForEach ($Key in $AssetData.ScanSummary.Score.Keys) {
                "  $($Key): $($AssetData.ScanSummary.Score.$Key)" | Out-File /etc/Evaluate-STIG -Append
            }

            Write-Log -Path $STIGLog -Message "Creating 'Results' values in /etc/Evaluate-STIG" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            "Results:" | Out-File /etc/Evaluate-STIG -Append
            $ScanObjects | ForEach-Object {
                " $($_.ESData.STIGShortName)" | Out-File /etc/Evaluate-STIG -Append
                "  Version: $($_.STIGInfo.Version)" | Out-File /etc/Evaluate-STIG -Append
                "  Release: $($_.STIGInfo.Release)" | Out-File /etc/Evaluate-STIG -Append
                "  ReleaseDate: $($_.STIGInfo.ReleaseDate)" | Out-File /etc/Evaluate-STIG -Append
                "  EvalScore: $($_.STIGInfo.EvalScore)" | Out-File /etc/Evaluate-STIG -Append
                "  CATI_OpenNRTotal: $($_.STIGInfo.CATI_OpenNRTotal)" | Out-File /etc/Evaluate-STIG -Append
                "  CATI_OpenNRTotal: $($_.STIGInfo.CATII_OpenNRTotal)" | Out-File /etc/Evaluate-STIG -Append
                "  CATI_OpenNRTotal: $($_.STIGInfo.CATIII_OpenNRTotal)" | Out-File /etc/Evaluate-STIG -Append
            }
        }
    }
}

Function Get-IniContent ($FilePath) {
    $Ini = @{ }
    Switch -Regex -File $FilePath {
        "^\[(.+)\]" {
            # Section
            $Section = $Matches[1]
            $Ini[$Section] = @{ }
            $CommentCount = 0
        }
        "^(;.*)$" {
            # Comment
            $Value = $Matches[1]
            $CommentCount = $CommentCount + 1
            $Name = "Comment" + $CommentCount
            If ($Section) {
                $Ini[$Section][$Name] = $Value
            }
            Else {
                $Ini[$Name] = $Value
            }
        }
        "(.+?)\s*=\s*(.*)" {
            # Key
            $Name, $Value = $Matches[1..2]
            If ($Section) {
                $Ini[$Section][$Name] = $Value
            }
            Else {
                $Ini[$Name] = $Value
            }
        }
    }
    Return $Ini
}

Function Get-TextHash {
    Param (
        [Parameter(Mandatory = $false)]
        [string]$Text,

        [Parameter(Mandatory = $false)]
        [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "SHA1"
    )

    Try {
        $HashStream = [IO.MemoryStream]::new([byte[]][char[]]$($Text -replace '[^\x00-\x7F]', ''))
        $HashString = ((Get-FileHash -InputStream $HashStream -Algorithm $Algorithm).Hash).ToUpper()
    }
    Finally {
        If ($HashStream) {
            $HashStream.Dispose()
        }
    }
    Return $HashString
}

Function Get-W32TMConfiguration {
    Try {
        $Output = w32tm /query /configuration
        If ($Output -match "Error") {
            Throw $Output
        }

        $Sections = [ordered]@{}
        $CurrentSection = $null
        ForEach ($Line in $Output) {
            If ($Line.Trim() -ne '') {
                If ($Line -match '^\[(.+)\]$') {
                    $CurrentSection = $Matches[1]
                    $Sections[$CurrentSection] = [ordered]@{}
                }
                Else {
                    Switch ($CurrentSection) {
                        "Configuration" {
                            $Key, $Value = $Line -split ':', 2
                            $Key = $Key.Trim()
                            $Value = $Value.Trim()
                            $Sections[$CurrentSection][$Key] = $Value
                        }
                        "TimeProviders" {
                            If ($line -inotmatch '\:' -and $Line -match '(^[a-z0-9]+\s{1,}.+)') {
                                $SubSection = $Matches[1]
                                $Sections[$CurrentSection][$SubSection] = [ordered]@{}
                            }
                            Else {
                                $Key, $Value = $Line -split ':', 2
                                $Key = $Key.Trim()
                                $Value = $Value.Trim()
                                $Sections[$CurrentSection][$SubSection][$Key] = $Value
                            }
                        }
                    }
                }
            }
        }

        Return $Sections
    }
    Catch {
        Throw $_.Exception.Message
    }
}

function Get-DomainRoleStatus {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String[]]$ExpectedRole
    )
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem#domainrole

    # Hashtable translation map
    $TranslationMap = @{
        '0' = 'Standalone Workstation'
        '1' = 'Member Workstation'
        '2' = 'Standalone Server'
        '3' = 'Member Server'
        '4' = 'Backup Domain Controller'
        '5' = 'Primary Domain Controller'
    }

    $ReturnObj = [PSCustomObject]@{
        DomainRole       = $null
        RoleFriendlyName = $null
        DomainMember     = $null
        Error            = $null
    }

    try {
        if ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption -match "multi-session") {
            # If OS is "Windows 10/11 'multi-session'"" force domain role to '1' (Member Workstation).  This is typically Azure workstations in a VDI environment.
            $DomainRole = [string]"1"
        }
        else {
            # Get the DomainRole from the Win32_ComputerSystem
            $DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole.ToString()
        }
        # Translate the DomainRole value to friendly text
        if ($TranslationMap.ContainsKey($DomainRole)) {
            $FriendlyText = $TranslationMap[$DomainRole]
        }
        else {
            $FriendlyText = 'Unknown Role'
        }

        if ($ExpectedRole) {
            if (($DomainRole -in $ExpectedRole) -or ($FriendlyText -in $ExpectedRole)) {
                $BoolMatchExpected = $true
            }
            else {
                $BoolMatchExpected = $false
            }
            $ReturnObj | Add-Member -MemberType NoteProperty -Name 'BoolMatchExpected' -Value $BoolMatchExpected
        }

        $ReturnObj.DomainRole = $DomainRole
        $ReturnObj.RoleFriendlyName = $FriendlyText
        switch ($DomainRole) {
            {($_ -in @(1, 3, 4, 5))} {
                $ReturnObj.DomainMember = $true
            }
            default {
                $ReturnObj.DomainMember = $false
            }
        }
    }
    catch {
        $ReturnObj.Error = $_
    }

    return $ReturnObj
}

Function Get-WindowsFeatureState {
    Try {
        $FeatureState = [System.Collections.Generic.List[System.Object]]::new()

        # Azure VMs showing to not always report expected DomainRole WMI value so test both DomainRole and Get-WindowsFeature existance as insurance.  Issues #2042 and #2427.
        Try {
            if (((Get-DomainRoleStatus).RoleFriendlyName -match "(Server|Domain Controller)") -and (Get-CimInstance Win32_OperatingSystem).Caption -notmatch "multi-session" -and (Get-Command -Name Get-WindowsFeature -ErrorAction Stop)) {
                $OSType = "Server"
            }
            Else {
                $OSType = "Workstation"
            }
        }
        Catch {
            $OSType = "Workstation"
        }

        Switch ($OSType) {
            "Server" {
                $FeatureData = Get-WindowsFeature -ErrorAction Stop
                ForEach ($Item in $FeatureData) {
                    $Enabled = $false
                    If ($Item.InstallState -eq "Installed") {
                        $Enabled = $true
                    }

                    $NewObj = [PSCustomObject]@{
                        DisplayName = $Item.DisplayName
                        Name        = $Item.Name
                        Enabled     = $Enabled
                    }
                    $FeatureState.Add($NewObj)
                }
            }
            "Workstation" {
                $FeatureData = Get-CimInstance -ClassName Win32_OptionalFeature -ErrorAction Stop
                ForEach ($Item in $FeatureData) {
                    $Enabled = $false
                    If ($Item.InstallState -eq 1) {
                        $Enabled = $true
                    }

                    $NewObj = [PSCustomObject]@{
                        DisplayName = $Item.Caption
                        Name        = $Item.Name
                        Enabled     = $Enabled
                    }
                    $FeatureState.Add($NewObj)
                }
            }
        }
    }
    Catch {
        Throw $_
    }

    Return $FeatureState
}

Function Get-UsersToEval {
    <#
    .DESCRIPTION
        Returns either a single user profile or all user profiles in order of preference.
        Profiles that have a NTUSER.POL modified within the last 14 days are preferred as best
        representation for current STIG user settings.

        NOTE:  Previous version referenced LastUseTime from Win32_UserProfile.
        With Windows 10 and greater, LastUseTime is updated every time the profile
        is queried from Win32_UserProfile thus not providing a true last use of the profile.
    #>

    # Changed to use $oProfile instead of $Profile due to warning from PSScriptAnalyzer. Ken Row, 9/29/25

    [cmdletbinding()]
    Param (
        [Switch]$ProvideSingleUser
    )

    $ProfileList = New-Object System.Collections.Generic.List[System.Object]
    $RegexSID = '^S-1-((5-21-\d*-\d*-\d*-\d*)|(5-32-\d*)|(12-\d*))$'
    $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $UserProfiles = Get-ChildItem $ProfileListPath | Where-Object PSChildName -Match $RegexSID

    ForEach ($oProfile in $UserProfiles) {
        Remove-Variable -Force LTH, LTL, LocalPath -ErrorAction SilentlyContinue
        $IsServiceAccount = $false

        # Get username
        Try {
            $Username = (New-Object System.Security.Principal.SecurityIdentifier($oProfile.PSChildName)).Translate([System.Security.Principal.NTAccount]).value
            If ($Username -match "(\s|')") {
                $Username = [Char]34 + $Username + [Char]34
            }
        }
        Catch {
            $Username = "[UNKNOWN]"
        }

        # Username ending in "$" is typically a gMSA
        If ($Username -match '\$$') {
            $IsServiceAccount = $true
        }

        # Get profile paths
        $LocalPath = (Get-ItemProperty -Path $oProfile.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        $CentralPath = (Get-ItemProperty -Path $oProfile.PSPath -Name CentralProfile -ErrorAction SilentlyContinue).CentralProfile

        # Verify NTUSER.DAT or NTUSER.MAN exists.  If not, ignore profile as there are no user registry settings to import.
        If ((Test-Path -Path "$($LocalPath)\ntuser.dat" -ErrorAction SilentlyContinue) -or (Test-Path -Path "$($CentralPath)\ntuser.man")) {
            If (Test-Path -Path "$($LocalPath)\ntuser.dat" -ErrorAction SilentlyContinue) {
                $ProfileType = "Local"

                # Get NTUSER.POL
                $NTUserPol = @()
                If (Test-Path "$($env:ProgramData)\Microsoft\GroupPolicy\Users\$($oProfile.PSChildName)\ntuser.pol") {
                    $NTUserPol += Get-ChildItem -Path "$($env:ProgramData)\Microsoft\GroupPolicy\Users\$($oProfile.PSChildName)\ntuser.pol" -Force
                }
                If (Test-Path "$($LocalPath)\ntuser.pol") {
                    $NTUserPol += Get-ChildItem -Path "$($LocalPath)\ntuser.pol" -Force
                }
                If (($NTUserPol | Measure-Object).Count -gt 0) {
                    $LastPolicyUpdate = ($NtuserPol | Sort-Object LastWriteTime -Descending)[0].LastWriteTime
                }
                Else {
                    $LastPolicyUpdate = Get-Date 01/01/1900
                }

                # Determine if preferred
                If (($UserName -ne "[UNKNOWN]") -and ($UserName.Split("\")[0] -ne $(Get-FullHostName).FullName -and ($LastPolicyUpdate -ne (Get-Date 01/01/1900)) -and (New-TimeSpan -Start $LastPolicyUpdate -End (Get-Date)).Days -le 14) -and -Not($IsServiceAccount)) {
                    $Preferred = $true
                }
                Else {
                    $Preferred = $false
                }

                # Set NTUSER.DAT path and get LastWriteTime
                $NTUserDatPath = "$($LocalPath)\ntuser.dat"
                $NTUserDatUpdate = Get-Date ((Get-ChildItem -Path $NTUserDatPath -Force).LastWriteTime)
            }
            ElseIf (Test-Path -Path "$($CentralPath)\ntuser.man") {
                $ProfileType = "Mandatory"

                $LastPolicyUpdate = Get-Date 01/01/1900
                $Preferred = $false

                # Set NTUSER.MAN path and get LastWriteTime
                $NTUserDatPath = "$($CentralPath)\ntuser.man"
                $NTUserDatUpdate = Get-Date ((Get-ChildItem -Path $NTUserDatPath -Force).LastWriteTime)
            }

            # Get profile last load time
            $LTH = '{0:X8}' -f (Get-ItemProperty -Path $oProfile.PSPath -Name LocalProfileLoadTimeHigh -ErrorAction SilentlyContinue).LocalProfileLoadTimeHigh
            $LTL = '{0:X8}' -f (Get-ItemProperty -Path $oProfile.PSPath -Name LocalProfileLoadTimeLow -ErrorAction SilentlyContinue).LocalProfileLoadTimeLow
            If ($LTH -and $LTL) {
                $ProfileLoadTime = [datetime]::FromFileTime("0x$LTH$LTL")
            }
            Else {
                $ProfileLoadTime = Get-Date 01/01/1900
            }

            # Get the SID
            If (-Not(Get-ItemProperty -Path $(Join-Path $ProfileListPath -ChildPath $oProfile.PsChildName) -Name 'Sid' -ErrorAction SilentlyContinue)) {
                $SID = "Unable to locate"
            }
            Else {
                $SID = (New-Object System.Security.Principal.SecurityIdentifier((Get-Item $(Join-Path $ProfileListPath -ChildPath $oProfile.PsChildName)).GetValue('Sid'), 0)).Value
            }

            $NewObj = [PSCustomObject]@{
                ProfileType      = $ProfileType
                Username         = $Username
                IsServiceAccount = $IsServiceAccount
                LastPolicyUpdate = $LastPolicyUpdate
                SID              = $SID
                LocalPath        = $LocalPath
                ProfileRegKey    = $($oProfile.PSChildName)
                ProfileLoadTime  = $ProfileLoadTime
                NTUserDatPath    = $NTUserDatPath
                NTUserDatUpdate  = $NTUserDatUpdate
                Preferred        = $Preferred
            }
            $ProfileList.Add($NewObj)
        }
    }

    # Sort results
    # Order: Preferred (True first), LastPolicyUpdate (newest first), ProfileLoadTime (newest first/most recent load first),
    # and ensure service accounts (IsServiceAccount) are last.
    # Create a calculated property to ensure service accounts sort after normal accounts.
    $ProfileList = $ProfileList | Sort-Object @{Expression = {$_.IsServiceAccount}; Descending = $false}, @{Expression = {$_.Preferred}; Ascending = $false}, @{Expression = {$_.LastPolicyUpdate}; Ascending = $false}, @{Expression = {$_.ProfileLoadTime}; Ascending = $false}

    If ($ProvideSingleUser -and $ProfileList) {
        Return $ProfileList[0]
    }
    Else {
        Return $ProfileList
    }
}

Function Get-GroupMembership ($Group) {
    $GroupMembers = New-Object System.Collections.Generic.List[System.Object]

    $Computer = [ADSI]"WinNT://$env:COMPUTERNAME,Computer"
    $Object = $Computer.psbase.Children | Where-Object { $_.psbase.schemaClassName -eq "group" -and $_.Name -eq $Group }
    ForEach ($Item In $Object) {
        $Members = @($Item.psbase.Invoke("Members"))
        ForEach ($Member In $Members) {
            $ObjectSID = $Member.GetType().InvokeMember("objectSid", 'GetProperty', $Null, $Member, $Null)
            $Name = ($Member.GetType().InvokeMember("AdsPath", 'GetProperty', $Null, $Member, $Null))
            If ($Name -match $env:COMPUTERNAME) {
                $Name = "$env:COMPUTERNAME" + (($Name -split $env:COMPUTERNAME)[1]).Replace("/", "\")
            }
            Else {
                $Name = ($Name).Replace("WinNT://", "").Replace("/", "\")
            }
            $NewObj = [PSCustomObject]@{
                Name        = $Name
                objectClass = $Member.GetType().InvokeMember("Class", 'GetProperty', $Null, $Member, $Null)
                objectSID   = (New-Object System.Security.Principal.SecurityIdentifier($objectSID, 0))
            }
            $GroupMembers.Add($NewObj)
        }
    }

    Return $GroupMembers
}

Function Search-AD {
    Param (
        [String[]]$Filter,
        [String[]]$Properties,
        [String]$SearchRoot
    )

    If ($SearchRoot) {
        $Root = [ADSI]$SearchRoot
    }
    Else {
        $Root = [ADSI]''
    }

    If ($Filter) {
        $LDAP = "(&({0}))" -f ($Filter -join ')(')
    }
    Else {
        $LDAP = "(name=*)"
    }

    If (-Not($Properties)) {
        $Properties = 'Name', 'ADSPath'
    }

    (New-Object ADSISearcher -ArgumentList @($Root, $LDAP, $Properties) -Property @{PageSize = 1000 }).FindAll() | ForEach-Object {
        $ObjectProps = @{ }
        $_.Properties.GetEnumerator() | ForEach-Object {
            $ObjectProps.Add($_.Name, (-join $_.Value))
        }
        New-Object PSObject -Property $ObjectProps | Select-Object $Properties
    }
}

Function Get-MembersOfADGroup {
    # Function simulate Get-ADGroupMember but not fail on ForeignSecurityPrincipals
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Identity,

        [Parameter(Mandatory = $false)]
        [Switch]$Recursive
    )

    Try {
        $ADObjectPropertiesList = @(
            'Name'
            'DistinguishedName'
            'objectClass'
            'objectGUID'
            'objectSID'
        )
        $Result = [System.Collections.Generic.List[System.Object]]::new()

        $ADGroupInfo = Get-ADGroup -Identity $Identity -Properties Members -ErrorAction Stop
        $GroupPrimaryGroupID = ($ADGroupInfo.Sid -split '-')[-1]

        If ($Recursive) {
            $ldapFilter = '(|(memberof:1.2.840.113556.1.4.1941:={0})(primaryGroupID={1}))' -f $ADGroupInfo.DistinguishedName, $GroupPrimaryGroupID
            $ADGroupMembership = Get-ADObject -LDAPFilter $ldapFilter -Properties $ADObjectPropertiesList -ErrorAction Stop | Where-Object objectClass -NE 'group' | Select-Object -Property $ADObjectPropertiesList
        }
        Else {
            $ldapFilter = '(|(memberof={0})(primaryGroupID={1}))' -f $ADGroupInfo.DistinguishedName, $GroupPrimaryGroupID
            $ADGroupMembership = Get-ADObject -LDAPFilter $ldapFilter -Properties $ADObjectPropertiesList -ErrorAction Stop | Select-Object -Property $ADObjectPropertiesList
        }

        Foreach ($Obj in $ADGroupMembership) {
            Try {
                $NameFromSID = ([System.Security.Principal.SecurityIdentifier]$Obj.objectSID).Translate([System.Security.Principal.NTAccount]).Value
            }
            Catch {
                $NameFromSID = "[UNABLE TO RESOLVE]"
            }
            $NewObj = [PSCustomObject]@{
                Name              = $NameFromSID
                DistinguishedName = $Obj.DistinguishedName
                objectSID         = $Obj.objectSID
                objectClass       = $Obj.objectClass
                objectGUID        = $Obj.objectGUID
            }
            [void]$Result.Add($NewObj)
        }

        Return $Result

    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Get-ADDomainControllerCertificate {
    # Derived from: https://github.com/roggenk/PowerShell/tree/master/LDAPS
    <#
        .SYNOPSIS
            Retrieves the LDAPS certificate properties.
        .PARAMETER ComputerName
            Specifies the Active Directory domain controller.
        .PARAMETER Domain
            Specifies the Active Directory DNS name.
        .PARAMETER Port
            LDAPS port for domain controller: 636 (default)
            LDAPS port for global catalog: 3269
        .DESCRIPTION
            The cmdlet 'Get-ADDomainControllerCertificate' retrieves the LDAP over TSL/SSL certificate properties.
        .EXAMPLE
            Get-ADDomainControllerCertificate -ComputerName DC01
        .EXAMPLE
            Get-ADDomainControllerCertificate -ComputerName DC01,DC02 | Select ComputerName,Port,Subject,Thumbprint
        .EXAMPLE
            Get-ADDomainControllerCertificate DC01,DC02
        .EXAMPLE
            Get-ADDomainControllerCertificate DC01 -Port 3269
        .EXAMPLE
            Get-ADDomainControllerCertificate -Domain domain.local
        .EXAMPLE
            Get-ADDomainControllerCertificate -Domain domain.local | Select-Object ComputerName,Port,Subject,Thumbprint
        .EXAMPLE
            Get-ADDomainControllerCertificate -Domain domain.local -Port 3269 | Select-Object ComputerName,Port,Subject,Thumbprint
    #>
    [Cmdletbinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Mandatory, Position = 0)]
        [Alias('CN')]
        [String[]]$ComputerName,

        [Parameter(ParameterSetName = 'DomainName', Mandatory, Position = 0)]
        [String]$Domain,

        [String]$Port = "636"
    )

    $DomainDCs = @()
    If ($ComputerName) {
        ForEach ($Computer in $ComputerName) {
            $DomainDCs += (Get-ADDomainController -Identity $Computer).HostName
        }
    }

    If ($Domain) {
        $DomainDCs += (Get-ADDomainController -DomainName $Domain -Discover).HostName
    }

    $KDCCert = @()
    ForEach ($DomainDC in $DomainDCs) {
        Try {
            $Connection = New-Object System.Net.Sockets.TcpClient($DomainDC, $Port)
            $TLSStream = New-Object System.Net.Security.SslStream($Connection.GetStream())
            # Try to validate certificate, break out if we don't
            Try {
                $TLSStream.AuthenticateAsClient($DomainDC)
            }
            Catch {
                $Connection.Close
                Break
            }
            #Grab the Cert and it's Basic Properties
            $KDCCert += New-Object system.security.cryptography.x509certificates.x509certificate2($TLSStream.get_remotecertificate())
            $Connection.Close()
        }
        Catch {
            If ($Connection) {
                $Connection.Close()
            }
            Throw $_.Exception.Message
        }
    }
    Return $KDCCert
}

function Get-UpnSuffixLevels {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$UpnList
    )

    $suffixes = @()

    foreach ($Upn in $UpnList) {
        # Extract domain part from UPN
        $domain = $Upn.Split('@')[-1].Trim('.')

        # Split domain into parts
        $parts = $domain -split '\.' | Where-Object { $_ -ne '' }

        if ($parts.Count -le 1) {
            $suffixes += @($domain)
            continue
        }

        for ($i = 0; $i -lt $parts.Count; $i++) {
            $suffixes += ($parts[$i..($parts.Count - 1)] -join '.')
        }
    }

    return $suffixes | Select-Object -Unique
}

Function Get-AssetData {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Windows", "Linux", "Cisco", "VMWare")]
        [String]$OSPlatform,

        # Cisco-specific
        [Parameter()]
        [psobject]$ShowRunningConfig,

        [Parameter()]
        [psobject]$DeviceInfo,

        # VMWare-Specific
        [Parameter()]
        [PSObject]$VMWareInfo
    )

    Try {
        Switch ($OSPlatform) {
            "Windows" {
                # Collect WMI class data
                $ComputerSystem = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_ComputerSystem
                $SerialNumber = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_SystemEnclosure
                $BIOSVersion = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_BIOS
                $OperatingSystem = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_OperatingSystem
                $Processor = (Get-CimInstance -Namespace root\cimv2 -ClassName Win32_Processor)[0]
                $NetAdapters = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

                # Determine CPU architecture from Win32_Processor
                # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor
                Switch ($Processor.Architecture) {
                    "0" {
                        $CPUArchitecture = "x86"
                    }
                    "1" {
                        $CPUArchitecture = "MIPS"
                    }
                    "2" {
                        $CPUArchitecture = "Alpha"
                    }
                    "3" {
                        $CPUArchitecture = "PowerPC"
                    }
                    "5" {
                        $CPUArchitecture = "ARM"
                    }
                    "6" {
                        $CPUArchitecture = "ia64"
                    }
                    "9" {
                        $CPUArchitecture = "x64"
                    }
                    "12" {
                        $CPUArchitecture = "ARM64"
                    }
                    DEFAULT {
                        $CPUArchitecture = "Other"
                    }
                }

                # Create the variables to return
                $Manufacturer = ($ComputerSystem).Manufacturer
                $Model = ($ComputerSystem).Model
                $SerialNumber = ($SerialNumber).SerialNumber
                $BIOSVersion = ($BIOSVersion).SMBIOSBIOSVersion
                $OSName = ($OperatingSystem).Caption
                $OSVersion = ($OperatingSystem).Version
                $OSArchitecture = ($OperatingSystem).OSArchitecture
                $CPUName = ($Processor).Name
                $CPUArchitecture = $CPUArchitecture
                $MachineName = ($(Get-FullHostName).FullName).ToUpper()
                $FQDN = ("$(($ComputerSystem).DNSHostName).$(($ComputerSystem).Domain)").ToLower()
                $Role = (Get-DomainRoleStatus).RoleFriendlyName

                # Get active network adapter information
                $NetInterfaces = New-Object System.Collections.Generic.List[System.Object]
                ForEach ($Adapter in $NetAdapters) {
                    $NewObj = [PSCustomObject]@{
                        InterfaceIndex = $Adapter.InterfaceIndex
                        Caption        = $Adapter.Caption
                        MACAddress     = $Adapter.MACAddress
                        IPv4Address    = $Adapter.IPAddress -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                        IPv6Address    = $Adapter.IPAddress -match ":"
                    }
                    $NetInterfaces.Add($NewObj)
                }
            }
            "Linux" {
                # Collect inventory data
                $DMIDecode = dmidecode
                $OperatingSystem = Get-Content /etc/os-release
                $Processor = lscpu
                $NetAdapters = @(ip addr | awk '/state UP/ {print $2}')
                if ($NetAdapters){
                    $NetAdapters = $NetAdapters.Replace(":", "")
                }

                # Create the variables to return
                if ($DMIDecode | grep -A5 '^System Information'){
                    $Manufacturer = ($DMIDecode | grep -A5 '^System Information' | grep Manufacturer).Replace("Manufacturer:", "").Trim()
                    $Model = ($DMIDecode | grep -A5 '^System Information' | grep Product).Replace("Product Name:", "").Trim()
                    $SerialNumber = ($DMIDecode | grep -A5 '^System Information' | grep Serial).Replace("Serial Number:", "").Trim()
                    $BIOSVersion = ($DMIDecode | grep -A3 "^BIOS" | grep Version).Replace("Version:", "").Trim()
                }
                else{  #handle situations where dmidecode is not available (RPi, Edison Boards, etc)
                    $Manufacturer = "undetermined"
                    $Model = "undetermined"
                    $SerialNumber = "undetermined"
                    $BIOSVersion = "undetermined"
                }
                $OSName = ($OperatingSystem | grep "^PRETTY").Replace("PRETTY_NAME=", "").Replace('"', "").Trim()
                $OSVersion = ($OperatingSystem | grep "^VERSION_ID").Replace("VERSION_ID=", "").Replace('"', "").Trim()
                $OSArchitecture = arch
                $CPUName = ($Processor | grep "^Model name")
                if ($CPUName){
                    $CPUName = $CPUName.Replace("Model name:", "").Trim()
                }
                else{
                    $CPUName = "undetermined"
                }
                $CPUArchitecture = ($Processor | grep "^Architecture").Replace("Architecture:", "").Trim()
                $MachineName = ($(Get-FullHostName).FullName).ToUpper()
                $FQDN = (hostname --fqdn)
                if ($FQDN){
                    $FQDN = $FQDN.ToLower()
                }
                else{
                    $FQDN = (hostname).toLower()
                }

                # Get system's role
                $Release = ""
                $Role = ""
                If (((Get-Content /etc/os-release) -like '*VERSION_ID="8.*') -or ((Get-Content /etc/os-release) -like '*VERSION_ID="9.*')) {
                    $Release = "Workstation"
                }
                Else {
                    $Release = (Get-Content /etc/os-release | egrep -i "VARIANT=|^ID=").Replace("VARIANT=", "").Replace('"', "").Replace("ID=", "").Replace("rhel", "") | Where-Object { $_ -ne "" }
                }
                Switch ($Release) {
                    {($_ -in @("Workstation", "ubuntu"))} {
                        $Role = "Workstation"
                    }
                    "Server" {
                        $Role = "Member Server"
                    }
                    DEFAULT {
                        $Role = "None"
                    }
                }

                # Get active network adapter information
                $lshwNetwork = lshw -C network
                $NetInterfaces = New-Object System.Collections.Generic.List[System.Object]
                ForEach ($Adapter in $NetAdapters) {
                    $Description = @($lshwNetwork | grep -B10 $Adapter | grep "description")
                    If ($Description) {
                        $Caption = (($Description[-1] | grep "description").Replace("description:", "").Trim())
                    }
                    Else {
                        $Caption = ""
                    }
                    if (Test-Path /sys/class/net/$Adapter/ifindex){
                        $NewObj = [PSCustomObject]@{
                            InterfaceIndex = (Get-Content /sys/class/net/$Adapter/ifindex)
                            Caption        = $Caption
                            MACAddress     = (ip addr show dev $Adapter | grep "link/ether" | cut -d ' ' -f 6)
                            IPv4Address    = (ip -4 addr show dev $Adapter | grep "inet " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                            IPv6Address    = (ip -6 addr show dev $Adapter | grep "inet6 " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                        }
                        $NetInterfaces.Add($NewObj)
                    }
                }
            }
            "Cisco" {
                If (-Not($DeviceInfo -and $ShowRunningConfig)) {
                    Throw "-DeviceInfo and -ShowRunningConfig required."
                }
                Else {
                    # Create the variables to return
                    $Manufacturer = "Cisco"
                    $Model = ($DeviceInfo).Model
                    $SerialNumber = ($DeviceInfo).SerialNumber
                    $BIOSVersion = ""
                    $OSName = ($DeviceInfo).CiscoOS
                    $OSVersion = ($DeviceInfo).CiscoOSVer
                    $OSArchitecture = ""
                    $CPUName = ""
                    $CPUArchitecture = ""
                    $MachineName = ($DeviceInfo).Hostname
                    $Role = "None"

                    If ($DeviceInfo.Hostname -and $DeviceInfo.DomainName) {
                        $FQDN = "$($DeviceInfo.Hostname).$($DeviceInfo.DomainName)"
                    }
                    Else {
                        $FQDN = ""
                    }

                    # Get network information
                    $NetInterfaces = New-Object System.Collections.Generic.List[System.Object]
                    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
                    ForEach ($Interface in $Interfaces) {
                        $IPv4 = (((Get-Section $ShowRunningConfig $Interface | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
                        If ($IPv4 -match "\d+\.\d+\.\d+\.\d+") {
                            $NewObj = [PSCustomObject]@{
                                InterfaceIndex = ""
                                Caption        = ($Interface -Replace "^interface", "").Trim()
                                MACAddress     = $DeviceInfo.MACAddress
                                IPv4Address    = $IPv4
                                IPv6Address    = ""
                            }
                            $NetInterfaces.Add($NewObj)
                        }
                    }
                }
            }
            "VMWare_VM" {

            }
            "VMWare_ESXi" {

            }
        }

        $AssetData = [ordered]@{
            Manufacturer    = $Manufacturer
            Model           = $Model
            SerialNumber    = $SerialNumber
            BIOSVersion     = $BIOSVersion
            OSName          = $OSName
            OSVersion       = $OSVersion
            OSArchitecture  = $OSArchitecture
            CPUName         = $CPUName
            CPUArchitecture = $CPUArchitecture
            HostName        = $MachineName
            FQDN            = $FQDN
            Role            = $Role
            ActiveAdapters  = $NetInterfaces | Sort-Object InterfaceIndex
        }

        Return $AssetData
    }
    Catch {
        Throw $_.Exception.Message
    }
}

Function Get-RiskScore {
    # Scoring based on JFHQ-DODIN CCRI Scoring Methodology|CORA Grading

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [String]$ES_Path,

        [Parameter(Mandatory)]
        [psobject]$ApplicableSTIGsCount,

        [Parameter(Mandatory)]
        [psobject]$ScanObjects
    )

    $STIGList = [XML](Get-Content $(Join-Path -Path $ES_Path -ChildPath 'xml' | Join-Path -ChildPath 'STIGList.xml'))

    # Initialize variables
    [int32]$CountRetrievalSuccess = 1
    [int32]$CATI_OpenNRTotal      = 0
    [int32]$CATI_PossibleTotal    = 0
    [int32]$CATI_PctOpenNR        = 0
    [int32]$CATII_OpenNRTotal     = 0
    [int32]$CATII_PossibleTotal   = 0
    [int32]$CATII_PctOpenNR       = 0
    [int32]$CATIII_OpenNRTotal    = 0
    [int32]$CATIII_PossibleTotal  = 0
    [int32]$CATIII_PctOpenNR      = 0
    [int32]$WeightedAvg           = 0

    ForEach ($STIG in $ApplicableSTIGsCount) {
        If (-Not($STIG.DetectionSuccess)) {
            [int32]$CountRetrievalSuccess = 0
        }
        $STIGListNode = $STIGList.List.STIG | Where-Object ShortName -eq $STIG.ShortName

        [int32]$CATI_Possible   = 0
        [int32]$CATII_Possible  = 0
        [int32]$CATIII_Possible = 0

        $CATI_Possible = [int32]$STIGListNode.Counts.CATI * [int32]$STIG.Total
        $CATII_Possible = [int32]$STIGListNode.Counts.CATII * [int32]$STIG.Total
        $CATIII_Possible = [int32]$STIGListNode.Counts.CATIII * [int32]$STIG.Total

        # Add to PossibleTotatl counts
        $CATI_PossibleTotal = $CATI_PossibleTotal + $CATI_Possible
        $CATII_PossibleTotal = $CATII_PossibleTotal + $CATII_Possible
        $CATIII_PossibleTotal = $CATIII_PossibleTotal + $CATIII_Possible
    }

    # Start OpenNRTotal to equal possible.  Will reduce for each where the Status is not NR or O.
    $CATI_OpenNRTotal = $CATI_PossibleTotal
    $CATII_OpenNRTotal = $CATII_PossibleTotal
    $CATIII_OpenNRTotal = $CATIII_PossibleTotal

    ForEach ($STIG in $ApplicableSTIGsCount.Shortname) {
        # Get Open|NR counts
        If ($STIG -in $ScanObjects.ESData.STIGShortName) {
            ForEach ($Vuln in ($ScanObjects | Where-Object {$_.ESData.STIGShortName -eq $STIG}).VulnResults) {
                Switch (($Vuln).Status) {
                    {$_ -notin @("Not_Reviewed", "Open")} {
                        Switch ($Vuln.Severity) {
                            "high" {
                                If ($CATI_OpenNRTotal -gt 0) {
                                    $CATI_OpenNRTotal--
                                }
                            }
                            "medium" {
                                If ($CATII_OpenNRTotal -gt 0) {
                                    $CATII_OpenNRTotal--
                                }
                            }
                            "low" {
                                If ($CATIII_OpenNRTotal -gt 0) {
                                    $CATIII_OpenNRTotal--
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    If ($CATI_OpenNRTotal -gt 0) {
        # Get percentage of Open/NR CAT Is
        $CATI_PctOpenNR = [System.Math]::Round(($CATI_OpenNRTotal / $CATI_PossibleTotal * 100), 2)
    }
    If ($CATII_OpenNRTotal -gt 0) {
        # Get percentage of Open/NR CAT IIs
        $CATII_PctOpenNR = [System.Math]::Round(($CATII_OpenNRTotal / $CATII_PossibleTotal * 100), 2)
    }
    If ($CATIII_OpenNRTotal -gt 0) {
        # Get percentage of Open/NR CAT IIIs
        $CATIII_PctOpenNR = [System.Math]::Round(($CATIII_OpenNRTotal / $CATIII_PossibleTotal * 100), 2)
    }

    # Calculate Weighted Average % (CORA Grading)
    [int32]$Weights = 0

    if ($CATI_PossibleTotal -gt 0){
        $Weights = $Weights + 10
    }
    if ($CATII_PossibleTotal -gt 0){
        $Weights = $Weights + 4
    }
    if ($CATIII_PossibleTotal -gt 0){
        $Weights = $Weights + 1
    }

    [int32]$CATSum = (($CATI_PctOpenNR * 10) + ($CATII_PctOpenNR * 4) + ($CATIII_PctOpenNR))

    $WeightedAvg = [System.Math]::Round($CATSum/$Weights, 2)

    # Determine Risk Value
    Switch ($WeightedAvg) {
        {$_ -ge 20} {
            $RiskRating = "Very High"
        }
        {$_ -lt 20 -and $_ -ge 10} {
            $RiskRating = "High"
        }
        {$_ -lt 10} {
            # CAT II/III percentages from CCRI Scoring Methodology
            $CATIIPct  = 5
            $CATIIIPct = 5
            if (($CATI_OpenNRTotal -eq 0) -and ($CATII_PctOpenNR -lt $CATIIPct) -and ($CATIII_OpenNRTotal -lt $CATIIIPct)) {
                $RiskRating = "Low"
            }
            else {
                $RiskRating = "Moderate"
            }
        }
        {$_ -eq 0} {
            $RiskRating = "Very Low"
        }
    }

    $Result = [ordered]@{
        CountRetrievalSuccess = $CountRetrievalSuccess
        RiskRating            = $RiskRating
        WeightedAvg           = $WeightedAvg
        CATI_OpenNRTotal      = $CATI_OpenNRTotal
        CATI_PossibleTotal    = $CATI_PossibleTotal
        CATII_OpenNRTotal     = $CATII_OpenNRTotal
        CATII_PossibleTotal   = $CATII_PossibleTotal
        CATIII_OpenNRTotal    = $CATIII_OpenNRTotal
        CATIII_PossibleTotal  = $CATIII_PossibleTotal
    }

    Return $Result
}

Function Invoke-STIGScan {
    param
    (
        [Parameter(Mandatory)]
        [string]$StigXmlPath,

        [Parameter(Mandatory)]
        [int]$VulnTimeout,

        [Parameter()]
        [Array]$SelectVuln,

        [Parameter()]
        [Array]$ExcludeVuln,

        [Parameter()]
        [Switch]$Deprecated,

        [Parameter()]
        [Switch]$AllowSeverityOverride,

        [Parameter()]
        [Switch]$Forced,

        [Parameter(Mandatory)]
        [String]$ModulesPath,

        [Parameter(Mandatory)]
        [String]$PsModule,

        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter()]
        [Int]$ProgressId,

        [Parameter(Mandatory)]
        [hashtable]$ModuleArgs
    )

    # Get Instance and DatabaseOrSite for display in progress bar
    $Instance = $ModuleArgs.Instance -ireplace "'",""
    $DatabaseOrSite = $(If ($ModuleArgs.Database) { $ModuleArgs.Database } Else { $ModuleArgs.SiteName }) -ireplace "'",""

    # Get the available commands to a variable.  This reduces scan times.
    $PsModuleCommands = Get-Command -Module $PsModule

    # Pull function parameters first from Get-V#### function
    ### TODO : Explore standardized function params and everthing else as a variable
    $CommonArgs = ($PsModuleCommands | Where-Object Name -Match "Get-V\d{4,}").Parameters.Keys | Where-Object {$_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters} | Select-Object -Unique

    # Build command arguments for scan module parameters.
    $CommandArgs = ""
    ForEach ($Item in $CommonArgs) {
        If ($ModuleArgs.$Item -eq "") {
            $CommandArgs += " -$($Item) " + [char]34 + [char]34
        }
        Else {
            if ($Item -in $ModuleArgs.Keys) {
                if ($ModuleArgs.$Item -match "\s" -and $Item -ne 'Database') {
                    $CommandArgs += ' -{0} {1}' -f ($Item), [char]34 + $($ModuleArgs.$Item) + [char]34
                }
                else {
                    $CommandArgs += ' -{0} {1}' -f ($Item), $($ModuleArgs.$Item)
                }
            }
        }
    }

    # Create global variable objects that need passed to runspace session
    $i = 1
    $GlobalVars = @{}
    ForEach ($Key in $ModuleArgs.Keys) {
        If ($Key -notin $CommonArgs) {
            If ($Key -in @("AnswerFileVars", "CustomVars")) {
                # $AnswerFileVars or $CustomVars key set for scan job (e.g. to hold data that cannot be retrieved using PS 7)
                ForEach ($Item in $ModuleArgs.$Key.Keys) {
                    If ($ModuleArgs.$Key.$Item -ne "") {
                        $GlobalVars.Add($i, [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($Item, $ModuleArgs.$Key.$Item, "", [System.Management.Automation.ScopedItemOptions]::AllScope))
                        $i++
                    }
                }
            }
            Else {
                $GlobalVars.Add($i, [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($Key, $ModuleArgs.$Key, "", [System.Management.Automation.ScopedItemOptions]::AllScope))
                $i++
            }
        }
    }

    # Create runspace pool to include required modules.
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath Master_Functions))
    $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath $PsModule))

    ForEach ($Key in $GlobalVars.Keys) {
        $SessionState.Variables.Add($GlobalVars.$Key)
    }
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $SessionState, $Host)
    $RunspacePool.Open()

    # Get inventory of Group IDs from STIG xccdf
    $STIGVulns = [System.Collections.Generic.List[System.Object]]::new()
    (Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.Group | ForEach-Object {
        $LegacyIDs = @()
        If ($_.rule.ident | Where-Object system -match "legacy") {
            ($_.rule.ident | Where-Object system -Match "legacy").'#text' | Sort-Object -Descending | ForEach-Object {
                $LegacyIDs += ($_).Trim()
            }
        }
        $CCI = @()
        If ($_.rule.ident | Where-Object system -match "cci") {
            ($_.rule.ident | Where-Object system -match "cci").'#text' | ForEach-Object {
                $CCI += ($_).Trim()
            }
        }
        $NewObj = [PSCustomObject]@{
            ID         = ($_.id).Trim()
            GroupTitle = $($_.title).Trim()
            RuleID     = ($_.rule.id).Trim()
            STIGID     = ($_.rule.version).Trim()
            Severity   = ($_.rule.severity).Trim()
            LegacyIDs  = $LegacyIDs
            RuleTitle  = $(Repair-XmlString -String $($_.rule.title).Trim() -RuleTitle)
            Discussion = $(Get-InnerXml -InnerXml $_.rule.description -Tag "VulnDiscussion").Trim()
            CheckText  = $($_.rule.check.'check-content').Trim()
            FixText    = $($_.rule.fixtext.'#text').Trim()
            CCI        = $CCI
        }
        $STIGVulns.Add($NewObj)
    }

    # Build list of vulns to scan
    $VulnsToScan = [System.Collections.Generic.List[System.Object]]::new()
    [int]$TotalSubSteps = ($STIGVulns | Measure-Object).Count
    [Int]$CurrentSubStep = 1
    # Add either Selected Vulns or All Vulns to list of those to be scanned
    ForEach ($Vuln in $STIGVulns) {
        If ($SelectVuln) {
            If ($Vuln.ID -in $SelectVuln) {
                $VulnsToScan.Add($Vuln)
            }
        }
        Else {
            $VulnsToScan.Add($Vuln)
        }
    }

    $ScanResults  = [System.Collections.Generic.List[System.Object]]::new()
    ForEach ($Vuln in $VulnsToScan) {
        $STIGManMetaData = ""

        # Initialize Object Variables
        $GroupID          = $Vuln.ID
        $GroupTitle       = $Vuln.GroupTitle
        $RuleID           = $Vuln.RuleID
        $STIGID           = $Vuln.STIGID
        $Severity         = $Vuln.Severity
        $SeverityOverride = ""
        $Justification    = ""
        $LegacyIDs        = $Vuln.LegacyIDs
        $RuleTitle        = $Vuln.RuleTitle
        $Discussion       = $Vuln.Discussion
        $CheckText        = $Vuln.CheckText
        $FixText          = $Vuln.FixText
        $CCI              = $Vuln.CCI
        $Status           = "Not_Reviewed"
        $FindingDetails   = ""
        $Comments         = ""
        $STIGMan          = [ordered]@{}
        $CheckError       = $false

        If ($Vuln.ID -in $ExcludeVuln) {
            Write-Log -Path $LogPath -Message "Group ID : $($Vuln.ID)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Log -Path $LogPath -Message "    Excluded due to -ExcludeVuln parameter" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
            Continue
        }
        Else {
            # If an Evaluate-STIG function exists for STIG item, process it here
            If ($PsModuleCommands | Where-Object Name -EQ "Get-$($Vuln.ID.Replace('-',''))") {
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity "$(If ($Instance) { $Instance + ' ' })$(If ($DatabaseOrSite) { '[' + $DatabaseOrSite + '] ' })Evaluating..." -Status "$($Vuln.ID)" -PercentComplete ($CurrentSubStep / $TotalSubSteps * 100)
                Write-Log -Path $LogPath -Message "Group ID : $($Vuln.ID)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "    Running $($PsModule)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Try {
                    $FindingDetailsPreText = ""

                    # Run check code
                    $Command = "Get-$($Vuln.ID.Replace('-',''))$($CommandArgs)"
                    $Result = Invoke-CodeWithTimeout -CommandString $Command -Timeout $VulnTimeout -RunspacePool $RunspacePool

                    If (($Result | Measure-Object).count -gt 1){
                        $Result = $Result[-1] #Required to remove STDOUT from "Returned" results (Issue 1841)
                    }

                    If ($Result.Keys -contains "CodeFail") {
                        Throw "CodeFail"
                    }
                    ElseIf ($null -eq $Result.Status) {
                        Throw '$Result.Status is null'
                    }
                    ElseIf ($Result.Status -notin @("Not_Reviewed", "Open", "NotAFinding", "Not_Applicable")) {
                        Write-Log -Path $LogPath -Message "    Scan Module returning an invalid Status of '$($Result.Status)'.  Forcing to 'Not_Reviewed." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        $Result.Status = "Not_Reviewed"
                    }
                    ElseIf ($Result.Status -ne "Not_Reviewed") {
                        Write-Log -Path $LogPath -Message "    Scan Module determined Status is '$($Result.Status)'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                    Else {
                        Write-Log -Path $LogPath -Message "    Scan Module unable to determine Status" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }

                    # Process any answer file mods
                    If ($Result.Comments) {
                        $FormattedAD = Format-AnswerData -ResultStatus $Result.Status -AFKey $Result.AFKey -AFStatus $Result.AFStatus -AFComment $Result.Comments -LogPath $LogPath
                        $Result.Status = $Result.AFStatus
                        $Result.Comments = $FormattedAD.Comments
                        $STIGManMetaData = $FormattedAD.STIGManMetaData
                    }

                    # Check for Severity Override
                    If ($Result.SeverityOverride) {
                        If (-Not($Result.Justification)) {
                            Throw "Module setting 'SeverityOverride' without justification.  This is not acceptable.  Skipping."
                        }
                        ElseIf (-Not($AllowSeverityOverride)) {
                            Write-Log -Path $LogPath -Message "    Module attempting to override severity to '$($Result.SeverityOverride)' but was not allowed." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            $Result.SeverityOverride = ""
                            $Result.Justification = ""
                        }
                        Else {
                            $FindingDetailsPreText += "*** Severity Override used as -AllowSeverityOverride is enabled ***`r`n" | Out-String
                            Write-Log -Path $LogPath -Message "    Overriding Severity to '$($Result.SeverityOverride)' as -AllowSeverityOverride is enabled" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            Write-Log -Path $LogPath -Message "    Justification: $($Result.Justification)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                    }

                    # If STIG was forced with -ForceSTIG, prepend FindingDetails with warning
                    If ($Forced) {
                        $FindingDetailsPreText += "*** Evaluate-STIG determined this STIG as not required.  Results generated with -ForceSTIG ***`r`n" | Out-String
                    }

                    # If STIG is deprecated prepend FindingDetails with warning
                    If ($Deprecated) {
                        $FindingDetailsPreText += "*** This STIG has been deprecated on cyber.mil ***`r`n" | Out-String
                    }

                    # If FindingDetails needs PreText, add it
                    If ($FindingDetailsPreText) {
                        $Result.FindingDetails = $FindingDetailsPreText + $Result.FindingDetails
                    }

                    # Truncate FindingDetails if over 32667 characters
                    If (($Result.FindingDetails | Measure-Object -Character).Characters -gt 32667) {
                        $Result.FindingDetails = $Result.FindingDetails.Substring(0, [System.Math]::Min(32617, $Result.FindingDetails.Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
                    }

                    # Update Object variables
                    $SeverityOverride = $Result.SeverityOverride
                    $Justification = $Result.Justification
                    $Status = $Result.Status
                    If ($Result.FindingDetails) {
                        $FindingDetails = $Result.FindingDetails
                    }
                    Else {
                        $FindingDetails = $Result.Comments
                    }
                    $Comments = $Result.Comments
                    If ($STIGManMetaData) {
                        $STIGMan = $STIGManMetaData
                    }
                }
                Catch {
                    Write-Log -Path $LogPath -Message "    Failed to execute vuln scan" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    If ($($_.Exception.Message) -eq "Job timed out.") {
                        Write-Host "$PsModule (Get-$($Vuln.ID.Replace('-',''))) : Timeout of $VulnTimeout minutes reached." -ForegroundColor Yellow
                        Write-Log -Path $LogPath -Message "    Check Timeout of $VulnTimeout minutes reached. Aborting." -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        $FindingDetails += "*** Evaluate-STIG check timeout of $VulnTimeout minutes reached and scan for this check aborted.  Either increase the timeout with '-VulnTimeout' or complete this check manually. ***" | Out-String
                    }
                    Else {
                        $ErrorText = ""
                        $FindingDetails = ""
                        $CheckError = $true
                        Write-Host "$PsModule (Get-$($Vuln.ID.Replace('-',''))) : Failed. See Evaluate-STIG.log for details." -ForegroundColor Red -BackgroundColor Black

                        # Parse the error output
                        if ($_.Exception.Message -eq "CodeFail") {
                            # Failure detected in scan module code
                            $ErrorData = $Result.ErrorData | Get-ErrorInformation
                            foreach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                                Write-Log -Path $LogPath -Message "      $($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                $ErrorText += "$($Prop) : $($ErrorData.$Prop)" | Out-String
                            }
                        }
                        else {
                            $ErrorData = $_ | Get-ErrorInformation
                            foreach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                                Write-Log -Path $LogPath -Message "    $($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                $ErrorText += "$($Prop) : $($ErrorData.$Prop)" | Out-String
                            }
                        }

                        # Get the hash of ErrorText
                        $ResultHash = Get-TextHash -Text $ErrorText -Algorithm SHA1

                        # Write to FindingDetails
                        $FindingDetails += "*** $PsModule (Get-$($Vuln.ID.Replace('-',''))) : Failed. ***" | Out-String
                        if (($ModuleArgs.AnswerFileVars.Instance).Length -gt 0) {
                            $FindingDetails += "Instance: $($ModuleArgs.AnswerFileVars.Instance)" | Out-String
                        }
                        if (($ModuleArgs.AnswerFileVars.Database).Length -gt 0) {
                            $FindingDetails += "Database: $($ModuleArgs.AnswerFileVars.Database)" | Out-String
                        }
                        if (($ModuleArgs.AnswerFileVars.Site).Length -gt 0) {
                            $FindingDetails += "Site: $($ModuleArgs.AnswerFileVars.Site)" | Out-String
                        }
                        if ($ModuleArgs.AnswerFileVars.Username -ne "NA") {
                            $FindingDetails += "Username: $($ModuleArgs.AnswerFileVars.Username)" | Out-String
                        }
                        if ($ModuleArgs.AnswerFileVars.UserSID -ne "NA") {
                            $FindingDetails += "UserSID: $($ModuleArgs.AnswerFileVars.UserSID)" | Out-String
                        }
                        $FindingDetails += "ResultHash: $($ResultHash)" | Out-String
                        $FindingDetails += "~~~~~" | Out-String
                        $FindingDetails += $ErrorText
                    }

                    If ($ModuleArgs.AnswerFile) {
                        # Look to see if there is an answer in an answer file for this STIG item
                        $GetCorpParams = @{
                            AnswerFile   = $ModuleArgs.AnswerFile
                            VulnID       = $Vuln.ID
                            RuleID       = $Vuln.RuleID
                            AnswerKey    = $ModuleArgs.AnswerKey
                            Hostname     = $ModuleArgs.AnswerFileVars.Hostname
                            Username     = $ModuleArgs.AnswerFileVars.Username
                            UserSID      = $ModuleArgs.AnswerFileVars.UserSID
                            Instance     = $ModuleArgs.AnswerFileVars.Instance
                            Database     = $ModuleArgs.AnswerFileVars.Database
                            Site         = $ModuleArgs.AnswerFileVars.Site
                            ResultHash   = $ResultHash
                            ResultData   = $ErrorText
                            ESPath       = $ModuleArgs.AnswerFileVars.ESpath
                            LogPath      = $LogPath
                            LogComponent = $LogComponent
                            OSPlatform   = $OSPlatform
                            UseSubProc   = $true
                        }

                        $AnswerData = (Get-CorporateComment @GetCorpParams)
                        If ($AnswerData -and $AnswerData.ExpectedStatus -eq $Status) {
                            $FormattedAD = Format-AnswerData -ResultStatus $Status -AFKey $AnswerData.AFKey -AFStatus $AnswerData.AFStatus -AFComment $AnswerData.AFComment -LogPath $LogPath
                            $Status = $AnswerData.AFStatus
                            $Comments = $FormattedAD.Comments
                            $STIGManMetaData = $FormattedAD.STIGManMetaData
                        }

                        # Update Object variables
                        $SeverityOverride = $SeverityOverride
                        $Justification = $Justification
                        $Status = $Status
                        $FindingDetails = $FindingDetails
                        $Comments = $Comments
                        If ($STIGManMetaData) {
                            $STIGMan = $STIGManMetaData
                        }
                    }
                }
            }
            ElseIf ($ModuleArgs.AnswerFile) {
                # If not checked by Evaluate-STIG function, look to see if there is an answer in an answer file for this STIG item
                $GetCorpParams = @{
                    AnswerFile       = $ModuleArgs.AnswerFile
                    VulnID           = $Vuln.ID
                    RuleID           = $Vuln.RuleID
                    AnswerKey        = $ModuleArgs.AnswerKey
                    Hostname         = $ModuleArgs.AnswerFileVars.Hostname
                    Username         = $ModuleArgs.AnswerFileVars.Username
                    UserSID          = $ModuleArgs.AnswerFileVars.UserSID
                    Instance         = $ModuleArgs.AnswerFileVars.Instance
                    Database         = $ModuleArgs.AnswerFileVars.Database
                    Site             = $ModuleArgs.AnswerFileVars.Site
                    ESPath           = $ModuleArgs.AnswerFileVars.ESpath
                    LogPath          = $LogPath
                    LogComponent     = $LogComponent
                    OSPlatform       = $OSPlatform
                    UseSubProc       = $true
                    UnsupportedCheck = $true
                }

                $AnswerData = (Get-CorporateComment @GetCorpParams)
                If ($AnswerData -and $AnswerData.ExpectedStatus -eq $Status) {
                    $FormattedAD = Format-AnswerData -ResultStatus $Status -AFKey $AnswerData.AFKey -AFStatus $AnswerData.AFStatus -AFComment $AnswerData.AFComment -LogPath $LogPath
                    $Status = $AnswerData.AFStatus
                    $Comments = $FormattedAD.Comments
                    $STIGManMetaData = $FormattedAD.STIGManMetaData
                }

                # Update Object variables
                $SeverityOverride = $SeverityOverride
                $Justification = $Justification
                $Status = $Status
                $FindingDetails = $Comments
                $Comments = $Comments
                If ($STIGManMetaData) {
                    $STIGMan = $STIGManMetaData
                }
            }

            # Add vuln to ScanResults
            $NewObj = [PSCustomObject]@{
                GroupID          = $GroupID
                GroupTitle       = $GroupTitle
                RuleID           = $RuleID
                STIGID           = $STIGID
                Severity         = $Severity
                SeverityOverride = $SeverityOverride
                Justification    = $Justification
                LegacyIDs        = $LegacyIDs
                RuleTitle        = $RuleTitle
                Discussion       = $Discussion
                CheckText        = $CheckText
                FixText          = $FixText
                CCI              = $CCI
                Status           = $Status
                FindingDetails   = $FindingDetails
                Comments         = $Comments
                STIGMan          = $STIGMan
                CheckError       = $CheckError
            }
            $ScanResults.Add($NewObj)
        }

        $CurrentSubStep++
    }
    Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity "Evaluating..." -Status "$($Vuln.ID)" -Completed
    if ($PsModule -like 'Scan-SqlServer*') {
        $null = Invoke-CodeWithTimeout -CommandString 'Close-SQLConnections' -Timeout $VulnTimeout -RunspacePool $RunspacePool
    }
    $RunspacePool.Close()
    $RunspacePool.Dispose()

    Return $ScanResults
}

Function Invoke-CodeWithTimeout {
    # Added an explicit result capture to EndInvoke() for clarity. Ken Row, 5/22/25, Issue 2320

    Param
    (
        [Parameter(Mandatory)]
        [string]$CommandString,

        [Parameter(Mandatory)]
        [int]$Timeout,

        [Parameter(Mandatory)]
        $RunspacePool
    )

    $CodeScriptblock = [scriptblock]::Create('Try {$Result = ' + $CommandString + '} Catch {$Result = @{CodeFail = $true; ErrorData = $_; Status="Not_Reviewed"}}; Return $Result')
    $ps = [PowerShell]::Create()
    $ps.Runspacepool = $RunspacePool
    $null = $ps.AddScript($CodeScriptblock)
    $handle = $ps.BeginInvoke()
    $start = Get-Date
    do {
        $timeConsumed = (Get-Date) - $start
        if ($timeConsumed.TotalMinutes -ge $Timeout) {
            $ps.Stop()
            $ps.Dispose()
            throw "Job timed out."
        }
        Start-Sleep -Milliseconds 50
    } until ($handle.isCompleted)

    $codeResult = $ps.EndInvoke($handle)
    $ps.Dispose()
    return $codeResult
}

Function Initialize-PreviousProcessing {
    Param (
        [Parameter(Mandatory)]
        [String]$ResultsPath,

        [Parameter(Mandatory)]
        [Int]$PreviousToKeep,

        [Parameter()]
        [PSObject]$SelectedShortNames,

        [Parameter()]
        [Switch]$SelectedCombinedCKL,

        [Parameter()]
        [Switch]$SelectedCombinedCKLB,

        [Parameter()]
        [Switch]$SelectedCombinedCSV,

        [Parameter()]
        [Switch]$SelectedSummary,

        [Parameter()]
        [Switch]$SelectedOQE,

        [Parameter(Mandatory)]
        [String]$LogPath,

        [Parameter(Mandatory)]
        [String]$LogComponent,

        [Parameter(Mandatory)]
        [String]$OSPlatform
    )

    $PreviousPath = $(Join-Path -Path $ResultsPath -ChildPath "Previous")
    If ($PreviousToKeep -eq 0) {
        Write-Log -Path $LogPath -Message "Parameter -PreviousToKeep is '0'.  Removing all previous scan results." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
        Remove-DirectoryRecurse -Path $ResultsPath
    }
    Else {
        # Get all recent results
        $PreviousResult = Get-ChildItem $ResultsPath -Recurse | Where-Object {$_.FullName -notlike "*Previous*"}

        If ($SelectedShortNames) {
            [array]$SelectedMatches = $SelectedShortNames
            $SelectedMatches += "Evaluate-STIG\.log"
            If ($SelectedCombinedCKL) { # Add combined .ckl to items to be moved
                $SelectedMatches += "COMBINED.{0,}\.ckl"
            }
            If ($SelectedCombinedCKLB) { # Add combined .cklb to items to be moved
                $SelectedMatches += "COMBINED.{0,}\.cklb"
            }
            If ($SelectedCombinedCSV) { # Add combined .csv to items to be moved
                $SelectedMatches += "COMBINED.{0,}\.csv"
            }
            If ($SelectedSummary) { # Add summary report files to items to be moved
                $SelectedMatches += "SummaryReport"
            }
            If ($SelectedOQE) { # Add OQE files to items to be moved
                $SelectedMatches += "AppLockerPol.{0,}\.xml"
                $SelectedMatches += "GPResult.{0,}\.html"
                $SelectedMatches += "SecPol.{0,}\.ini"
            }
            $PreviousResult = $PreviousResult | Where-Object {$_.Name -match ($SelectedMatches -join "|")}
        }

        If ($PreviousResult) {
            # Move recent results to previous
            $PreviousDate = Get-Date ($PreviousResult.LastWriteTime | Sort-Object -Descending)[0] -Format yyyyMMdd-HHmmss
            $PreviousSession = $(Join-Path -Path $PreviousPath -ChildPath $PreviousDate)
            Write-Log -Path $LogPath -Message "Moving previous scan result to '$PreviousSession'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            If (-Not(Test-Path $PreviousSession)) {
                $null = New-Item -Path $PreviousSession -ItemType Directory
            }

            $PreviousResult | Where-Object {$null -ne $_.DirectoryName} | ForEach-Object {
                If ($($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),"") {
                    # Create subfolder in PreviousSession
                    If (-Not(Test-Path $(Join-Path -Path $PreviousSession -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),"")))) {
                        $null = New-Item -Path $(Join-Path -Path $PreviousSession -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),"")) -ItemType Directory
                    }
                }
                Copy-Item -Path $_.FullName -Destination $(Join-Path -Path $PreviousSession -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),""))
                Remove-Item -Path $_.FullName -Force
            }
        }

        # Clean up previous path to only retain number of folders specified by -PreviousToKeep or all folder if -PreviousToKeep is negative value
        If ($PreviousToKeep -lt 0) {
            Write-Log -Path $LogPath -Message "Retaining ALL previous scans per -PreviousToKeep parameter being a negative value" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Else {
            Write-Log -Path $LogPath -Message "Retaining a maximum of '$PreviousToKeep' previous scans per -PreviousToKeep parameter" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            If (Test-Path $PreviousPath) {
                $i = 0
                ForEach ($Item in (Get-ChildItem -Path $PreviousPath | Sort-Object -Descending).FullName) {
                    $i++
                    If ($i -gt $PreviousToKeep) {
                        Write-Log -Path $LogPath -Message "Removing previous result: '$Item'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Remove-Item $Item -Recurse -Force
                    }
                }
            }
        }
    }
}

Function Convert-SubnetMask {
    ###############################################################################################################
    # Language     :  PowerShell 4.0
    # Filename     :  Convert-Subnetmask.ps1
    # Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
    # Description  :  Convert a subnetmask to CIDR and vise versa
    # Repository   :  https://github.com/BornToBeRoot/PowerShell
    ###############################################################################################################

    <#
        .SYNOPSIS
        Convert a subnetmask to CIDR and vise versa

        .DESCRIPTION
        Convert a subnetmask like 255.255.255 to CIDR (/24) and vise versa.

        .EXAMPLE
        Convert-Subnetmask -CIDR 24

        Mask          CIDR
        ----          ----
        255.255.255.0   24

        .EXAMPLE
        Convert-Subnetmask -Mask 255.255.0.0

        Mask        CIDR
        ----        ----
        255.255.0.0   16

        .LINK
        https://github.com/BornToBeRoot/PowerShell/blob/master/Documentation/Function/Convert-Subnetmask.README.md

    #>

    [CmdLetBinding(DefaultParameterSetName = 'CIDR')]
    param(
        [Parameter(
            ParameterSetName = 'CIDR',
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'CIDR like /24 without "/"')]
        [ValidateRange(0, 32)]
        [Int32]$CIDR,

        [Parameter(
            ParameterSetName = 'Mask',
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Subnetmask like 255.255.255.0')]
        [ValidateScript({
                if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$") {
                    return $true
                }
                else {
                    throw "Enter a valid subnetmask (like 255.255.255.0)!"
                }
            })]
        [String]$Mask
    )

    Begin {

    }

    Process {
        switch ($PSCmdlet.ParameterSetName) {
            "CIDR" {
                # Make a string of bits (24 to 11111111111111111111111100000000)
                $CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")

                # Split into groups of 8 bits, convert to Ints, join up into a string
                $Octets = $CIDR_Bits -split '(.{8})' -ne ''
                $Mask = ($Octets | ForEach-Object -Process {[Convert]::ToInt32($_, 2) }) -join '.'
            }

            "Mask" {
                # Convert the numbers into 8 bit blocks, join them all together, count the 1
                $Octets = $Mask.ToString().Split(".") | ForEach-Object -Process {[Convert]::ToString($_, 2)}
                $CIDR_Bits = ($Octets -join "").TrimEnd("0")

                # Count the "1" (111111111111111111111111 --> /24)
                $CIDR = $CIDR_Bits.Length
            }
        }

        [pscustomobject] @{
            Mask = $Mask
            CIDR = $CIDR
        }
    }

    End {

    }
}

Function Convert-Status {
    # Super simple function to save space. Converts freely between Status for Evaluate-STIG, CKL, CKLB, XCCDF.
    [cmdletbinding()]
    Param (
        [Parameter(ValueFromPipeline)]
        [ValidateSet(
            'NR', 'NF', 'NA', 'O', # Evaluate-STIG
            'Not_Reviewed', 'NotAFinding', 'Not_Applicable', 'Open', # CKL/CKLB (except 'NotAFinding')
            'not_a_finding', # CKLB only
            'notchecked', 'pass', 'notapplicable', 'fail' # STIG Manager
        )]
        $InputObject,

        [ValidateSet('EvalSTIG', 'CKL', 'CKLB', 'XCCDF')]
        [String]
        $Output
    )

    $SortingHat = @{
        'EvalSTIG' = @{
            # Input = CKL
            'Not_Reviewed'   = 'NR'
            'NotAFinding'    = 'NF'
            'Not_Applicable' = 'NA'
            'Open'           = 'O'
            # Input = CKLB
            'not_a_finding'  = 'NF'
            # Input = STIGMAN
            'notchecked'     = 'NR'
            'pass'           = 'NF'
            'notapplicable'  = 'NA'
            'fail'           = 'O'
        }
        'CKL'      = @{
            # Input = Evaluate-STIG
            'NR'             = 'Not_Reviewed'
            'NF'             = 'NotAFinding'
            'NA'             = 'Not_Applicable'
            'O'              = 'Open'
            # Input = CKLB
            'not_a_finding'  = 'NotAFinding'
            # Input = STIGMAN
            'notchecked'     = 'Not_Reviewed'
            'pass'           = 'NotAFinding'
            'notapplicable'  = 'Not_Applicable'
            'fail'           = 'Open'
        }
        'CKLB'     = @{
            # Input = Evaluate-STIG
            'NR'             = 'Not_Reviewed'
            'NF'             = 'not_a_finding'
            'NA'             = 'Not_Applicable'
            'O'              = 'Open'
            # Input = CKLB
            'NotAFinding'    = 'not_a_finding'
            # Input = STIGMAN
            'notchecked'     = 'Not_Reviewed'
            'pass'           = 'not_a_finding'
            'notapplicable'  = 'Not_Applicable'
            'fail'           = 'Open'
        }
        'XCCDF'  = @{
            # Input = Evaluate-STIG
            'NR'             = 'notchecked'
            'NF'             = 'pass'
            'NA'             = 'notapplicable'
            'O'              = 'fail'
            # Input = CKL
            'Not_Reviewed'   = 'notchecked'
            'NotAFinding'    = 'pass'
            'Not_Applicable' = 'notapplicable'
            'Open'           = 'fail'
            # Input = CKLB
            'not_a_finding'  = 'pass'
        }
    }

    $result = $SortingHat[$Output][$InputObject]
    If (-not($result)) {
        $result = $InputObject
    }
    Return $result
}

Function Get-InnerXml {
    # Function to extract data from InnerXml objects (e.g. Benchmark.Group.Rule.Description from STIG XCCDF).
    param
    (
        [Parameter(Mandatory)]
        [string]$InnerXml,

        [Parameter(Mandatory)]
        [psobject]$Tag
    )

    $Value = ""
    #$MatchString = "<$Tag>.{0,}\n{0,}\r{0,}.{0,}</$Tag>"
    $MatchString = "(?sm)<$Tag>.{0,}</$Tag>"
    If ($InnerXml -match $MatchString) {
        $Value = $Matches[0] -replace "</{0,}$Tag>", ""
    }

    Return $Value
}

Function Invoke-CombinedCKL {
    Param (
        [Parameter(Mandatory = $true)]
        [PSObject]$STIGsToProcess,

        [Parameter(Mandatory = $true)]
        [String]$CklDestinationPath,

        [Parameter(Mandatory = $true)]
        [String]$CKLResultsPath,

        [Parameter(Mandatory = $true)]
        [String]$CombinedFile,

        [Parameter(Mandatory = $false)]
        [String]$Marking
    )

    Try {
        $CklOutFile = Join-Path -Path $CklDestinationPath -ChildPath $CombinedFile

        # Build list of STIGs that cannot combine
        $ShortNamesToExclude = @()
        ForEach ($Item in ($STIGsToProcess | Where-Object CanCombine -NE $true)) {
            $ShortNamesToExclude += $Item.ShortName
        }

        # Build list of CKLs to preserve
        $ChecklistsToCombine = @()
        ForEach ($Item in (Get-ChildItem -Path $CKLResultsPath -Filter "*.ckl" | Where-Object Name -NotLike "*_COMBINED_*.ckl")) {
            $Exclude = $false
            ForEach ($ShortName in $ShortNamesToExclude) {
                If ($Item.Name -match $ShortName) {
                    $EXclude = $true
                }
            }
            If ($Exclude -ne $true) {
                $ChecklistsToCombine += $Item
            }
        }

        # Get CKL framework from first discovered CKL
        $NewCKL = (Select-Xml -Path $ChecklistsToCombine[0].FullName -XPath /).Node

        # Remove Comments
        $NewCKL.SelectNodes("//comment()") | ForEach-Object {$null = $_.ParentNode.RemoveChild($_)}

        If ($Marking) {
            # Add marking header
            $MarkingHeader = $NewCKL.CreateComment("                                                                                          $Marking                                                                                          ")
            $null = $NewCKL.InsertBefore($MarkingHeader, $NewCKL.CHECKLIST)
        }

        # Add Evaluate-STIG comment
        $ESVersionXML = $NewCKL.CreateComment("<Evaluate-STIG><global><version>$ESVersion</version><time>$(Get-Date -Format 'o')</time></global><module><name></name><version></version></module><stiglist><name>COMBINED_CKL</name><shortname>COMBINED_CKL</shortname><template>COMBINED_CKL</template></stiglist></Evaluate-STIG>")
        $null = $NewCKL.InsertBefore($ESVersionXML, $NewCKL.CHECKLIST)

        # Initialize WEB_OR_DATABASE, WEB_DB_SITE, and WEB_DB_INSTANCE elements
        $NewCKL.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"
        $NewCKL.CHECKLIST.ASSET.WEB_DB_SITE = ""
        $NewCKL.CHECKLIST.ASSET.WEB_DB_INSTANCE = ""
        $NewCKL.CHECKLIST.ASSET.MARKING = [string]$Marking

        # Remove iSTIG node.  Will replace later
        $NodesToDelete = $NewCKL.SelectNodes("//iSTIG")
        ForEach ($Node in $NodesToDelete) {
            $Node.ParentNode.RemoveChild($Node) | Out-Null
        }

        If (($ChecklistsToCombine | Measure-Object).Count -gt 1) {
            ForEach ($Checklist in $ChecklistsToCombine) {
                $CKL = (Select-Xml -Path $Checklist.Fullname -XPath /).Node

                # Add iSTIG node to combined CKL
                $iSTIG = $NewCKL.ImportNode($CKL.SelectSingleNode("//iSTIG"), $true)
                $NewCKL.CHECKLIST.STIGS.AppendChild($iSTIG) | Out-Null
            }

            If ($Marking) {
                # Add marking footer
                $MarkingFooter = $NewCKL.CreateComment("                                                                                          $Marking                                                                                          ")
                $null = $NewCKL.InsertAfter($MarkingFooter, $NewCKL.CHECKLIST)
            }

            # Save the combined CKL
            $NewCKL.Save($CklOutFile)
        }
        Else {
            Throw "Only one (1) checklist found.  Nothing to combine."
        }
    }
    Catch {
        Throw $_.Exception.Message
    }
}

function Repair-XmlString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$String,

        [Parameter(Mandatory = $false)]
        [Switch]$RuleTitle
    )

    # Replace control characters with the given replacement
    $newstring = -join ($String.ToCharArray() | ForEach-Object {
        $charCode = [int][char]$_

        # Check if the character is a control character
        $ValidASCIICodeRanges = 9, 10, 13, (32..126) # List of valid decimal ASCII codes
        $CodesToExclude = $ValidASCIICodeRanges | ForEach-Object {$_}
        If ($charCode -notin $CodesToExclude) {
            # Replace other control characters with nothing
            ""
        }
        Else {
            # Leave printable characters as is
            $_
        }
    })

    $pattern =  "(?<=\&)(#x?[0-9A-Fa-f]+)(?=\;)"
    $hex = "$([regex]::matches($newstring, $pattern).value)"
    if ($hex){
        $hex -split " " | Foreach-Object {
            $newstring = $newstring -replace "&$_;", [char[]]$([BYTE][CHAR]([CONVERT]::toint16($($_ -replace "#","0"),16)))
        }
    }

    $newstring = $newstring -Replace "`0", "[null]"
    If ($RuleTitle) {
        $newstring = $newstring -Replace "[\x00-\x1F\x7F]"
    }

    Return $newstring
}

Function Send-CheckResult {
    # Returns custom check data to Write-Ckl for inclusion into the checklist file
    Param (
        # Scan Module Name
        [Parameter(Mandatory = $true)]
        [String]$Module,

        # Status of check
        [Parameter(Mandatory = $true)]
        [String]$Status,

        # Finding Details of check
        [Parameter(Mandatory = $false)]
        [String]$FindingDetails,

        # Answer File Source Key
        [Parameter(Mandatory = $false)]
        [String]$AFKey,

        # Answer File FinalStatus
        [Parameter(Mandatory = $false)]
        [String]$AFStatus,

        # Approved Comments of check
        [Parameter(Mandatory = $false)]
        [String]$Comments,

        # SeverityOverride Change
        [Parameter(Mandatory = $false)]
        [String]$SeverityOverride,

        # SeverityOverride Justification
        [Parameter(Mandatory = $false)]
        [String]$Justification,

        # Instance for FindingDetails header
        [Parameter(Mandatory = $false)]
        [String]$HeadInstance,

        # Database for FindingDetails header
        [Parameter(Mandatory = $false)]
        [String]$HeadDatabase,

        # Site for FindingDetails header
        [Parameter(Mandatory = $false)]
        [String]$HeadSite,

        # Username for FindingDetails header
        [Parameter(Mandatory = $false)]
        [String]$HeadUsername,

        # UserSID for FindingDetails header
        [Parameter(Mandatory = $false)]
        [String]$HeadUserSID,

        # Hash of FindingDetails
        [Parameter(Mandatory = $false)]
        [String]$HeadHash
    )

    [hashtable]$CheckResults = @{ }
    $CheckResults.Status = "Not_Reviewed" #acceptable values are "Not_Reviewed", "Open", "NotAFinding", "Not_Applicable"
    $CheckResults.FindingDetails = ""
    $CheckResults.AFKey = ""
    $CheckResults.AFStatus = ""
    $CheckResults.Comments = ""

    if ($HeadHash) {
        # Existence of HeadHash indicates that Finding Details has data
        $FindingDetailsText = ""

        Switch ($Status) {
            "Open" {
                $CheckResults.Status = "Open"
                $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be OPEN on $(Get-Date -Format MM/dd/yyyy)" | Out-String
            }
            "NotAFinding" {
                $CheckResults.Status = "NotAFinding"
                $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be NOT A FINDING on $(Get-Date -Format MM/dd/yyyy)" | Out-String
            }
            "Not_Applicable" {
                $CheckResults.Status = "Not_Applicable"
                $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be NOT APPLICABLE on $(Get-Date -Format MM/dd/yyyy)" | Out-String
            }
            DEFAULT {
                $CheckResults.Status = "Not_Reviewed"
                If ($FindingDetails.Trim().Length -gt 0) {
                    $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) was unable to determine a Status but found the below configuration on $(Get-Date -Format MM/dd/yyyy):" | Out-String
                }
            }
        }

        # Add additonal data to FindingDetails header
        If ($HeadInstance.Length -gt 0) {
            $FindingDetailsText += "Instance: $($HeadInstance)" | Out-String
        }
        If ($HeadDatabase.Length -gt 0) {
            $FindingDetailsText += "Database: $($HeadDatabase)" | Out-String
        }
        If ($HeadSite.Length -gt 0) {
            $FindingDetailsText += "Site: $($HeadSite)" | Out-String
        }
        If ($HeadUsername) {
            $FindingDetailsText += "Username: $($HeadUsername)" | Out-String
        }
        If ($HeadUserSID) {
            $FindingDetailsText += "UserSID: $($HeadUserSID)" | Out-String
        }
        If ($HeadHash) {
            $FindingDetailsText += "ResultHash: $($HeadHash)" | Out-String
        }
        $FindingDetailsText += "~~~~~" | Out-String

        If ($FindingDetails) {
            $FindingDetailsText += Repair-XmlString -String $FindingDetails
        }
        $CheckResults.FindingDetails = $FindingDetailsText
    }

    If ($AFKey) {
        $CheckResults.AFKey = Repair-XmlString -String $AFKey
    }

    If ($AFStatus) {
        $CheckResults.AFStatus = Repair-XmlString -String $AFStatus
    }

    If ($Comments) {
        $CheckResults.Comments = Repair-XmlString -String $Comments
    }

    Switch ($SeverityOverride) {
        "CAT_I" {
            $CheckResults.SeverityOverride = "high"
        }
        "CAT_II" {
            $CheckResults.SeverityOverride = "medium"
        }
        "CAT_III" {
            $CheckResults.SeverityOverride = "low"
        }
    }

    If ($Justification) {
        $CheckResults.Justification = Repair-XmlString -String $Justification
    }

    Return $CheckResults
}

Function Write-Log {
    <#
    .Synopsis
        Write to a CMTrace friendly .log file.
    .DESCRIPTION
        Takes the input and generates an entry for a CMTrace friendly .log file
        by utilizing a PSCustomObject and Generic List to hold the data.
        A string is created and added to the .log file.
    .EXAMPLE
       PS C:\> Write-Log -Path 'C:\Temp\sample.log' -Message 'Test Message' -Component 'Write-Log' -MessageType Verbose -OSPlatform Windows
    .INPUTS
        -Path
            Use of this parameter is required. Forced to be a String type. The path to where the .log file is located.
        -Message
            Use of this parameter is required. Forced to be a String type. The message to pass to the .log file.
        -Component
            Use of this parameter is required. Forced to be a String type. What is providing the Message.
            Typically this is the script or function name.
        -Type
            Use of this parameter is required. Forced to be a String type. What type of output to be. Choices are
            Info, Warning, Error and Verbose.
        -OSPlatform
            Use of this parameter is required. Forced to be a String type. What OS platform the system is. Choices are Windows or Linux.
        -TemplateMessage <"LineBreak-Dash" | "LineBreak-Text">
            Write a standardized line/section break to the log.
        -WriteOutToStream
            Write message to both log and console.
    .OUTPUTS
        No output. Writes an entry to a .log file via Add-Content.
    .NOTES
        Resources/Credits:
            Dan Ireland - daniel.c.ireland@us.navy.mil
            Brent Betts - brent.a.betts2.civ@us.navy.mil
        Helpful URLs:
            Russ Slaten's Blog Post - Logging in CMTrace format from PowerShell
            https://blogs.msdn.microsoft.com/rslaten/2014/07/28/logging-in-cmtrace-format-from-powershell/
    #>

    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$Message,

        [Parameter(Mandatory = $true)]
        [String]$Component,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error", "Verbose")]
        [String]$Type,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LineBreak-Dash', 'LineBreak-Text')]
        [String]$TemplateMessage,

        [Parameter(Mandatory = $false)]
        [Switch]$WriteOutToStream,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [String]$FGColor
    )

    Switch ($Type) {
        'Info' {
            [Int]$Type = 1
            If (-Not($FGColor)) {
                $FGColor = "White"
            }
        }
        'Warning' {
            [Int]$Type = 2
            If (-Not($FGColor)) {
                $FGColor = "Yellow"
            }
        }
        'Error' {
            [Int]$Type = 3
            If (-Not($FGColor)) {
                $FGColor = "Red"
                $BGColor = "Black"
            }
        }
        'Verbose' {
            [Int]$Type = 4
            If (-Not($FGColor)) {
                $FGColor = "DarkGray"
            }
        }
    }

    # Obtain date/time
    Switch ($OSPlatform) {
        "Windows" {
            $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
            $DateTime.SetVarDate($(Get-Date))
            $UtcValue = $DateTime.Value
            $UtcOffset = [Math]::Abs($UtcValue.Substring(21, $UtcValue.Length - 21))
            $user_name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        "Linux" {
            $UtcOffset = (date +%z_).Trim("-")
            $user_name = whoami
        }
    }

    Switch ($TemplateMessage) {
        'LineBreak-Dash' {
            $Message = '----------------------------------'
        }
        'LineBreak-Text' {
            $Message = '==========[{0}]==========' -f $Message
        }
    }

    # Create Object to hold items to log
    $LogItems = [System.Collections.Generic.List[System.Object]]::new()
    $NewObj = [PSCustomObject]@{
        Message   = $Message
        Time      = [Char]34 + (Get-Date -Format "HH:mm:ss.fff") + "+$UtcOffset" + [Char]34
        Date      = [Char]34 + (Get-Date -Format "MM-dd-yyyy") + [Char]34
        Component = [Char]34 + $Component + [Char]34
        Context   = [Char]34 + $user_name + [Char]34
        Type      = [Char]34 + $Type + [Char]34
        Thread    = [Char]34 + [Threading.Thread]::CurrentThread.ManagedThreadId + [Char]34
        File      = [Char]34 + [Char]34
    }
    $LogItems.Add($NewObj)

    # Format Log Entry
    $padMessage = '{0,-80}' -f $LogItems.Message
    $Entry = "<![LOG[${padMessage}]LOG]!><time=$($LogItems.Time) date=$($LogItems.Date) component=$($LogItems.Component) context=$($LogItems.Context) type=$($LogItems.Type) thread=$($logItems.Thread) file=$($LogItems.File)>"

    # Write to the Console
    If ($WriteOutToStream) {
        If ($BGColor) {
            Write-Host $Message -ForegroundColor $FGColor -BackgroundColor $BGColor
        }
        Else {
            Write-Host $Message -ForegroundColor $FGColor
        }
    }

    # Add to Log
    Out-File -FilePath $Path -InputObject $Entry -Append -Encoding utf8 -Force -ErrorAction SilentlyContinue
}

Function Invoke-TaskAsSYSTEM {
    # Creates a self-deleting scheduled task that will run as the SYSTEM account and executes it.
    Param (
        [Parameter(Mandatory = $true)]
        [String]$TaskName,

        [Parameter(Mandatory = $true)]
        [String]$FilePath,

        [Parameter(Mandatory = $false)]
        [String]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRunInMinutes
    )

    If (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
        $TaskAction = New-ScheduledTaskAction -Execute $FilePath -Argument $ArgumentList
        $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $MaxRunInMinutes) -AllowStartIfOnBatteries
        $TaskObj = Register-ScheduledTask -TaskName $TaskName -Trigger $TaskTrigger -Action $TaskAction -Settings $TaskSettings -User "SYSTEM" -Force

        $RegisteredTask = Get-ScheduledTask -TaskName $TaskName
        $RegisteredTask.Triggers[0].EndBoundary = ((Get-Date).AddMinutes($MaxRunInMinutes)).ToString('s')
        $RegisteredTask.Settings.DeleteExpiredTaskAfter = 'PT0S'
        $RegisteredTask | Set-ScheduledTask

        Start-ScheduledTask -InputObject $TaskObj
        While ((Get-ScheduledTask -TaskName $TaskName).State -eq "Running") {
            Start-Sleep -Seconds 1
        }
        $TaskResult = Get-ScheduledTaskInfo -InputObject $TaskObj
        Unregister-ScheduledTask -InputObject $TaskObj -Confirm:$false
    }
    Else {
        $OutXml = "$env:temp\Eval-STIG_Task.xml"
        $StartTime = (Get-Date).AddMinutes($MaxRunInMinutes)
        $EndTime = (Get-Date $StartTime).AddMinutes($MaxRunInMinutes)

        # Create XML stream
        $xmlWriter = New-Object System.Xml.XmlTextWriter($OutXml, $null)
        $xmlWriter.Formatting = "Indented"
        $xmlWriter.Indentation = 2
        $XmlWriter.IndentChar = " "
        $xmlWriter.WriteStartDocument()

        # Start 'Task' Element
        $xmlWriter.WriteStartElement("Task")
        $XmlWriter.WriteAttributeString("version", "1.3")
        $XmlWriter.WriteAttributeString("xmlns", "http://schemas.microsoft.com/windows/2004/02/mit/task")
        # Start 'Triggers' Element
        $xmlWriter.WriteStartElement("Triggers")
        # Start 'TimeTrigger' Element
        $xmlWriter.WriteStartElement("TimeTrigger")
        # Create Child Elements
        $xmlWriter.WriteElementString("StartBoundary", $(Get-Date $StartTime -Format yyyy-MM-ddTHH:mm:ssK))
        $xmlWriter.WriteElementString("EndBoundary", $(Get-Date $EndTime -Format yyyy-MM-ddTHH:mm:ss))
        $xmlWriter.WriteElementString("Enabled", "true")
        # End 'TimeTrigger' Element
        $xmlWriter.WriteEndElement()
        # End 'Triggers' Element
        $xmlWriter.WriteEndElement()
        # Start 'Settings' Element
        $xmlWriter.WriteStartElement("Settings")
        # Create Child Elements
        $xmlWriter.WriteElementString("MultipleInstancesPolicy", "IgnoreNew")
        $xmlWriter.WriteElementString("DisallowStartIfOnBatteries", "false")
        $xmlWriter.WriteElementString("StopIfGoingOnBatteries", "false")
        $xmlWriter.WriteElementString("AllowHardTerminate", "true")
        $xmlWriter.WriteElementString("AllowStartOnDemand", "true")
        $xmlWriter.WriteElementString("Enabled", "true")
        $xmlWriter.WriteElementString("UseUnifiedSchedulingEngine", "true")
        $xmlWriter.WriteElementString("ExecutionTimeLimit", "PT$($MaxRunInMinutes)M")
        $xmlWriter.WriteElementString("DeleteExpiredTaskAfter", "PT0S")
        # End 'Settings' Element
        $xmlWriter.WriteEndElement()
        # Start 'Actions' Element
        $xmlWriter.WriteStartElement("Actions")
        # Start 'Exec' Element
        $xmlWriter.WriteStartElement("Exec")
        # Create Child Elements
        $xmlWriter.WriteElementString("Command", $FilePath)
        $xmlWriter.WriteElementString("Arguments", $ArgumentList)
        # End 'Exec' Element
        $xmlWriter.WriteEndElement()
        # End 'Actions' Element
        $xmlWriter.WriteEndElement()
        # End 'Task' Element
        $xmlWriter.WriteEndElement()

        # Save file and close the stream
        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        $xmlWriter.Close()

        $null = SCHTASKS /Create /TN $TaskName /RU SYSTEM /XML $OutXml /F
        $null = SCHTASKS /Run /TN $TaskName /I
        While (((SCHTASKS /Query /TN $TaskName /V /FO List) -match "Status:").Split(":")[1].Trim() -eq "Running") {
            Start-Sleep -Seconds 1
        }
        $TaskResult = @{
            LastTaskResult = ((SCHTASKS /Query /TN $TaskName /V /FO List 2>&1) -match "Last Result:").Split(":")[1].Trim()
        }
        $null = SCHTASKS /Delete /TN $TaskName /F
        Remove-Item $OutXml -Force
    }
    Return $TaskResult
}

Function Get-CommandLine {
    Param (
        [Parameter(Mandatory = $false)]
        [String]$CommandName,

        [Parameter(Mandatory = $false)]
        $BoundParameters,

        [Parameter(Mandatory = $false)]
        [Array]$IgnoreParams
    )

    # Get the name of the script
    If ($CommandName) {
        $CommandLine = $CommandName
    }
    Else {
        $CommandLine = ($Script:MyInvocation.MyCommand).Name
    }

    If ($BoundParameters) {
        ForEach ($Item in $BoundParameters.Keys) {
            If ($Item -notin $IgnoreParams) {
                # Replace SMPassphrase
                If ($Item -eq "SMPassphrase") {
                    $BoundParameters[$Item] = "**************"
                }

                # Recreate the command line from BoundParameters
                Switch ($BoundParameters.$Item.GetType().Name) {
                    {($_ -in @("String[]", "Object[]"))} {
                        $CommandLine += " -$($Item) $($BoundParameters[$Item] -join ',')"
                    }
                    "SwitchParameter" {
                        $CommandLine += " -$($Item)"
                    }
                    DEFAULT {
                        $CommandLine += " -$($Item) $($BoundParameters[$Item])"
                    }
                }
            }
        }
    }

    Return $CommandLine
}

Function Get-RegistryResult {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $false)]
        [String]$ValueName
    )

    $Value = $null
    $Type = $null
    If ($ValueName -eq "(default)") {
        $ValueNameToCheck = ""
    }
    ElseIf (-Not($ValueName)) {
        $ValueName = "(default)"
        $ValueNameToCheck = ""
    }
    Else {
        $ValueNameToCheck = $ValueName
    }

    $Output = New-Object System.Collections.Generic.List[System.Object]
    If (Test-Path -LiteralPath $Path) {
        If (Get-ItemProperty -LiteralPath $Path -Name $ValueNameToCheck -ErrorAction SilentlyContinue) {
            $RegistryKey = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
            If (-Not($null -eq $RegistryKey.GetValue($ValueNameToCheck))) {
                $Value = Get-ItemPropertyValue -LiteralPath $Path -Name $ValueNameToCheck
                $ValueType = $RegistryKey.GetValueKind($ValueNameToCheck)
                Switch ($ValueType) {
                    "Binary" {
                        $Type = "REG_BINARY"
                    }
                    "Dword" {
                        $Type = "REG_DWORD"
                    }
                    "ExpandString" {
                        $Type = "REG_EXPAND_SZ"
                        $Value = $Value.Trim()
                    }
                    "MultiString" {
                        $Type = "REG_MULTI_SZ"
                        If (-Not([String]::IsNullOrEmpty($Value))) {
                            $Value = $Value.Trim()
                        }
                    }
                    "Qword" {
                        $Type = "REG_QWORD"
                    }
                    "String" {
                        $Type = "REG_SZ"
                        $Value = $Value.Trim()
                    }
                }
            }
        }

        If (-Not($Value) -and $ValueName -eq "(default)") {
            $Value = "(value not set)"
            $Type = "REG_SZ"
        }
        ElseIf (-Not($Type)) {
            $ValueName = "(NotFound)"
            $Value = "(NotFound)"
            $Type = "(NotFound)"
        }
        ElseIf (($Type -in @("REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_SZ")) -and ([String]::IsNullOrEmpty($Value))) {
            $Value = "(blank)"
        }

    }
    Else {
        $Path = "(NotFound)"
        $ValueName = "(NotFound)"
        $Value = "(NotFound)"
        $Type = "(NotFound)"
    }

    $NewObj = [PSCustomObject]@{
        Key       = ($Path -replace "\\$", "")
        ValueName = ($ValueName)
        Value     = ($Value)
        Type      = ($Type)
    }
    $Output.Add($NewObj)

    # Clean up registry variables
    $VarsToRemove = @("RegistryKey", "Value", "ValueType")
    ForEach ($Var in $VarsToRemove) {
        If (Get-Variable $Var -ErrorAction SilentlyContinue) {
            Remove-Variable $Var -Force
        }
    }

    Return $Output
}

Function Get-InstalledSoftware {
    If ($null -ne $Global:InstalledSoftware) {
        Return $Global:InstalledSoftware
    }
    Else {
        $SoftwareList = New-Object System.Collections.Generic.List[System.Object]
        $OSArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        Switch ($OSArch) {
            "64-Bit" {
                $RegPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
            }
            Default {
                $RegPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            }
        }
        ForEach ($Path in $RegPath) {
            $RegKeys += (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue).Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:")
        }

        ForEach ($Key in $RegKeys) {
            Try {
                $Properties = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue # A corrupt registry value will cause this to fail.  If so then we do this a different, though slower way, below.

                If ($Properties.DisplayName) {
                    $DisplayName = ($Properties.DisplayName).Trim()
                }
                Else {
                    $DisplayName = ""
                }

                If ($Properties.DisplayVersion) {
                    $DisplayVersion = ($Properties.DisplayVersion -replace "[^a-zA-Z0-9.-_()]").Trim()
                }
                Else {
                    $DisplayVersion = ""
                }

                If ($Properties.Publisher) {
                    $Publisher = ($Properties.Publisher).Trim()
                }
                Else {
                    $Publisher = ""
                }

                If ($Properties.InstallLocation) {
                    $InstallLocation = ($Properties.InstallLocation).Trim()
                }
                Else {
                    $InstallLocation = ""
                }

                If ($Properties.SystemComponent) {
                    $SystemComponent = $Properties.SystemComponent
                }
                Else {
                    $SystemComponent = ""
                }

                If ($Properties.ParentKeyName) {
                    $ParentKeyName = $Properties.ParentKeyName
                }
                Else {
                    $ParentKeyName = ""
                }
            }
            Catch {
                # If above method fails, then do this
                Try {
                    $DisplayName = (Get-ItemPropertyValue $Key -Name DisplayName).Trim()
                }
                Catch {
                    $DisplayName = ""
                }

                Try {
                    $DisplayVersion = (Get-ItemPropertyValue $Key -Name DisplayVersion).Replace("[^a-zA-Z0-9.-_()]", "").Trim()
                }
                Catch {
                    $DisplayVersion = ""
                }

                Try {
                    $Publisher = (Get-ItemPropertyValue $Key -Name Publisher).Trim()
                }
                Catch {
                    $Publisher = ""
                }

                Try {
                    $InstallLocation = (Get-ItemPropertyValue $Key -Name InstallLocation).Trim()
                }
                Catch {
                    $InstallLocation = ""
                }

                Try {
                    $SystemComponent = (Get-ItemPropertyValue $Key -Name SystemComponent).Trim()
                }
                Catch {
                    $SystemComponent = ""
                }

                Try {
                    $ParentKeyName = (Get-ItemPropertyValue $Key -Name ParentKeyName).Trim()
                }
                Catch {
                    $ParentKeyName = ""
                }
            }

            If ($DisplayName -and $SystemComponent -ne 1 -and (-Not($ParentKeyName))) {
                $NewObj = [PSCustomObject]@{
                    DisplayName     = $DisplayName
                    DisplayVersion  = $DisplayVersion
                    Publisher       = $Publisher
                    InstallLocation = $InstallLocation
                }
                $SoftwareList.Add($NewObj)
            }
        }
        $Global:InstalledSoftware = $SoftwareList  | Select-Object * -Unique | Sort-Object DisplayName
        Return $Global:InstalledSoftware
    }
}

Function Get-InstalledO365Apps {
    $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0")
    $PossibleApps = @("Access", "Excel", "Groove", "Lync", "OneNote", "Outlook", "PowerPoint", "Project", "Publisher", "Visio", "Word")
    $InstalledApps = New-Object System.Collections.Generic.List[System.Object]

    ForEach ($App in $PossibleApps) {
        ForEach ($Path in $RegPaths) {
            If (Test-Path "$($Path)\$($App)\InstallRoot") {
                $InstallRoot = (Get-ItemProperty "$($Path)\$($App)\InstallRoot").Path
                Switch ($App) {
                    "Access" {
                        $Exe = "msaccess.exe"
                    }
                    "Excel" {
                        $Exe = "excel.exe"
                    }
                    "Lync" {
                        $Exe = "lync.exe"
                    }
                    "OneNote" {
                        $Exe = "onenote.exe"
                    }
                    "Outlook" {
                        $Exe = "outlook.exe"
                    }
                    "PowerPoint" {
                        $Exe = "powerpnt.exe"
                    }
                    "Project" {
                        $Exe = "winproj.exe"
                    }
                    "Publisher" {
                        $Exe = "mspub.exe"
                    }
                    "Visio" {
                        $Exe = "visio.exe"
                    }
                    "Word" {
                        $Exe = "winword.exe"
                    }
                }
                $NewObj = [PSCustomObject]@{
                    Name = $App
                    Exe  = $Exe
                    Path = $InstallRoot
                }
                $InstalledApps.Add($NewObj)
            }
        }
    }
    Return $InstalledApps
}

Function Get-AdobeReaderProInstalls {
    $InstalledVersions = New-Object System.Collections.Generic.List[System.Object]

    $64bitAcrobatDC = @(Get-InstalledSoftware | Where-Object DisplayName -Like "Adobe Acrobat*(64-bit)*")
    If (($64bitAcrobatDC | Measure-Object).Count -ge 1) {
        # 64-bit Adobe Acrobat DC
        $Path = "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC"
        If (Test-Path (Join-Path -Path $((Get-ItemProperty "$($Path)\InstallPath").'(Default)') -ChildPath "Acrobat.exe") -ErrorAction SilentlyContinue) {
            # 64-bit Adobe Pro and Reader are a unified application and SCAPackageLevel identifies which product is intalled.
            # https://helpx.adobe.com/acrobat/kb/about-acrobat-reader-dc-migration-to-64-bit.html
            $SCAPackageLevel = [Int]((Get-ItemProperty "$($Path)\Installer" -ErrorAction SilentlyContinue)).SCAPackageLevel
            Switch ($SCAPackageLevel) {
                { $_ -gt 1 } {
                    $NewObj = [PSCustomObject]@{
                        Name           = "Adobe Acrobat DC"
                        Version        = "DC"
                        Track          = "Continuous"
                        DisplayVersion = $64bitAcrobatDC[0].DisplayVersion
                        Architecture   = "x64"
                    }
                    If ($NewObj.Name -notin $InstalledVersions.Name) {
                        $InstalledVersions.Add($NewObj)
                    }
                }
                { $_ -eq 1 } {
                    $NewObj = [PSCustomObject]@{
                        Name           = "Adobe Reader DC"
                        Version        = "DC"
                        Track          = "Continuous"
                        DisplayVersion = $64bitAcrobatDC[0].DisplayVersion
                        Architecture   = "x64"
                    }
                    If ($NewObj.Name -notin $InstalledVersions.Name) {
                        $InstalledVersions.Add($NewObj)
                    }
                }
            }
        }
    }

    # 32-bit Adobe Acrobat and Adobe Reader
    $Paths = @("HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat", "HKLM:\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader")
    ForEach ($Path in $Paths) {
        If (Test-Path $Path) {
            Switch (Split-Path $Path -Leaf) {
                "Adobe Acrobat" {
                    $InstallPaths = @((Get-ChildItem $Path -Recurse | Where-Object { $_.Name -like "*InstallPath" -and $null -ne $_.GetValue("") }).Name)
                    ForEach ($Object in ($InstallPaths | Where-Object { $null -ne $_ })) {
                        If (Test-Path (Join-Path -Path $((Get-ItemProperty $($Object.Replace("HKEY_LOCAL_MACHINE", "HKLM:"))).'(Default)') -ChildPath "Acrobat.exe") -ErrorAction SilentlyContinue) {
                            Switch (Split-Path ($Object -split "Installer")[0] -Leaf) {
                                "11.0" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat XI"
                                        Version        = "XI"
                                        Track          = ""
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat XI*") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                { ($_ -in @("2015", "2017", "2020")) } {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat $_"
                                        Version        = $_
                                        Track          = "Classic"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat DC*" -and $_.DisplayVersion -match "15.") -or ($_.DisplayName -Like "Adobe Acrobat 2017*" -and $_.DisplayVersion -match "17.") -or ($_.DisplayName -Like "Adobe Acrobat 2020*" -and $_.DisplayVersion -match "20.") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                "DC" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat $_"
                                        Version        = $_
                                        Track          = "Continuous"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat*" -and $_.DisplayName -NotLike "Adobe Acrobat Reader*" -and $_.DisplayVersion -gt 20) }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                            }
                        }
                        If ($NewObj.Name -notin $InstalledVersions.Name) {
                            $InstalledVersions.Add($NewObj)
                        }
                    }
                }
                "Acrobat Reader" {
                    $InstallPaths = @((Get-ChildItem $Path -Recurse | Where-Object { $_.Name -like "*InstallPath" -and $null -ne $_.GetValue("") }).Name)
                    ForEach ($Object in ($InstallPaths | Where-Object { $null -ne $_ })) {
                        If (Test-Path (Join-Path -Path $((Get-ItemProperty $($Object.Replace("HKEY_LOCAL_MACHINE", "HKLM:"))).'(Default)') -ChildPath "AcroRd32.exe") -ErrorAction SilentlyContinue) {
                            Switch (Split-Path ($Object -split "InstallPath")[0] -Leaf) {
                                "11.0" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader XI"
                                        Version        = "XI"
                                        Track          = ""
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Reader XI*") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                { ($_ -in @("2015", "2017", "2020")) } {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader $_"
                                        Version        = $_
                                        Track          = "Classic"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat Reader DC*" -and $_.DisplayVersion -match "15.") -or ($_.DisplayName -Like "Adobe Acrobat Reader 2017*" -and $_.DisplayVersion -match "17.") -or ($_.DisplayName -Like "Adobe Acrobat Reader 2020*" -and $_.DisplayVersion -match "20.") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                "DC" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader $_"
                                        Version        = $_
                                        Track          = "Continuous"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat Reader*" -and $_.DisplayVersion -gt 20) }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                            }
                            If ($NewObj.Name -notin $InstalledVersions.Name) {
                                $InstalledVersions.Add($NewObj)
                            }
                        }
                    }
                }
            }
        }
    }

    If ($InstalledVersions) {
        Return $InstalledVersions | Sort-Object Version -Descending
    }
}

Function Confirm-DefaultAcl {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("FileSystem", "Registry")]
        [String]$Type,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [Array]$DefaultAcl
    )

    $IsDefault = $true
    $AclFindings = @()
    [hashtable]$AclResults = @{}

    Switch ($Type) {
        "FileSystem" {
            # Any SIDs in DefaultAcl must first be resolved
            $i = 0
            ForEach ($Acl in $DefaultAcl) {
                Try {
                    If ($Acl.Split(":")[0] -match "^S-\d+-\d+-\d+-\d+") {
                        $SID = $Acl.Split(":")[0]
                        $Rights = $Acl.Split(":")[1]
                        # Resolve SID
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
                        $Identity = $objSID.Translate( [System.Security.Principal.NTAccount]).Value

                        $DefaultAcl[$i] = "$($Identity):$($Rights)"
                    }
                    $i++
                }
                Catch {
                    # Do Nothing
                }
            }

            $AclList = icacls $Path
            $AclList = $AclList.Replace($Path, "").Trim() | Select-Object -Index (0..$(($AclList | Measure-Object).Count - 3))
            $AclEnum = @()
            ForEach ($Acl in $AclList) {
                $Rights = ""
                $Identity = $Acl.Split(":")[0]
                $Flags = $Acl.Split(":")[1].Trim()
                ForEach ($Flag in $Flags.Split(")").Replace("(", "")) {
                    If ($Flag -ne "") {
                        $Rights += "("
                        If ($Flag -match ",") {
                            $Multiflags = $Flag.Split(",")
                            $Rights += ($Multiflags | Where-Object { $_ -ne "S" }) -join "," # Ignore the Synchronize (S) flag which can be part of the ACL - especially when configured via group policy
                        }
                        Else {
                            $Rights += $Flag
                        }
                        $Rights += ")"
                    }
                }
                $AclEnum += "$($Identity):$($Rights)"
            }

            # Check default permissions exist
            ForEach ($Acl in $DefaultAcl) {
                If ($Acl -notin $AclEnum) {
                    $IsDefault = $false
                    $AclFindings += $Acl + " - Missing Default Rule"
                }
            }

            # Check for non-default permissions
            ForEach ($Acl in $AclEnum) {
                If ($Acl -notin $DefaultAcl) {
                    $IsDefault = $false
                    $AclFindings += $Acl + " - Non-Default Rule"
                }
            }
        }
        "Registry" {
            # Any SIDs in DefaultAcl must first be resolved
            $i = 0
            ForEach ($Acl in $DefaultAcl) {
                If ($Acl.IdentityReference -match "^S-\d+-\d+-\d+-\d+") {
                    Try {
                        # Resolve SID
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier($Acl.IdentityReference)
                        $Identity = $objSID.Translate( [System.Security.Principal.NTAccount]).Value

                        $DefaultAcl[$i].IdentityReference = $Identity
                    }
                    Catch {
                        # Do Nothing
                    }
                }
                $i++
            }

            #Default ACL is to always be written as if only 1 ACL per acct exist
            <#
	        Translation of permissions:
		        Applies to 						                | Inheritance Flags 	| Propagation Flags
		        ------------------------------------------------------------------------------
		        "This key (folder) only" 						| "None" 				| "None"
		        "This key (folder) and subkeys (subfolders)" 	| "ContainerInherit"	| "None"
		        "Subkeys (subfolders) only"						| "ContainerInherit"	| "InheritOnly"

	        Translation of properties:
		        STIG / GUI Option Name	| PowerShell Option Name
		        --------------------------------------------------------------
		        Principal			| IdentityReference
		        Type 				| AccessControlType
		        Access 				| RegistryRights
		        Read Access			| ReadKey

	        RegistryRights can hold multiple values and sometimes create multiple entries for the same ACL when querying.
	        Specifically, the RegistryRights can be returned as a human readable string (ReadOnly, FullControl) or as a Two's Complement number.
	        The Two's compliment aligns with the permissions described in the "Access Mask Format" in Windows Documentation
	        (https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format)

	        Permission Values of Interest:
		        Two's Complement	| Human Readable Equivalent
		        -----------------------------------------------------------
			        -2147483648		| 	Read (Called "ReadKey" for registry keys)
			        -1610612736		| 	Read + Execute
			        1073741824		| 	Write
			        268435456		| 	FullControl





	        DEFINITION OF A 'SPLIT ACL'
		        A split ACL can sometimes occur when a permission has been applied to "this key (folder) and subkeys (subfolders)".
		        The Get-ACL cmdlet will sometimes return a single ACL, as expected with inheritanceFlags = ContainerInherit and propagationFlags = None,
		        but other times will return two ACLs. One ACL will have inheritanceFlags = ContainerInherit and propagationFlags = InheritOnly;
		        the other ACL will have inheritanceFlags = None and propagationFlags = None), which when combined apply the expected permissions.
	        #>

            $Hive = $Path.Replace("HKLM:\", "")
            If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
                $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$($Hive)", "Default", "ReadPermissions")
                $CollectedAcl = $Key.GetAccessControl() | Select-Object -ExpandProperty Access | Sort-Object IdentityReference
            }
            Else {
                $PSCommand = 'PowerShell.exe -NoProfile -Command {$Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("'+$Hive+'", "Default", "ReadPermissions"); $Key.GetAccessControl() | Select-Object -ExpandProperty Access | Sort-Object IdentityReference}'
                $CollectedAcl = Invoke-Expression $PSCommand
            }

            $CurrentAcl = New-Object System.Collections.Generic.List[System.Object]
            ForEach ($Obj in $CollectedAcl) {
                $NewObj = New-Object -TypeName PsObject
                ForEach ($Prop in ($Obj | Get-Member -MemberType Properties).Name) {
                    If ("Value" -in ($Obj.$Prop | Get-Member -MemberType Properties).Name) {
                        $NewObj | Add-Member -MemberType NoteProperty -Name $Prop -Value $Obj.$Prop.Value
                    }
                    Else {
                        $NewObj | Add-Member -MemberType NoteProperty -Name $Prop -Value $Obj.$Prop
                    }
                }
                $CurrentAcl.Add($NewObj)
            }

            $CurrentRightsType = ($CurrentAcl | Get-Member * | Where-Object Name -Like "*Rights").Name
            $DefaultRightsType = ($DefaultAcl | Get-Member * | Where-Object Name -Like "*Rights").Name

            #-------------------------
            #Access Rights Translation
            #-------------------------
            $TranslatedACL = New-Object System.Collections.Generic.List[System.Object]
            ForEach ($Obj in $CurrentAcl) {
                #Translate all Two's Compliment Rights into human readable rights
                If ($Obj.$CurrentRightsType -Match "^-?\d+$") {
                    #If the RightsType is a number
                    Switch ($Obj.$CurrentRightsType) {
                        -2147483648 {
                            If ($CurrentRightsType -eq "RegistryRights") {
                                $TranslatedRightsType = "ReadKey"
                            }
                            Else {
                                $TranslatedRightsType = "Read"
                            }
                        }
                        -1610612736 {
                            If ($CurrentRightsType -eq "RegistryRights") {
                                $TranslatedRightsType = "ReadKey"
                            }
                            Else {
                                $TranslatedRightsType = "ReadAndExecute"
                            }
                        }
                        1073741824 {
                            $TranslatedRightsType = "Write"
                        }
                        268435456 {
                            $TranslatedRightsType = "FullControl"
                        }
                    }
                }
                Else {
                    $TranslatedRightsType = $Obj.$CurrentRightsType
                }

                $NewObj = [PSCustomObject]@{
                    $($CurrentRightsType) = $TranslatedRightsType
                    AccessControlType     = $($Obj.AccessControlType)
                    IdentityReference     = $($Obj.IdentityReference)
                    IsInherited           = $($Obj.IsInherited)
                    InheritanceFlags      = $($Obj.InheritanceFlags)
                    PropagationFlags      = $($Obj.PropagationFlags)
                }
                $TranslatedACL.Add($NewObj)
            }

            #----------------------------------------------
            #Combine split ACLs and update $CurrentACL
            #----------------------------------------------
            $AclList = New-Object System.Collections.Generic.List[System.Object]
            $UniqueIDs = $TranslatedACL.IdentityReference | Select-Object -Unique
            ForEach ($ID in $UniqueIDs) {
                #Used to grab unique IdentityReference
                $Rule = ($TranslatedACL | Where-Object { ($_.IdentityReference -eq $ID) -and (($_.InheritanceFlags -eq "ContainerInherit" -and $_.PropagationFlags -eq "InheritOnly") -or ($_.InheritanceFlags -eq "None" -and $_.PropagationFlags -eq "None")) }) #Query for split ACLs
                If (($Rule | Measure-Object).Count -eq 2) {
                    #If the ACL is split (this key only + subkeys only)
                    #If the two records match in all but InhertianceFlags and PropagationFlags
                    If (($Rule[0].$CurrentRightsType -eq $Rule[1].$CurrentRightsType) -and ($Rule[0].IsInherited -eq $Rule[1].IsInherited) -and ($Rule[0].AccessControlType -eq $Rule[1].AccessControlType)) {
                        #New Combined ACL object (Applies to this key and subkeys)
                        $NewObj = [PSCustomObject]@{
                            $($CurrentRightsType) = $Rule[0].$CurrentRightsType
                            AccessControlType     = $Rule[0].AccessControlType
                            IdentityReference     = $Rule[0].IdentityReference
                            IsInherited           = $Rule[0].IsInherited
                            InheritanceFlags      = "ContainerInherit"
                            PropagationFlags      = "None"
                        }
                        $AclList.Add($NewObj)
                    }
                }
                Else {
                    $Rule = ($TranslatedACL | Where-Object { ($_.IdentityReference -eq $ID) })
                    ForEach ($r in $Rule) {
                        $NewObj = [PSCustomObject]@{
                            $($CurrentRightsType) = $($r.$CurrentRightsType)
                            AccessControlType     = $($r.AccessControlType)
                            IdentityReference     = $($r.IdentityReference)
                            IsInherited           = $($r.IsInherited)
                            InheritanceFlags      = $($r.InheritanceFlags)
                            PropagationFlags      = $($r.PropagationFlags)
                        }
                        $AclList.Add($NewObj)
                    }
                }
            }

            #--------------------------
            #Proceed as normal
            #--------------------------
            # Look for missing default rules
            ForEach ($Object in $DefaultAcl) {
                If ($Object.Mandatory -eq $true -and (-Not($AclList | Where-Object { ($_.IdentityReference -eq $Object.IdentityReference) -and ($_.$($CurrentRightsType) -eq $Object.$($DefaultRightsType)) -and ($_.AccessControlType -eq $Object.AccessControlType) -and ($_.InheritanceFlags -eq $Object.InheritanceFlags) -and ($_.PropagationFlags -in $Object.PropagationFlags) }))) {
                    $IsDefault = $false
                    $AclObj = New-Object -TypeName PsObject
                    $AclObj | Add-Member -MemberType NoteProperty -Name "Reason" -Value "Missing Default Rule"
                    $AclObj | Add-Member -MemberType NoteProperty -Name "$($DefaultRightsType)" -Value $Object.$($DefaultRightsType)
                    $AclObj | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $Object.AccessControlType
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $Object.IdentityReference
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $Object.IsInherited
                    $AclObj | Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $Object.InheritanceFlags
                    $AclObj | Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value ($Object.PropagationFlags -Join " or ")
                    $AclFindings += $AclObj
                }
            }

            # Compare rules
            ForEach ($Object in $AclList) {
                If (-Not($DefaultAcl | Where-Object { ($_.IdentityReference -eq $Object.IdentityReference) -and ($_.$($DefaultRightsType) -contains $Object.$($CurrentRightsType)) -and ($_.AccessControlType -eq $Object.AccessControlType) -and ($_.InheritanceFlags -contains $Object.InheritanceFlags) -and ($_.PropagationFlags -contains $Object.PropagationFlags) })) {
                    # Look for unexpected rule
                    $IsDefault = $false
                    $AclObj = New-Object -TypeName PsObject
                    $AclObj | Add-Member -MemberType NoteProperty -Name "Reason" -Value "Non-Default Rule"
                    $AclObj | Add-Member -MemberType NoteProperty -Name "$($CurrentRightsType)" -Value $Object.$($CurrentRightsType)
                    $AclObj | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $Object.AccessControlType
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $Object.IdentityReference
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $Object.IsInherited
                    $AclObj | Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $Object.InheritanceFlags
                    $AclObj | Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value $Object.PropagationFlags
                    $AclFindings += $AclObj
                }
            }
        }
    }

    $AclResults.IsDefault = $IsDefault
    $AclResults.AclFindings = $AclFindings
    $AclResults.Acl = $AclList
    Return $AclResults
}

Function Confirm-CompliantAcl {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("FileSystem")]
        [String]$Type,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [psobject]$ExpectedAcl,

        [Parameter(Mandatory = $false)]
        [String]$OthersMaxPermission,

        [Parameter(Mandatory = $false)]
        [Switch]$ReturnAll
    )

    Try {
        $Compliant = $true

        $ValidPermissions = @(
            'FullControl', 'Modify', 'Write', 'Write', 'ReadAndExecute', 'Read', # Basic Permissions
            'CreateFiles', 'AppendData', 'WriteAttributes', 'WriteExtendedAttributes', 'DeleteSubdirectoriesAndFiles', 'Delete', 'ReadData', 'ReadAttributes', 'ReadExtendedAttributes', 'ExecuteFile', 'ChangePermissions', 'ReadPermissions', 'TakeOwnership', 'Synchronize' # Advanced Permissions
        )

        # Confirm specified permissions values are valid
        ForEach ($Item in $ExpectedAcl.Access) {
            If ($Item -notin $ValidPermissions) {
                Throw "'$Item' is not a valid permission."
            }
        }
        If ($OthersMaxPermission -and $OthersMaxPermission -notin $ValidPermissions) {
            Throw "'$OthersMaxPermission' is not a valid permission."
        }

        # Assign numerical values for permissions
        $AdvPermissions = @{
            CreateFiles                  = [int]4096
            AppendData                   = [int]2048
            WriteAttributes              = [int]1024
            WriteExtendedAttributes      = [int]512
            DeleteSubdirectoriesAndFiles = [int]256
            Delete                       = [int]128
            ReadData                     = [int]64
            ReadAttributes               = [int]32
            ReadExtendedAttributes       = [int]16
            ExecuteFile                  = [int]8
            ChangePermissions            = [int]4
            ReadPermissions              = [int]2
            TakeOwnership                = [int]1
            Synchronize                  = [int]0
        }

        # Assign numerical values for basic permissions based on advanced permissions that a enabled
        $BasPermissions = @{
            FullControl    = [int]8191
            Modify         = [int]7930
            Write          = [int]7680
            ReadAndExecute = [int]122
            Read           = [int]114
        }

        # Build master list of permissions
        $PermissionList = @{}
        ForEach ($Key in $BasPermissions.Keys) {
            $PermissionList.Add($Key, $BasPermissions.$Key)
        }
        ForEach ($Key in $AdvPermissions.Keys) {
            $PermissionList.Add($Key, $AdvPermissions.$Key)
        }

        <#
        RegistryRights can hold multiple values and sometimes create multiple entries for the same ACL when querying.
	    Specifically, the RegistryRights can be returned as a human readable string (ReadOnly, FullControl) or as a Two's Complement number.
	    The Two's compliment aligns with the permissions described in the "Access Mask Format" in Windows Documentation
	    (https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format)

	    Permission Values of Interest:
		    Two's Complement	| Human Readable Equivalent
		    -----------------------------------------------------------
			    -2147483648		| 	Read (Called "ReadKey" for registry keys)
			    -1610612736		| 	Read + Execute
			    1073741824		| 	Write
			    268435456		| 	FullControl
        #>

        # Get current ACL.  Ignore Deny rules as STIG does not call those out and it really complicates things
        $CurrentAcl = New-Object System.Collections.Generic.List[System.Object]
        ForEach ($Acl in ((Get-Acl -Path $Path).AccessToString -split "`n" | Where-Object {$_ -notmatch "\sDeny\s"})) {
            $Rule = ($Acl -split "Allow").Trim()
            $NewObj = [PSCustomObject]@{
                Principal = $Rule[0]
                Access    = $Rule[1].Split(",").Trim() -replace "-2147483648", "Read" -replace "-1610612736", "ReadAndExecute" -replace "1073741824", "Write" -replace "268435456", "FullControl" | Select-Object -Unique
            }
            $CurrentAcl.Add($NewObj)
        }

        # Compare current ACL against expected ACL
        $Result = New-Object System.Collections.Generic.List[System.Object]

        ForEach ($Rule in $CurrentAcl) {
            $RuleCompliant = $true
            [int]$MaxRuleValue = 0
            [int]$CurrentValue = 0

            $PrincipalToEval = $ExpectedAcl | Where-Object {$_.Principal -eq $Rule.Principal}
            If ($PrincipalToEval) {
                # Calculate maximum allow access level
                ForEach ($Item in $PrincipalToEval.Access) {
                    $MaxRuleValue = $MaxRuleValue + $PermissionList.$Item
                }

                # Calculate current allow access level for principals called out by STIG
                ForEach ($Item in $Rule.Access) {
                    $CurrentValue = $CurrentValue + $PermissionList.$Item
                }
            }
            ElseIf ($OthersMaxPermission) {
                # Calculate current allow access level for other principals
                $MaxRuleValue = $MaxRuleValue + $PermissionList.$OthersMaxPermission

                # Calculate current allow access level
                ForEach ($Item in $Rule.Access) {
                    $CurrentValue = $CurrentValue + $PermissionList.$Item
                }
            }
            Else {
                # No other principals are allowed per STIG so CurrentValue will be higher than MaxValue and ensure non-compliance is returned
                # Calculate current allow access level
                ForEach ($Item in $Rule.Access) {
                    $CurrentValue = $CurrentValue + $PermissionList.$Item
                }
            }

            # Compare CurrentValue to MaxRuleValue.  If larger, this is non-compliant
            If ($CurrentValue -gt $MaxRuleValue) {
                $Compliant = $false
                $RuleCompliant = $false
            }

            # Add rule to results
            $NewObj = [PSCustomObject]@{
                Principal = $Rule.Principal
                Access    = $Rule.Access
                Compliant = $RuleCompliant
            }
            $Result.Add($NewObj)
        }

        If ($Compliant) {
            If ($ReturnAll) {
                Return $Result | Select-Object * -Unique
            }
            Else {
                Return $Compliant
            }
        }
        Else {
            If ($ReturnAll) {
                Return $Result | Select-Object * -Unique
            }
            Else {
                Return $Result | Where-Object Compliant -NE $true | Select-Object * -Unique
            }
        }
    }
    Catch {
        Throw $_.Exception.Message
    }
}

Function Get-ESBestAnswerKey {
    <#
    .SYNOPSIS
        Internal helper to select the single, best-fit AnswerKey object that applies to the target currently being evaluated.
    .DESCRIPTION
        Function is **NOT** meant for direct user consumption; keep it un-exported in the module (or dot-source).
        Callers pass:
            $AnswerData: deserialized answer file that contains .AnswerKey[]
            $Status    : status Evaluate-STIG produced from the check
            $Context   : a single PSCustomObject whose properties mirror the attributes desired to match against the key (Name, Hostname, Instance, Database, Site, ResultHash)

        A key is eligible when *every populated attribute* in the key matches the same property in $Context.
        When several keys match, a weighted score favors more specific keys:

        The function returns the AnswerKey object itself (or $null when nothing matches)
    .PARAMETER AnswerData
        The object that holds the array property .AnswerKey produced by reading the answer file.
    .PARAMETER Status
        The evaluation status for the current check (e.g. 'Open', 'NotAFinding', 'NotReviewed', 'NotApplicable').
        Only keys whose ExpectedStatus equals this value are considered.
    .PARAMETER Context
        A [PSCustomObject] that contains a subset of these properties:
            Name (AnswerKey), Hostname, Instance, Database, Site, ResultHash
        Missing or misspelled properties throw a terminating error so bugs surface early.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .EXAMPLE
        $ctx = @{
            Name       = $AnswerKey
            Hostname   = $env:COMPUTERNAME
            Instance   = $SqlInstance
            Database   = $DbName
            Site       = $SiteCode
            ResultHash = $Hash
        }

        $key = Get-ESBestAnswerKey -AnswerData $ad -Status 'Open' -Context $ctx
    #>
    [CmdletBinding()]
    Param (
        # Content from a given answer file
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $AnswerData,

        # Status from Evaluate-STIG. Compare against $ExpectedStatus from Answer File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Status,

        # List of properties to weigh
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject]$Context
    )

    # List of attributes and their weights. Ensure to edit this if it changes!
    $Weights = [ordered]@{
        Hostname   = 5
        Instance   = 4
        Database   = 3
        Site       = 2
        ResultHash = 1
        Name       = 16
    }

    # Guardrail to ensure the caller supplied required properties. Doesn't care if they're $null or empty.
    ForEach ($Attr in $Weights.Keys) {
        If (-not $Context.PSObject.Properties.Match($Attr)) {
            Throw "Context object is missing required property '$Attr'."
        }
    }

    $MaxPossibleWeight = ($Weights.Values | Measure-Object -Sum).Sum
    $BestWeight = -1
    $BestMatch = $null

    ForEach ($AnswerKey in $AnswerData.AnswerKey) {
        ForEach ($Answer in $AnswerKey.Answer) {
            # Initialize MatchInfo object
            $MatchInfo = [System.Collections.Generic.List[System.Object]]::new()


            # 1.) Filter on the Status early
            If ($Status -ne (Convert-Status -InputObject $Answer.ExpectedStatus -Output CKL)) {
                Continue
            }
            Else {
                $NewObj = [PSCustomObject]@{
                    ConfiguredAttribute = "ExpectedStatus"
                    ConfiguredData      = $Answer.ExpectedStatus
                    MatchedData         = $Status
                    ValidInContext      = $true
                    AttributeWeight     = 0
                }
                $MatchInfo.Add($NewObj)
            }

            # 2.) Normalize the key's attributes into arrays of trimmed strings
            $KeyAttributes = @{
                Name       = $AnswerKey.Name
                Hostname   = $Answer.Hostname
                Instance   = $Answer.Instance
                Database   = $Answer.Database
                Site       = $Answer.Site
                ResultHash = $Answer.ResultHash
            }.GetEnumerator() | ForEach-Object {
                $_.Value = ($_.Value -split ',' | ForEach-Object { $_.Trim() })
                $_
            }

            # 3.) Evaluate each attribute in precedence order
            $Weight = 0
            $AllMatch = $true

            Foreach ($Attr in $Weights.Keys) {
                $KeyValues = ($KeyAttributes | Where-Object Name -EQ $Attr).Value
                If (-not $KeyValues) {
                    Continue
                } # Skip if the $attr is NOT specified in the key.

                $Current = $Context.$Attr

                If ($Attr -eq 'Name') {
                    # Special handling for DEFAULT AnswerKey
                    If (($Current -notin $KeyValues) -and ('DEFAULT' -notin $KeyValues)) {
                        $Allmatch = $false
                        Break
                    }
                    If ($Current -in $KeyValues) {
                        If ($Current -ne "DEFAULT") {
                            $NewObj = [PSCustomObject]@{
                                ConfiguredAttribute = $Attr
                                ConfiguredData      = $KeyValues
                                MatchedData         = $Current
                                ValidInContext      = $true
                                AttributeWeight     = $Weights[$Attr]
                            }
                            $MatchInfo.Add($NewObj)
                            $Weight += $Weights[$Attr]
                        }
                    }
                }
                ElseIf ($Current -in $KeyValues) {
                    $NewObj = [PSCustomObject]@{
                        ConfiguredAttribute = $Attr
                        ConfiguredData      = $Answer.$Attr
                        MatchedData         = $Current
                        ValidInContext      = $true
                        AttributeWeight     = $Weights[$Attr]
                    }
                    $MatchInfo.Add($NewObj)
                    $Weight += $Weights[$Attr]
                }
                ElseIf ($Current -in @($null, "")) {
                    $NewObj = [PSCustomObject]@{
                        ConfiguredAttribute = $Attr
                        ConfiguredData      = $Answer.$Attr
                        MatchedData         = "No match needed"
                        ValidInContext      = $false
                        AttributeWeight     = 0
                    }
                    $MatchInfo.Add($NewObj)
                    # Attribute is not valid in this context so do nothing - even if the attribute is configured in the answer file
                }
                Else {
                    $AllMatch = $false
                    Break
                }
            }
            If (-not $AllMatch) {
                Continue
            }

            # 4.) Keep the best scoring key (so far)
            If ($Weight -gt $BestWeight) {
                $BestWeight = $Weight

                # Put key data into hashtable
                $BestMatch = [ordered]@{
                    KeyName           = $AnswerKey.Name
                    Index             = $Answer.Index
                    ExpectedStatus    = $Status
                    ValidationCode    = $Answer.ValidationCode
                    ValidTrueStatus   = $Answer.ValidTrueStatus
                    ValidTrueComment  = $Answer.ValidTrueComment
                    ValidFalseStatus  = $Answer.ValidFalseStatus
                    ValidFalseComment = $Answer.ValidFalseComment
                    TotalWeight       = $Weight
                }

                $BestMatchResult = [PSCustomObject]@{
                    BestMatch = $BestMatch
                    MatchInfo = $MatchInfo
                }

                If ($BestWeight -eq $MaxPossibleWeight) {
                    Break
                } # perfect match - done
            }
        }
    }

    Return $BestMatchResult
}

Function Get-CorporateComment {
    # Function for getting standarized comments from answer file.

    # Added parameter UseSubProc, defaulted to $false, to control whether a fresh powershell.exe will be created to do the test. -- Ken Row, 9/12/25

    Param (
        [Parameter(Mandatory = $true)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$VulnID = "",

        [Parameter(Mandatory = $false)]
        [String]$RuleID = "",

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Not_Reviewed", "Open", "NotAFinding", "Not_Applicable")]
        [String]$Status = "Not_Reviewed",

        [Parameter(Mandatory = $false)]
        [String]$Hostname,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$Site,

        [Parameter(Mandatory = $false)]
        [String]$ResultHash,

        [Parameter(Mandatory = $false)]
        [psobject]$ResultData,

        [Parameter(Mandatory = $true)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [parameter(Mandatory = $false)]
        [boolean]$UseSubProc = $false,

        [parameter(Mandatory = $false)]
        [switch]$UnsupportedCheck
    )

    $ErrorActionPreference = "SilentlyContinue"

    $AnswerResults = @{
        AFKey          = ""
        AFComment      = ""
        ExpectedStatus = ""
        AFStatus       = ""
    }

    Try {
        # Look for Check that equals VulnID or RuleID.  If multiple, get first only.  Answer files should commit to either using VulnID or RuleID - not both.
        $AnswerData = (Select-Xml -Path $($AnswerFile -replace ("'", "")) -XPath "/" | Select-Object -ExpandProperty Node).STIGComments.Vuln | Where-Object ID -In @($VulnID, $RuleID) | Select-Object -First 1
        If ($AnswerData) {
            $Context = @{
                Name       = $AnswerKey
                Hostname   = $Hostname
                Instance   = $Instance
                Database   = $Database
                Site       = $Site
                ResultHash = $ResultHash
            }

            $KeyToProcess = Get-ESBestAnswerKey -AnswerData $AnswerData -Status $Status -Context $Context

            # If a valid key was identified, continue processing
            If ($KeyToProcess) {
                If ($UnsupportedCheck) {
                    if ($UnsupportedCheck) {
                        Write-Log -Path $LogPath -Message "Group ID : $($Vuln.ID)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                }
                Write-Log -Path $LogPath -Message "    Answer key '$($KeyToProcess.BestMatch.KeyName)', index '$($KeyToProcess.BestMatch.Index)' selected.  Weight: $($KeyToProcess.BestMatch.TotalWeight)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "    Match info: $($KeyToProcess.MatchInfo | Format-List | Out-String)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                $AnswerResults.AFKey = $KeyToProcess.BestMatch.KeyName
                $AnswerResults.ExpectedStatus = $KeyToProcess.BestMatch.ExpectedStatus

                # If <ValidationCode> is configured, execute it to determine which Status|Comment to apply
                If ($KeyToProcess.BestMatch.ValidationCode) {
                    # Create scriptblock to include Eval-STIG variables and ValidationCode
                    if ($UseSubProc) {
                        $PSCommand = '
                            Try {
                                $ErrorActionPreference = "Stop"
                                Set-Variable ESPath -Value  "' + $ESPath + '"
                                Set-Variable ExpectedStatus -Value  "' + $Status + '"
                                Set-Variable ResultHash -Value  "' + $ResultHash + '"
                                Set-Variable ResultData -Value  "' + $($ResultData -replace '"',"'") + '"
                                Set-Variable Hostname -Value  "' + $Hostname + '"
                                Set-Variable Username -Value  "' + $Username + '"
                                Set-Variable UserSID -Value "' + $UserSID + '"
                                Set-Variable Instance -Value "' + $Instance + '"
                                Set-Variable Database -Value "' + $Database + '"
                                Set-Variable Site -Value "' + $Site + '"
                                Import-Module (Join-Path -Path $ESPath -ChildPath Modules | Join-Path -ChildPath Master_Functions)
                                ' + $KeyToProcess.BestMatch.ValidationCode + '
                            }
                            Catch {
                                $ValidationResults = @{
                                    Valid   = $False
                                    Results = "ERROR: $($_.Exception.Message)"
                                }
                                Return $ValidationResults
                            }
                        '
                    }
                    else {
                        $PSCommand = '
                            Try {
                                $ErrorActionPreference = "Stop"
                                Set-Variable ExpectedStatus -Value  "' + $Status + '"
                                Import-Module (Join-Path -Path $ESPath -ChildPath Modules | Join-Path -ChildPath Master_Functions)
                                ' + $KeyToProcess.BestMatch.ValidationCode + '
                            }
                            Catch {
                                $ValidationResults = @{
                                    Valid   = $False
                                    Results = "ERROR: $($_.Exception.Message)"
                                }
                                Return $ValidationResults
                            }
                        '
                    } # if ($UseSubProc)/$PSCommand

                    $PSScriptBlock = [scriptblock]::Create($PSCommand)
                    Write-Log -Path $LogPath -Message "    Executing Answer File ValidationCode" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    # Execute the ValidationCode and compare the output
                    if ($UseSubProc) {
                        # Set the Powershell executable to execute
                        Switch ($PSVersionTable.PSVersion.Major) {
                            "5" {
                                $PSEXE = Join-Path -Path $PSHome -ChildPath "powershell.exe"
                            }
                            "7" {
                                $PSEXE = Join-Path -Path $PSHome -ChildPath ('pwsh{0}' -f $(if ($IsWindows) { '.exe' }))
                            }
                        }

                        $ValidationResult = & $PSEXE -NoProfile -Command $PSScriptBlock
                    }
                    else {
                        $ValidationResult = & $PSScriptBlock
                    } # if ($UseSubProc)/Switch

                    Switch ($ValidationResult.GetType().Name) {
                        "Boolean" {
                            Write-Log -Path $LogPath -Message "    ValidationResult: $ValidationResult" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            $ValidationCodeResults = "[Validation Code Results]:`r`n$($ValidationResult)"
                            $Validated = $ValidationResult
                        }
                        {$_ -eq "Hashtable" -and "Valid" -in $ValidationResult.Keys -and "Results" -in $ValidationResult.Keys} {
                            # If output is hashtable, must be object that contains "Valid" and "Results" entries.  "Valid" must be [Bool] type and is evaluated against <ValidationResult>
                            If ($ValidationResult.Results -match "^ERROR:") {
                                Write-Log -Path $LogPath -Message "    ValidationResult: $($ValidationResult.Results)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                            Else {
                                Write-Log -Path $LogPath -Message "    ValidationResult: $($ValidationResult.Results)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            }
                            $ValidationCodeResults = "[Validation Code Results]:`r`n$($ValidationResult.Results)"
                            $Validated = $ValidationResult.Valid
                        }
                        {$_ -eq "PSCustomObject" -and "Valid" -in ($ValidationResult | Get-Member).Name -and "Results" -in ($ValidationResult | Get-Member).Name} {
                            # PSCustomObject is legacy answer file format.  Warn to update as hashtable.
                            Write-Log -Path $LogPath -Message "    ValidationCode object is a PSCustomObject.  Please convert to Hashtable to ensure compatibility." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            if ($ValidationResult.Results -match "^ERROR:") {
                                Write-Log -Path $LogPath -Message "    ValidationResult: $($ValidationResult.Results)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                            else {
                                Write-Log -Path $LogPath -Message "    ValidationResult: $($ValidationResult.Results)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            }
                            $ValidationCodeResults = "[Validation Code Results]:`r`n$($ValidationResult.Results)"
                            $Validated = $ValidationResult.Valid
                        }
                        DEFAULT {
                            Write-Log -Path $LogPath -Message "    Invalid ValidationCode object returned.  Must be either boolean or hashtable with 'Valid' (boolean) and 'Results' keys." -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }
                    }

                    If ($Validated -eq $true) {
                        If ($KeyToProcess.BestMatch.ValidTrueStatus -eq "") {
                            $AnswerResults.AFStatus = $Status
                        }
                        Else {
                            $AnswerResults.AFStatus = (Convert-Status -InputObject $KeyToProcess.BestMatch.ValidTrueStatus -Output CKL)
                        }
                        $AnswerResults.AFComment = "Answer File: $($AnswerFile)`r`nKey Name: $($KeyToProcess.BestMatch.KeyName)`r`nIndex: $($KeyToProcess.BestMatch.Index)`r`n`r`n[ValidTrueComment]:`r`n$($KeyToProcess.BestMatch.ValidTrueComment)`r`n`r`n$($ValidationCodeResults)" | Out-String
                    }
                    Else {
                        If ($KeyToProcess.BestMatch.ValidFalseStatus -eq "") {
                            $AnswerResults.AFStatus = $Status
                        }
                        Else {
                            $AnswerResults.AFStatus = (Convert-Status -InputObject $KeyToProcess.BestMatch.ValidFalseStatus -Output CKL)
                        }
                        $AnswerResults.AFComment = "Answer File: $($AnswerFile)`r`nKey Name: $($KeyToProcess.BestMatch.KeyName)`r`nIndex: $($KeyToProcess.BestMatch.Index)`r`n`r`n[ValidFalseComment]:`r`n$($KeyToProcess.BestMatch.ValidFalseComment)`r`n`r`n$($ValidationCodeResults)" | Out-String
                    }
                }
                Else {
                    If ($KeyToProcess.BestMatch.ValidTrueStatus -eq "") {
                        $AnswerResults.AFStatus = $Status
                    }
                    Else {
                        $AnswerResults.AFStatus = (Convert-Status -InputObject $KeyToProcess.BestMatch.ValidTrueStatus -Output CKL)
                    }
                    $AnswerResults.AFComment = "Answer File: $($AnswerFile)`r`nKey Name: $($KeyToProcess.BestMatch.KeyName)`r`nIndex: $($KeyToProcess.BestMatch.Index)`r`n`r`n[ValidTrueComment]:`r`n$($KeyToProcess.BestMatch.ValidTrueComment)" | Out-String
                }
            }
            Else {
                $AnswerResults = $null
            }
        }
        Else {
            $AnswerResults = $null
        }
    }
    Catch {
        $AnswerResults = $null
        $ErrorData = $_ | Get-ErrorInformation
        If ($LogPath -and (Test-Path $LogPath)) {
            ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                Write-Log -Path $LogPath -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
        }
    }

    Return $AnswerResults
} # Function Get-CorporateComment

Function Format-AnswerData {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$ResultStatus,

        [Parameter(Mandatory = $true)]
        [String]$AFKey,

        [Parameter(Mandatory = $true)]
        [String]$AFStatus,

        [Parameter(Mandatory = $true)]
        [String]$AFComment,

        [Parameter(Mandatory = $true)]
        [String]$LogPath
    )

    $Result = @{}
    $Comments = ""
    $STIGManMetaData = [ordered]@{}

    Write-Log -Path $LogPath -Message "    Adding Comment from answer file for Key '$($AFKey)'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

    If ($AFStatus -ne $ResultStatus) {
        $PreComment = "Evaluate-STIG answer file is changing the Status from '$($ResultStatus)' to '$($AFStatus)' and providing the below comment on $($ScanStartDate):`r`n" | Out-String
        Write-Log -Path $LogPath -Message "    Answer file for Key '$($AFKey)' is changing the Status from '$($ResultStatus)' to '$($AFStatus)'" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform

        # Set Metadata for STIGMAN
        $STIGManMetaData = [ordered]@{
            AnswerFile = $(Split-Path $ModuleArgs.AnswerFile -Leaf).TrimEnd('"').TrimEnd("'")
            LastWrite  = $(Get-Date (Get-ChildItem $($ModuleArgs.AnswerFile -replace "(^'|'$)")).LastWriteTime -Format 'o')
            AFMod      = $true
            OldStatus  = $(Convert-Status -InputObject $ResultStatus -Output XCCDF)
            NewStatus  = $(Convert-Status -InputObject $AFStatus -Output XCCDF)
        }
    }
    Else {
        $PreComment = "Evaluate-STIG answer file is providing the below comment on $($ScanStartDate):`r`n" | Out-String
    }

    # Set the final comment data
    [String]$Comments = $PreComment + $AFComment
    # Truncate Comment if over 32667 characters
    If (($Comments | Measure-Object -Character).Characters -gt 32667) {
        $Comments = $Comments.Substring(0, [System.Math]::Min(32617, $Comments.Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
    }

    $Result.Add("Comments",$Comments)
    $Result.Add("STIGManMetaData",$STIGManMetaData)
    Return $Result
}

Function Get-ErrorInformation {
    <#
    .SYNOPSIS
        Parses the provided Error Record for useful information and outputs as PSCustomObject
    .DESCRIPTION
        Function that ingests a single Error Record and parses out useful information to include the Exception Message, Exception Type, Script Name, Script Line Number, the command and, if available, the Target Object of the failed line.
    .NOTES
        Springboarded off GngrNinja
            https://www.gngrninja.com/script-ninja/2016/6/5/powershell-getting-started-part-11-error-handling
    .LINK
    .EXAMPLE
        Get-ErrorInformation -IncomingError $Error[0]
        Ingests the first error in the automatic variable $Error and outputs useful properties.
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory)]
        [System.Management.Automation.ErrorRecord]$IncomingError,

        [Parameter(Mandatory = $false)]
        [Switch]$IncludeRawError
    )
    process {
        $e  = $IncomingError
        $ex = $e.Exception

        # Unwrap common wrappers
        if ($ex -is [System.Management.Automation.ActionPreferenceStopException] -and $ex.InnerException) {
            $ex = $ex.InnerException
        }
        if ($ex -is [System.AggregateException]) {
            $flat = $ex.Flatten()
            if ($flat.InnerExceptions.Count) { $ex = $flat.InnerExceptions[0] }
        }

        # Safe pulls (InvocationInfo can be null)
        $inv      = $e.InvocationInfo
        $script   = if ($inv) { $inv.ScriptName } else { $null }
        $lineNum  = if ($inv) { $inv.ScriptLineNumber } else { $null }
        $column   = if ($inv) { $inv.OffsetInLine } else { $null }
        $lineText = if ($inv -and $inv.Line) { $inv.Line.Trim() } else { $null }

        $msg      = if ($ex) { $ex.Message } else { $e.ToString() }
        $exType   = if ($ex) { $ex.GetType().FullName } else { $null }
        $hresult  = if ($ex) { '0x{0:X8}' -f $ex.HResult } else { $null }
        #$stack    = if ($ex) { $ex.StackTrace } else { $null }

        $ErrorPSObject = [pscustomobject]@{
            TimeStamp        = Get-Date
            Message          = $msg
            Category         = $e.CategoryInfo.Category
            Reason           = $e.CategoryInfo.Reason
            TargetName       = $e.TargetObject
            FullyQualified   = $e.FullyQualifiedErrorId
            ScriptName       = $script
            Line             = $lineNum
            Column           = $column
            LineText         = $lineText
            ExceptionType    = $exType
            HResult          = $hresult
            #StackTrace     = $stack
            ScriptStackTrace = $e.ScriptStackTrace
            WasTerminating   = $e.CategoryInfo.Activity -eq 'Throw'
            Computer         = $env:COMPUTERNAME
        }

        $PSCallStack = Get-PSCallStack
        If ($PSCallStack) {
            $ParentFunctionName = $PSCallStack[1].FunctionName
            $ErrorPSObject |
                Add-Member -MemberType NoteProperty -Name 'ParentFunctionName' -Value $ParentFunctionName
        }

        If ($IncludeRawError) {
            $ErrorPSObject | Add-Member -MemberType NoteProperty -Name RawError -Value $e
        }

        Return $ErrorPSObject
    }
}

############################################################
## SQL Functions                                        #
############################################################
Function Get-AllInstances {
    # Generate list of valid instances.  Exclude SQL Server 2014 Express edition.
    $ValidInstances = New-Object System.Collections.Generic.List[System.Object]
    $KeysToCheck = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server")
    ForEach ($Key in $KeysToCheck) {
        $Instances = (Get-ItemProperty $Key).InstalledInstances
        ForEach ($Instance in $Instances) {
            $p = (Get-ItemProperty "$($Key)\Instance Names\SQL").$Instance
            $Edition = (Get-ItemProperty "$($Key)\$($p)\Setup").Edition
            $Version = [Version](Get-ItemProperty "$($Key)\$($p)\Setup").Version
            If (-Not($Version -like "12.0*" -and $Edition -like "*Express*")) {
                $NewObj = [PSCustomObject]@{
                    InstanceName = $Instance
                    Edition      = $Edition
                    Version      = $Version
                }
                $ValidInstances.Add($NewObj)
            }
        }
    }

    # Get instance names and service status
    $allInstances = New-Object System.Collections.Generic.List[System.Object]
    $KeysToCheck = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL")
    ForEach ($Key in $KeysToCheck) {
        If (Test-Path $Key) {
            (Get-Item $Key).GetValuenames() | Where-Object { $_ -notlike '*#*' } | ForEach-Object {
                If ($_ -in $ValidInstances.InstanceName) {
                    # Grab the version from the array built earlier
                    $tmpVersion = ($ValidInstances | Where-Object InstanceName -EQ $_).Version

                    # Determine the server Name
                    $tsname = (Get-Item $Key).GetValue($_)
                    If ($Key -like "*WOW6432Node*") {
                        If (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\$tsname\cluster") {
                            $cname = (Get-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\$tsname\cluster").GetValue('ClusterName')
                        }
                        Else {
                            $cname = $env:computername
                        }
                    }
                    Else {
                        If (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$tsname\cluster") {
                            $cname = (Get-Item "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$tsname\cluster").GetValue('ClusterName')
                        }
                        Else {
                            $cname = $env:computername
                        }
                    }

                    # Determine the Windows Service Name and Status
                    If ($_ -eq 'MSSQLSERVER') {
                        $tmpServiceName = 'MSSQLSERVER'
                        $tmpInstanceName = $cname
                    }
                    else {
                        $tmpServiceName = "mssql`$$_"
                        $tmpInstanceName = "$cname\$_"
                    }
                    $oService = Get-Service $tmpServiceName -ErrorAction SilentlyContinue
                    if ($oService) {
                        $tmpStatus = $oService.Status
                    }
                    else {
                        $tmpServiceName = "NotFound"
                        $tmpStatus = 'NA'
                    }

                    $NewObj = [PSCustomObject]@{
                        Name    = $tmpInstanceName
                        Service = $tmpServiceName
                        Status  = $tmpStatus
                        Version = $tmpVersion
                    }
                    $allInstances.Add($NewObj)
                }
            }
        }
    }
    Return $allInstances
}

Function Get-InstanceVersion {
    param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $InstanceVersion = (Get-ISQL -ServerInstance "$Instance" -Qry "select @@version").column1
    $null = $InstanceVersion -match "SQL Server \d{4}"
    $VersionToReturn = $Matches.Values -replace "[^0-9]"
    Return $VersionToReturn
}

$hashSQLConns = @{}
$SQLCONNECTIONERROR = 'Undefined'

Function Add-PortToSQLInstance {
    # New function to insert the SQL listener port number into the server\instance name. Ken Row, 5/28/25, Issue 2326

    # Replaced 'select' with 'select-object'. Ken Row, 9/29/25

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [String] $ServerInstance
    )

    if ($ServerInstance -like '*\*') {
        $tInstance = $ServerInstance -replace '^.*\\',''
        $tServer   = $ServerInstance -replace '\\.*$',''

        $s1='HKLM:\SOFTWARE'; $s2="microsoft\microsoft sql server\$tInstance\MSSQLServer\SuperSocketNetLib\Tcp"

        $port = (Get-ItemProperty "$s1\$s2","$s1\wow6432node\$s2" -Name TcpPort -ErrorAction SilentlyContinue | Select-Object TcpPort -Unique).TcpPort
        if (!($port)) {
            $port = (Get-ItemProperty "$s1\$s2","$s1\wow6432node\$s2" -Name TcpDynamicPort -ErrorAction SilentlyContinue | Select-Object TcpDynamicPort -Unique).TcpDynamicPort
        }
        if ($port) {
            return "$tServer,$port\$tInstance"
        } else {
            return $ServerInstance
        }
    } else {
        return $ServerInstance
    }
} # Function Add-PortToSQLInstance

Function Get-SQLConnection {
    # Changed to flag a bad SQL connection to help prevent subsequent processing.
    # Also replaced obsolete system.Data.SqlClient w/ Microsoft.Data.SqlClient.
    # Ken Row, 5/28/25, Issue 2320

    # Changed to get the SQL listener port from the registry. Ken Row, 5/28/25, Issue 2326

    # Changed to fall back to system.data.sqlclient if microsoft.data.sqlclient does not exist.
    # Also changed to attempt an unencrypted connection if using Microsoft.data.sqlclient and the default encrypted connection fails.
    # Ken Row, 6/5/25, Issue 2336

    # Implemented James Wilde's recommendation to block pooling so that closed connections actually close instead of releasing for reuse.
    # Ken Row, 6/27/25, Issue 2350

    # Changed to use the proper app name and connection timeout. Ken Row, 9/29/25

    # Changed to only save successful connections to the hash table. Ken Row, 10/15/25

    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true)]
        [String] $ServerInstance,

        [Parameter(Mandatory = $true)]
        [String] $Database
    )
    $C_APPLICATION_NAME = 'Eval-STIG'
    $C_CONN_TIMEOUT     = 60   # Number of seconds for initial connections to time out.

    if ($hashSQLConns[$ServerInstance]) {
        $conn = $hashSQLConns[$ServerInstance]
    } else {
        try   {$CSBuilder = New-Object -TypeName Microsoft.Data.SqlClient.SqlConnectionStringBuilder}
        catch {$CSBuilder = New-Object -TypeName System.Data.SqlClient.SqlConnectionStringBuilder}

        $CSBuilder["Server"] = Add-PortTOSQLInstance($ServerInstance)
        $CSBuilder["Database"] = $Database
        $CSBuilder["Connection Timeout"]  = $C_CONN_TIMEOUT
        $CSBuilder["Integrated Security"] = $true
        $CSBuilder["Application Name"]    = $C_APPLICATION_NAME
        $CSBuilder["Pooling"]             = $false

        try   {$conn = New-Object -TypeName Microsoft.Data.SqlClient.SQLConnection}
        catch {$conn = New-Object -TypeName System.Data.SqlClient.SQLConnection}

        $conn.ConnectionString = $CSBuilder.ToString()
        try {$conn.Open()} catch {$oErr = $_}

        if (($oErr) -and $conn.GetType().FullName -eq 'Microsoft.Data.SqlClient.SQLConnection') {
            # Attempt an unencrypted connection in case the above failure is due to a bad server certificate or bad tls settings.
            $CSBuilder.Encrypt = $false
            $conn.ConnectionString = $CSBuilder.ToString()
            $oErr = $null
            try {$conn.Open()} catch {$oErr = $_}
        }

        if ($oErr) {
            $conn.ConnectionString = 'Data Source=ERROR'
            $script:SQLCONNECTIONERROR = $oErr
        } else {
            $hashSQLConns[$ServerInstance] = $conn
            $script:SQLCONNECTIONERROR = $null
        }
    }
    return $conn
} # Get-SQLConnection

Function Close-SQLConnections {
    $keylist = @()

    foreach ($key in $hashSQLConns.Keys) {
        $conn = $hashSQLConns[$key]
        $conn.close()
        $keylist += $key
    }
    foreach ($key in $keylist) {
        $hashSQLConns.Remove($key)
    }
} # Close-SQLConnections

Function Get-ISQL {
    # Added an error throw if the SQL Server login fails.
    # Also replaced obsolete system.Data.SqlClient w/ Microsoft.Data.SqlClient.
    # Ken Row, 5/22/25, Issue 2320

    # Changed to fall back to system.data.sqlclient if microsoft.data.sqlclient does not exist. Ken Row, 6/5/25, Issue 2336

    # Corrected error message "user lacks privileges" to properly show the target server and database. Ken Row, 9/24/25

    # Changed error message to show the actual error message from the failed connection attempt. Ken Row, 10/15/25

    [OutputType([System.Data.DataRow])]
    Param (
        # A valid SQL or DDL statement must either be piped in or specified via the qry parameter.
        [Parameter(Mandatory = $true)]
        [String] $Qry,

        [Parameter(Mandatory = $true)]
        [String] $ServerInstance,

        [Parameter(Mandatory = $false)]
        [String] $Database = "master"
    )

    begin {
        $CSQL_QUERY_TIMEOUT = 1200 # Number of seconds for queries to time out.

        function Resolve-SqlError {
            param($Err)
            if ($Err) {
                if ($PSBoundParameters.Verbose) {
                    if ($Err.Exception.GetType().Name -eq 'SqlException') {
                        Write-Verbose -Message "SQL Error:  $Err"
                    } else {
                        Write-Verbose -Message "Other Error:  $Err"
                    }
                }

                switch ($ErrorActionPreference.ToString()) {
                    { 'SilentlyContinue', 'Ignore' -contains $_ } {   }
                    'Stop' { throw $Err }
                    'Continue' { throw $Err }
                    Default { Throw $Err }
                } # switch ($ErrorActionPreference.ToString())
            } # if ($Err)
        } # sub function Resolve-SqlError

        #Grab a connection...
        $Conn = Get-SQLConnection -ServerInstance $ServerInstance -Database $Database
        if ($conn.DataSource -ne 'ERROR') {
            if ($Conn.State -notlike "Open") {
                try {
                    $Conn.Open()
                }
                catch {
                    throw $_
                }
            } # if ($Conn.State -notlike "Open")

            if ($Conn.Database -notlike $Database) {
                try {
                    $Conn.ChangeDatabase($Database)
                }
                catch {
                    throw "Could not change Connection database '$($Conn.Database)' to $Database`: $_"
                }
            } # if ($Conn.Database -notlike $Database)

            if ($Conn.state -notlike "Open") {
                throw "SQL Connection is not open"
            }
        } else {
            throw "Cannot log in to SQL Instance ${ServerInstance}, Database ${Database}: ${script:SQLCONNECTIONERROR}"
        } # if ($conn.Database -ne 'ERROR')
    } # begin

    process {
        if ($conn.GetType().FullName -eq 'Microsoft.Data.SqlClient.SQLConnection') {
            $cmd = New-Object Microsoft.Data.SqlClient.SqlCommand($Qry, $Conn)
            $cmd.CommandTimeout = $CSQL_QUERY_TIMEOUT
            $da  = New-Object Microsoft.Data.SqlClient.SqlDataAdapter($cmd)
        } else {
            $cmd = New-Object System.Data.SqlClient.SqlCommand($Qry, $Conn)
            $cmd.CommandTimeout = $CSQL_QUERY_TIMEOUT
            $da  = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
        }

        #Following EventHandler is used for PRINT and RAISERROR T-SQL statements. Executed when -Verbose parameter specified by caller
        if ($PSBoundParameters.Verbose) {
            $Conn.FireInfoMessageEventOnUserErrors = $false
            $handler = [Microsoft.Data.SqlClient.SqlInfoMessageEventHandler] { Write-Verbose "$($_)" }
            $Conn.add_InfoMessage($handler)
        }

        $ds = New-Object system.Data.DataSet
        $Err = $null
        try   {
            [void]$da.fill($ds)
        }
        catch {
            $Err = $_
        }
        finally {
            if ($PSBoundParameters.Verbose) {
                $conn.remove_InfoMessage($handler)
            }
        }
        Resolve-SqlError $Err

        if ($ds.Tables.Count -ne 0) {
            Return $ds.Tables[0]
        }
    } # process
} # Get-ISQL

function Confirm-TraceAuditSetting {
    <#
        .SYNOPSIS
            Examines a MSSQL server's trace and audit settings to verify STIG adherance.
        .DESCRIPTION
            Confirm-TraceAuditSettings will first determine whether audits or traces are being used, and then will inspect the configuration of the audits or traces to verify all required events are being audited.  A report of any un-audited events is returned as a string.
        .INPUTS
            None. Does not accept piped-in input.
        .OUTPUTS
            Returns a string detailing any findings.
        .RELEASENOTES
            04/02/25   Ken Row   Issue 2188
              Changed to use the passed-in instance name instead of asking SQL for a list of instances.
    #>
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database
    )
    $ResultData = ""

    $res = Get-ISQL -serverinstance $Instance "
      with q as (
              select 'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP' as audit_action_name
        union select 'AUDIT_CHANGE_GROUP'
        union select 'BACKUP_RESTORE_GROUP'
        union select 'DATABASE_CHANGE_GROUP'
        union select 'DATABASE_OBJECT_CHANGE_GROUP'
        union select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
        union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
        union select 'DATABASE_OPERATION_GROUP'
        union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
        union select 'DATABASE_PERMISSION_CHANGE_GROUP'
        union select 'DATABASE_PRINCIPAL_CHANGE_GROUP'
        union select 'DATABASE_PRINCIPAL_IMPERSONATION_GROUP'
        union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
        union select 'DBCC_GROUP'
        union select 'FAILED_LOGIN_GROUP'
        union select 'LOGIN_CHANGE_PASSWORD_GROUP'
        union select 'LOGOUT_GROUP'
        union select 'SCHEMA_OBJECT_CHANGE_GROUP'
        union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
        union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
        union select 'SERVER_OBJECT_CHANGE_GROUP'
        union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
        union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
        union select 'SERVER_OPERATION_GROUP'
        union select 'SERVER_PERMISSION_CHANGE_GROUP'
        union select 'SERVER_PRINCIPAL_CHANGE_GROUP'
        union select 'SERVER_PRINCIPAL_IMPERSONATION_GROUP'
        union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
        union select 'SERVER_STATE_CHANGE_GROUP'
        union select 'SUCCESSFUL_LOGIN_GROUP'
        union select 'TRACE_CHANGE_GROUP'
       except
	          select audit_action_name
	            from sys.server_audit_specification_details d
			   inner join sys.server_audit_specifications s	on d.server_specification_id = s.server_specification_id
			   inner join sys.server_audits a on s.audit_guid = a.audit_guid
			   where s.is_state_enabled = 1
			     and a.is_state_enabled = 1
    )
    select @@SERVERNAME as InstanceName, Audit_Action_Name from q
    "
    if ($res) {
      # Deficiencies were found in the audits, check traces
      $qry = "
        with q as (
                select 14 as eventid
          union select 15
          union select 18
          union select 20
          union select 102
          union select 103
          union select 104
          union select 105
          union select 106
          union select 107
          union select 108
          union select 109
          union select 110
          union select 111
          union select 112
          union select 113
          union select 115
          union select 116
          union select 117
          union select 118
          union select 128
          union select 129
          union select 130
          union select 131
          union select 132
          union select 133
          union select 134
          union select 135
          union select 152
          union select 153
          union select 170
          union select 171
          union select 172
          union select 173
          union select 175
          union select 176
          union select 177
          union select 178
      "
      Get-ISQL -serverinstance $Instance 'select id from sys.traces' | ForEach-Object {
        $qry += "except select eventid from sys.fn_trace_geteventinfo(" + $_.id + ") "
      } # foreach-object

      $qry += ")
        select @@SERVERNAME as InstanceName, eventid from q
      "
      $restrace = Get-ISQL -serverinstance $instance $qry
      if ($restrace) {
        if ($ResultData -eq "") {
          $ResultData = "The check found events that are not being audited by SQL traces:`n"
        }
        $ResultData += "$($restrace | Format-Table | Out-String)"
      } # if ($restrace)
    } # if ($res)
    Write-Output $ResultData
}

Function Get-AccessProblem (
# Changed variable type of CurrentAuthorizations to a generic type. Ken Row, 9/25/25

      [parameter(mandatory = $true)][System.Collections.Generic.List[System.Object]]$CurrentAuthorizations
    , [parameter(mandatory = $true)][System.Collections.Hashtable]$AllowedAuthorizations
    , [parameter(mandatory = $true)][string]$FilePath
    , [parameter(mandatory = $true)][string]$InstanceName
    ) {
    # Removed some unused code and variables. Ken Row, 9/29/25.

    Set-StrictMode -Version 2.0
    $ResultData = ''

    function AppendResultData (
        [parameter(mandatory = $true)][ref]    $ResultData
        , [parameter(mandatory = $true)][string] $FilePath
        , [parameter(mandatory = $true)][string] $Message
    ) {
        Set-StrictMode -Version 2.0
        if ($ResultData.value -eq '') {
            $ResultData.value = "In directory ${FilePath}:`n`n"
        }
        $ResultData.value += "$Message`n"
    }

    $CurrentAuthorizations | ForEach-Object {
        $arrRights = $_.FileSystemRights -split ', *'
        $sUser = $_.IdentityReference.value
        if ($sUser -match "\`$${InstanceName}$") {
            # This is a service-based account (e.g. NT SERVER\SQLAgent$SQL01), replace the service w/ <INSTANCE> when checking the hash table
            $sSearchUser = $sUser -replace "\`$${InstanceName}$", "$<INSTANCE>"
            $arrAuthPerms = $AllowedAuthorizations[$sSearchUser]
        }
        elseif ($sUser -eq 'NT SERVICE\MSSQLSERVER' -and $InstanceName -eq 'MSSQLSERVER' ) {
            $arrAuthPerms = $AllowedAuthorizations['NT SERVICE\MSSQL$<INSTANCE>']
        }
        else {
            $arrAuthPerms = $AllowedAuthorizations[$sUser]
        }

        try {
            $iAuth = ($arrAuthPerms | Measure-Object).count
        }
        catch {
            $iAuth = 0
        }

        if ($iAuth -gt 0) {
            if ('FullControl' -notin $arrAuthPerms) {
                # Let's try to identify perms held by the user, but not in the list of authorized perms
                $arrTemp = $arrRights -ne 'Synchronize' # Get a copy of rights assigned to the user, less 'Synchronize' which seems innocuous.
                foreach ($p in $arrAuthPerms) {
                    $arrTemp = $arrTemp -ne $p # rebuild the array without $p in it
                    foreach ($psub in get-subperm($p)) {
                        $arrTemp = $arrTemp -ne $p
                    }
                }
                if (($arrTemp | Measure-Object).count -gt 0) {
                    # We removed any permissions that were authorized, so the only ones left should be the unauthorized perms
                    AppendResultData ([ref]$ResultData) $FilePath "$sUser has $($arrTemp -join ',') rights (should be $($arrAuthPerms -ne 'Synchronize' -join ','))."
                }
                else {
                    if (-Not($_.inheritanceflags -eq 'ContainerInherit, ObjectInherit' -and $_.propagationflags -eq 'None')) {
                        if (-Not($FilePath -match '\.trc$' -or $FilePath -match '\.sqlaudit$')) {
                            AppendResultData ([ref]$ResultData) $FilePath "$sUser seems to have appropriate rights, but those rights are not properly propogated."
                        }
                    }
                }
            } # if ('FullControl' -notin $arrAuthPerms)
        }
        else {
            AppendResultData ([ref]$ResultData) $FilePath "$sUser has $($arrRights -join ',') rights (should be NO rights)."
        } # if ($iAuth -gt 0) {
    }

    if ($ResultData -gt '') {
        $ResultData += "`n"
    }

    Return $ResultData
}

function Get-SubPerm {
    <#
        .SYNOPSIS
            Returns an array of file-access permissions that are included with the passed-in permission.
        .PARAMETER perm
            [Mandatory] A file-access permission.
        .INPUTS
            None. Get-SubPerm does not accept piped-in input.
        .OUTPUTS
            An array of permissions.
        .EXAMPLE
            Get-SubPerm 'ReadAndExecute'
            Returns all file access permissions that are included with 'ReadAndExecute'.
    #>
    param(
        [parameter(mandatory = $true)] [string] $perm
    )

    $hashSubPerms = @{
        'Modify'         = @('ReadAndExecute', 'Write', 'Delete')
        'Read'           = @('ReadData', 'ReadExtendedAttributes', 'ReadAttributes', 'ReadPermissions')
        'ReadAndExecute' = @('Read', 'ExecuteFile')
        'Write'          = @('WriteData', 'AppendData', 'WriteExtendedAttributes', 'WriteAttributes')
    }

    $arrResult = $arrPerms = $hashSubPerms[$perm]
    foreach ($p in $arrPerms) {
        $arr = get-SubPerm($p);
        try {
            $iCnt = ($arr | Measure-Object).count
        }
        catch {
            $iCnt = 0
        }

        if ($iCnt -gt 0) {
            $arrResult += $arr
        }
    }
    return $arrResult
}

function Get-SqlVersion {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $res = Get-ISQL -ServerInstance $Instance -Database "Master" "select @@version"

    $sqlVersion = ""
    if ($res.column1 -like "Microsoft SQL Server 2014*") {
        $sqlVersion = "120"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2016*") {
        $sqlVersion = "130"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2017*") {
        $sqlVersion = "140"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2019*") {
        $sqlVersion = "150"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2022*") {
        $sqlVersion = "160"
    }
    return $sqlVersion
}

function Get-SqlVersionInstance {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $sqlVersion = Get-SqlVersion $Instance
    #$sqlVersionInstance = left($sqlVersion,2)+$Instance
    #$sqlVersionInstance = $sqlVersion.Substring(0,2)
    #$sqlVersionInstance = "MSSQL"+$sqlVersion.Substring(0,2)+".$instance"
    # need to remove hostname\
    $HostName = (Get-CimInstance Win32_Computersystem).name
    $InstanceOnly = $Instance.Replace($HostName + "\", "")
    $sqlVersionInstance = "MSSQL" + $sqlVersion.Substring(0, 2) + ".$instanceOnly"
    return $sqlVersionInstance
}


function Get-SqlProductFeatures {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $false)]
        [String]$Database = "master"
    )

    $sqlVersion = Get-SqlVersion $Instance

    $SqlInstallSummaryFile = "$env:programfiles\Microsoft SQL Server\$sqlVersion\Setup Bootstrap\Log\Summary.txt"

    $ProductFeaturesLineCount = 0
    $ProductFeatures = "Using file ($SqlInstallSummaryFile) for SQL Product Features.`n"

    if (Test-Path -Path $SqlInstallSummaryFile) {
        # read SqlInstallSummaryFile for section "Product features discovered:"
        try {
            $SqlInstallSummaryFileLines = Get-Content "$SqlInstallSummaryFile"

            $ProductFeaturesFound = $false

            foreach ($SqlInstallSummaryFileLine in $SqlInstallSummaryFileLines) {
                if ($SqlInstallSummaryFileLine -like "Product features discovered*" -or $ProductFeaturesFound -eq $True) {
                    $ProductFeaturesFound = $true
                    if ($ProductFeaturesFound -eq $true) {
                        if ($SqlInstallSummaryFileLine -like "Package properties*" ) {
                            break
                        }
                        else {
                            $ProductFeaturesLineCount += 1
                            $ProductFeatures += $SqlInstallSummaryFileLine + "`n"
                        }
                    }
                }
            }

            If ($ProductFeaturesLineCount -eq 0) {
                $ProductFeatures = "ERROR: No SQL Product Features Found in File ($SqlInstallSummaryFile)"
            }

        }
        catch {
            $ProductFeatures = "ERROR: Reading SQL Product Features File ($SqlInstallSummaryFile)"
        }
    }
    else {
        $ProductFeatures = "ERROR: Could not find SQL Product Features File ($SqlInstallSummaryFile)"
    }

    return $ProductFeatures
}

function Get-LeftNumbers {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$StringToScan
    )

    $returnValue = ""
    for ($i = 0; $i -lt $StringToScan.Length; $i++) {
        if ($StringToScan[$i] -like "[0-9]*") {
            $returnValue += $StringToScan[$i]
        }
        else {
            break
        }
    }
    return $returnValue
}

Function Get-DeepCopy {
    # Source : https://powershellexplained.com/2016-11-06-powershell-hashtable-everything-you-wanted-to-know-about/#deep-copies
    [cmdletbinding()]
    Param(
        $InputObject
    )

    Process {
        If ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.Specialized.OrderedDictionary] ) {
            If ($InputObject -is [System.Collections.Specialized.OrderedDictionary]) {
                $copy = [ordered]@{}
            }
            Else {
                $copy = @{}
            }

            ForEach ($key in $InputObject.keys) {
                $copy[$key] = Get-DeepCopy $InputObject[$key]
            }
            Return $copy
        }
        Else {
            Return $InputObject
        }
    }
}

Function Out-NormalizedPath {
    param(
        [switch] $UseQuotes,
        [parameter(ValueFromPipeline)] $Pathin)

    $PathOut = $Pathin -replace "[\\/]", "$([IO.Path]::DirectorySeparatorChar)"
    $PathOut = $PathOut -replace "\$([IO.Path]::DirectorySeparatorChar)+", "$([IO.Path]::DirectorySeparatorChar)"

    if ( $UseQuotes -and $PathOut.Contains(" ") ) {
        $PathOut = '"{0}"' -f $PathOut
    }
    else {
        $PathOut = $PathOut -replace '"'
    }

    $PathOut
}

############################################################
## Container Functions                                     #
############################################################

Function Get-ContainerProcessIds {
    param (
        [Parameter(Mandatory = $True)]
        [string]$Engine,
        [Parameter(Mandatory = $True)]
        [string]$ContainerName
    )

    [System.Collections.ArrayList]$ProcessIds = @()

    if ($IsLinux) {
        $pIds = & $Engine inspect -f '{{.State.Pid}}' $ContainerName
    }

    foreach ($p in $pIds) {
        [void] $ProcessIds.add($p)
    }

    return $ProcessIds
}

function Get-ContainerEngine {

	$Engine = ""

	if (Get-Process -name "conmon" -ErrorAction SilentlyContinue) {
		$Engine = "podman"
	}
	elseif (Get-Process -name "containerd" -ErrorAction SilentlyContinue) {
		$Engine = "docker"
	}

	return $Engine
}

Function Get-ContainerNames {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Engine)

	try {
		& $Engine container list | tail -n +2 | awk '{print $NF}'
	}
	catch {
		return ""
	}
}

Function Get-ImageContainerName {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Engine,
        [Parameter(Mandatory = $true)]
        [string] $ImageName)

	try {
		& $Engine container list | tail -n +2 | grep -i $ImageName | awk '{print $NF}'
	}
	catch {
		return ""
	}
}

Function Get-ContainerProcessUser {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Engine,
        [Parameter(Mandatory = $true)]
        [string] $Container,
        [Parameter(Mandatory = $true)]
        [string] $Process)

	try {
		& sudo $Engine top $container | grep -i $Process | sed -n '2p' | awk '{print $1}'
	}
	catch {
		return ""
	}
}

Function Invoke-ContainerCommand {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Engine,
        [Parameter(Mandatory = $true)]
        [string] $Container,
        [Parameter(Mandatory = $true)]
        [string] $Command)

	try {
		& sudo $Engine exec $Container bash -c "$Command"
	}
	catch {
		return ""
	}
}

############################################################
## Apache Functions                                        #
############################################################

function Get-ApacheUnixExecutablePids {
    $Command = "netstat -pant | grep LISTEN | awk '{print `$7}' | grep -Pv `"^-`$`" | awk -F`"/`" `'{print `$1}`'"
    $ListenPids = @(Invoke-Expression -Command $Command) | Sort-Object -Unique

    $Executables = [System.Collections.ArrayList]@()
    foreach ($listenPid in $ListenPids) {
        $binCommand = "readlink /proc/$($listenPid)/exe"
        $bin = Invoke-Expression -Command $binCommand

        $binInfoCommand = "timeout -k 5s 3s $($bin) -v 2>&1 | grep -Pi `"^Server\s*version:\s*Apache/2\.4`""
        $binInfo = Invoke-Expression -Command $binInfoCommand

        if ([string]::IsNullOrEmpty($binInfo)) {
            continue
        }

        [void]$Executables.Add($listenPid.Trim())
    }

    return $Executables
}

function Get-ApacheVersionTable {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-V'
    $Version = & "$ExecutablePath" $Param 2>$null

    return $Version
}

Function Get-ApacheConfigs {
    Param (
        [Parameter(Mandatory = $false)]
        [String]$RootPath,

        [Parameter(Mandatory = $true)]
        [String]$SearchPath,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$FoundConfigs
    )

    $SearchPattern = "^(Include|IncludeOptional)\s+\S*"

    if ( $null -eq $FoundConfigs) {
        $FoundConfigs = [System.Collections.ArrayList]::new()
    }

    if ($SearchPath | Select-String -Pattern "\*") {
        if (Test-Path -Path $SearchPath) {
            $path = $SearchPath
        } else {
            $path = Join-Path -Path $RootPath -ChildPath $SearchPath
            if (-not (Test-Path -Path $path)) {
                return
            }
        }

        $paths = (Get-ChildItem -Path $path).FullName
        foreach ($p in $paths) {
            if (($FoundConfigs | Where-Object { $_.Contains($p)}).Length -eq 0 ) {
                Get-ApacheConfigs -RootPath $rootPath -SearchPath $p -FoundConfigs $FoundConfigs
            }
        }
    }
    else {
        if (Test-Path -Path $SearchPath) {
            $path = $SearchPath
        } else {
            $path = Join-Path -Path $RootPath -ChildPath $SearchPath
            if (-not (Test-Path -Path $path)) {
                return
            }
        }

        if (($FoundConfigs | Where-Object { $_.Contains($path)}).Length -eq 0 ) {
            Write-Output $path
            $null = $FoundConfigs.Add($path)
        }

        $foundIncludes = (Select-String -Path $path -Pattern $SearchPattern -AllMatches).Matches.Value

        ForEach ($found in $foundIncludes) {

            $foundPath = $found.Split(" ")[1]

            if (Test-Path -Path $foundPath) {
                $foundPath = $foundPath
            } else {
                $foundPath = Join-Path -Path $RootPath -ChildPath $foundPath
            }

            if (Test-Path -Path $foundPath) {
                if (($FoundConfigs | Where-Object { $_.Contains($foundPath)}).Length -eq 0 ) {
                    Get-ApacheConfigs -RootPath $rootPath -SearchPath $foundPath -FoundConfigs $FoundConfigs
                }
            }
        }
    }
}

function Get-ConfigFilePaths {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath,
        [Parameter(Mandatory=$false)]
        [string] $CustomConfigDir
    )

    if ($isLinux) {
        $TempOutputFile = '/tmp/Evaluate-STIG_Apache_Server_Config_File_Valid_Check'
        $Param = '-t'
        $Param2 = '-D'
        $Param3 = 'DUMP_INCLUDES'
        & "$ExecutablePath" $Param $Param2 $Param3 > $TempOutputFile 2>&1
        $Configs = & "$ExecutablePath" $Param $Param2 $Param3 2>$null

        if (Test-Path $TempOutputFile) {
            if (Select-String -Path $TempOutputFile -Pattern "Syntax OK") {
                if ($null -ne $CustomConfigDir -and $CustomConfigDir -ne "") {
                    $RootPath = $CustomConfigDir
                    $ServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath -CustomConfigDir $CustomConfigDir
                }
                else {
                    $RootPath = Get-HttpdRootPath -ExecutablePath $executablePath
                    $ServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath
                }

                $Configs = Get-ApacheConfigs -RootPath $RootPath -SearchPath $ServerConfigFile -FoundConfigs $null
            }
            Remove-Item -Path $TempOutputFile
    }
    else {
        $Param = '-t'
        $Param2 = '-D'
        $Param3 = 'DUMP_INCLUDES'
        $Configs = & "$ExecutablePath" $Param $Param2 $Param3 2>$null

        if ($Configs | Select-String -Pattern "Syntax OK") {
            $RootPath = Get-HttpdRootPath -ExecutablePath $ExecutablePath
            $ServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath
            $Configs = Get-ApacheConfigs -RootPath $RootPath -SearchPath $ServerConfigFile -FoundConfigs $null
            }
        }
    }

    $ConfigArray = [System.Collections.ArrayList]@()
    foreach ($string in $Configs) {
        if ($string | Select-String -SimpleMatch 'Included configuration files') {
            continue
        }

        # Get rid of those weird numbers before the path and preserve numbers in the path.
        # Example '(*) C:\Program Files (x86)\blah\blahblah' is converted to 'C:\Program Files (x86)\blah\blahblah'
        $Filtered = $string -replace '^\s*\(\*\)|^\s*\(\d+\)'
        $MoreFiltered = $Filtered.Trim().Replace('\', '/')
        if ($ConfigArray.Contains($MoreFiltered)) {
            continue
        }

        [void]$ConfigArray.Add($MoreFiltered)
    }

    return $ConfigArray
}

function Get-ApacheConfigFileFromPs {
    param (
        [Parameter(Mandatory)]
        [string] $ApachePID
    )
    $CommandText = "ps -p $ApachePID -o args | grep -v COMMAND"
    $ProcessString = Invoke-Expression -Command $CommandText
#    return $ProcessString
    if ($ProcessString -match ' -d ') {
        $FileString = $ProcessString -replace ".* -d ", ""
        $ConfigFile = ($FileString -split ' ')[0]
        return $ConfigFile
    }
}
function Get-HttpdRootPath {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-S'
    $Output = & "$ExecutablePath" $Param 2>$null
    $HttpdRootPath = (($Output | Select-String "ServerRoot" | Out-String).split('"')[1]).Replace('/', '\')
    $HttpdRootPath = $HttpdRootPath + '\'
    $Formatted = $HttpdRootPath.Replace('\\', '\')

    return $Formatted.Trim().Replace('\', '/')
}

function Get-RootServerConfigFile {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath,
        [Parameter(Mandatory=$false)]
        [string] $CustomConfigDir
    )

    $HttpdRootPath = Get-HttpdRootPath -ExecutablePath $ExecutablePath
    if ($CustomConfigDir) {
        $HttpdRootPath = $CustomConfigDir + '/'
    }
    $VersionTable = Get-ApacheVersionTable -ExecutablePath $ExecutablePath
    $RootServerConfigFile = (($VersionTable | Select-String -Pattern "SERVER_CONFIG_FILE" | Out-String).Split('"')[1]).Replace('/', '\')
    $RootServerConfigFile = $HttpdRootPath + $RootServerConfigFile
    $Formatted = $RootServerConfigFile.Replace('\\', '\')

    return $Formatted.Trim().Replace('\', '/')
}

function Get-Modules {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-M'
    $Modules = & "$ExecutablePath" $Param 2>$null

    return $Modules
}

function Get-VirtualHosts {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-t'
    $Param2 = '-D'
    $Param3 = 'DUMP_VHOSTS'
    $VirtualHosts = & "$ExecutablePath" $Param $Param2 $Param3 2>$null

    $Index = 0
    $VirtualHostArray = [System.Collections.ArrayList]@()
    $AddedVhosts = [System.Collections.ArrayList]@()
    foreach ($line in $VirtualHosts) {
        $IsHeader = $line | Select-String -Pattern "VirtualHost configuration" -Quiet
        if ($IsHeader -eq $true ) {
            continue
        }

        $IsTitle = $line | Select-String -Pattern "is a NameVirtualHost" -Quiet
        if ($IsTitle -eq $true ) {
            continue
        }

        # Get the Path and
        $Original = $line -replace '(^.*\()', '' -replace '[()]', ''
        if ($IsLinux) {
            $Path = $Original.Split(':')[0]
            $LineNumber = $Original.Split(':')[1]
        }
        else {
            $Path = $Original.Split(':')[0] + ':' + $Original.Split(':')[1]
            $LineNumber = $Original.Split(':')[2]
        }

        if (-not(Test-Path -Path $Path -PathType Leaf)) {
            continue
        }

        if ($AddedVhosts.Contains($Original.ToString())) {
            continue
        }

        $TotalLines = (Get-Content -Path $Path).Length + 1
        $StartingLine = $TotalLines - $LineNumber
        $fileData = Get-Content -Path $Path -Tail $StartingLine

        $LineInFile = $LineNumber - 1
        $startPrinting = $false
        $LinesInBlock = [System.Collections.ArrayList]@()
        foreach ($line in $fileData) {
            $LineInFile++

            $isComment = $line | Select-String -Pattern '^\s{0,}#'
            if ($null -ne $isComment -and $isComment -ne "") {
                continue
            }

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startPrinting = $false
                $BlockLine = [PSCustomObject]@{
                    LineNumber = $LineInFile
                    Line       = $line
                }
                [void]$LinesInBlock.Add($BlockLine)
                break
            }

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startPrinting = $true

                $SitePortLine = $line -replace '^\<VirtualHost\s+', '' -replace '>', ''
                $SitePortArray = $SitePortLine.Split(':')

                $SiteName = ($SitePortArray[0]).Trim()
                if ($SiteName -eq "*") {
                    $SiteName = "_default_"
                }

                $SitePort = ($SitePortArray[1]).Trim()
            }

            if ($startPrinting -eq $true) {
                $ServerNameLine = ($line | Select-String -Pattern "\bServerName\b.*")
                if ($null -ne $ServerNameLine -and $ServerNameLine -ne "") {
                    $SiteName = ($ServerNameLine.ToString().Trim() -split "\s+")[1]
                }

                $BlockLine = [PSCustomObject]@{
                    LineNumber = $LineInFile
                    Line       = $line
                }
                [void]$LinesInBlock.Add($BlockLine)
            }
        }

        $VirtualHostObject = [PSCustomObject]@{
            SiteName           = $SiteName
            SitePort           = $SitePort
            Index              = $Index
            ConfigFile         = $Path
            StartingLineNumber = $LineNumber
            Block              = $LinesInBlock
        }

        [void]$AddedVhosts.Add($Original.ToString())
        [void]$VirtualHostArray.Add($VirtualHostObject)
        $Index++
    }

    if (($VirtualHostArray | Measure-Object).Count -eq 0) {
        $RootPath = Get-RootServerConfigFile $ExecutablePath
        $VirtualHostObject = [PSCustomObject]@{
            Index              = -1
            ConfigFile         = $RootPath
            StartingLineNumber = -1
            Block              = ""
        }

        [void]$VirtualHostArray.Add($VirtualHostObject)
    }

    # Add Root Server as additional VHOST.
    return $VirtualHostArray
}

function Get-ApacheInstances {
    $Index = 1
    $ApacheObjects = [System.Collections.ArrayList]@()
    $ExecutablePaths = [System.Collections.ArrayList]@()
    $ApachePIDs = [System.Collections.ArrayList]@()
    if ($IsLinux) {
        $ApachePIDs = Get-ApacheUnixExecutablePids
        foreach ($ApachePID in $ApachePIDs) {
            $binCommand = "readlink /proc/$($ApachePID)/exe"
            $ExecutablePath = (Invoke-Expression -Command $binCommand).Trim()
            $HttpdRootPath = Get-HttpdRootPath -ExecutablePath $executablePath
            $CustomConfigDir = Get-ApacheConfigFileFromPs -ApachePID $ApachePID
            if ($Null -ne $CustomConfigDir -and $CustomConfigDir -ne "") {
                $HttpdRootPath = $CustomConfigDir
                $RootServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath -CustomConfigDir $CustomConfigDir
                $ConfigFilePaths = Get-ConfigFilePaths -ExecutablePath $executablePath -CustomConfigDir $CustomConfigDir
            }
            else {
                $RootServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath
                $ConfigFilePaths = Get-ConfigFilePaths -ExecutablePath $executablePath
            }
            $Modules = Get-Modules -ExecutablePath $executablePath
            $VirtualHosts = Get-VirtualHosts -ExecutablePath $executablePath

            $ApacheInstance = [PSCustomObject]@{
                Index                = $Index
                ExecutablePath       = $executablePath
                HttpdRootPath        = $HttpdRootPath
                RootServerConfigFile = $RootServerConfigFile
                ConfigFilePaths      = $ConfigFilePaths
                Modules              = $Modules
                VirtualHosts         = $VirtualHosts
            }

            [void]$ApacheObjects.Add($ApacheInstance)
            $Index++
        }
    }
    else {
        $ApacheServices = Get-CimInstance -Class Win32_Service | Where-Object { $_.Name -like '*Apache*' -and $_.State -like 'Running'}
        foreach ($service in $ApacheServices) {
            if ($($service.PathName) -like '*"*') {
                $ExecutablePath = ($service.PathName -split'"')[1]
            }
            else {
                $ExecutablePath = ($service.PathName -split " ")[0]
            }
            if ($ExecutablePath -eq "") {
                continue
            }

            if (-not (Test-Path -Path $ExecutablePath -PathType Leaf)) {
                # If the path parsed from the PathName is not a valid path does not lead to a file.
                continue
            }

            [void]$ExecutablePaths.Add($ExecutablePath)
        }
        foreach ($executablePath in $ExecutablePaths) {
            $HttpdRootPath = Get-HttpdRootPath -ExecutablePath $executablePath
            $RootServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath
            $ConfigFilePaths = Get-ConfigFilePaths -ExecutablePath $executablePath
            $Modules = Get-Modules -ExecutablePath $executablePath
            $VirtualHosts = Get-VirtualHosts -ExecutablePath $executablePath

            $ApacheInstance = [PSCustomObject]@{
                Index                = $Index
                ExecutablePath       = $executablePath
                HttpdRootPath        = $HttpdRootPath
                RootServerConfigFile = $RootServerConfigFile
                ConfigFilePaths      = $ConfigFilePaths
                Modules              = $Modules
                VirtualHosts         = $VirtualHosts
            }

            [void]$ApacheObjects.Add($ApacheInstance)
            $Index++
        }
    }
    return $ApacheObjects
}

function Get-ApacheModule {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $ModuleName
    )

    $Status = "Disabled"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    if ($null -eq $ApacheInstance) {

        $Module = [PSCustomObject]@{
            Name           = $ModuleName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
        }

        return $Module
    }

    $ModuleFound = $ApacheInstance.Modules | Select-String -Pattern $ModuleName
    if ($null -eq $ModuleFound -or $ModuleFound -eq "") {
        $Status = "Disabled"
    }
    else {
        $Status = "Enabled"
    }

    # Check the config files to see if the LoadModule Line with the module name is present.
    $Pattern = "LoadModule\b\s*$($ModuleName)\b"
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {

        $Test = Select-String -Path $aConfigFile -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch #| Select-Object -ExpandProperty Line,LineNumber
        if ($null -eq $Test -or $Test -eq "") {
            continue
        }

        $ConfigFileLine = $Test.Line
        $LineNumber = $Test.LineNumber
        $ConfigFile = $aConfigFile
        break
    }

    $Module = [PSCustomObject]@{
        Name           = $ModuleName
        Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
        ConfigFileLine = $ConfigFileLine # Actual Line in the config file
        LineNumber     = $LineNumber
        ConfigFile     = $ConfigFile # Absolute File path
    }

    return $Module
}

function Get-ApacheDirectiveFromGlobalConfig {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $BackslashPattern = '\\$'
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {
        $LineInFile = 0
        $startReading = $true
        $LineContinues = $false
        foreach ($line in Get-Content -Path $aConfigFile) {
            $LineInFile++

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startReading = $false
            }

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startReading = $true
                continue
            }

            if ($startReading -eq $true) {
                # This is where we would check for the directive.
                $Test = $line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                $EOLBackslash = $line | Select-String -Pattern $BackslashPattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                if ($null -eq $Test -or $Test -eq "") {
                    if ($LineContinues -eq $true) {
                        $line = $line -replace $BackslashPattern, ""
                        $Directive.ConfigFileLine += $line
                        $LineContinues = $false
                        if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                            $LineContinues = $true
                        }
                    }
                }
                else {
                    #The directive exists
                    $Directive = [PSCustomObject]@{
                        Name           = $DirectiveName
                        Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                        ConfigFileLine = $line.Trim() # Actual Line in the config file
                        LineNumber     = $LineInFile
                        ConfigFile     = $aConfigFile # Absolute File path
                        VirtualHost    = $null
                    }
                    [void]$DirectivesFound.Add($Directive)
                    $FoundCount++

                    if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                        $LineContinues = $true
                        $Directive.ConfigFileLine = $Directive.ConfigFileLine -replace $BackslashPattern, ""
                    }
                }
            }
        }
    }

    #IF we STILL haven't found anything. Use our default values of not found.
    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $null
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheBlockFromGlobalConfig {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {
        $LineInFile = 0
        $startReading = $true
        foreach ($line in Get-Content -Path $aConfigFile) {
            $LineInFile++

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startReading = $false
                Continue
            }

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startReading = $true
                continue
            }

            if ($startReading -eq $true) {
                $isBlockStart = $line | Select-String -Pattern "\<$BlockStart.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
                if ($null -ne $isBlockStart -and $isBlockStart -ne "") {
                    $inBlock = $true
                }

                if ($inBlock -eq $true) {
                    # This is where we would check for the directive.
                    $found = $line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                    if ($null -ne $found -and $found -ne "") {
                        $Directive = [PSCustomObject]@{
                            Name           = $DirectiveName
                            Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                            ConfigFileLine = $line.Trim() # Actual Line in the config file
                            LineNumber     = $LineInFile
                            ConfigFile     = $aConfigFile # Absolute File path
                            VirtualHost    = $null
                        }
                        [void]$DirectivesFound.Add($Directive)
                    }

                    $isEnd = $line | Select-String -Pattern "\<\/$BlockEnd>" | Select-String -Pattern '^\s{0,}#' -NotMatch
                    if ($null -ne $isEnd -and $isEnd -ne "") {
                        $inBlock = $false
                    }
                }
            }
        }
    }

    #IF we STILL haven't found anything. Use our default values of not found.
    if (($DirectivesFound | Measure-Object).Count -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $null
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheDirectiveFromVirtualBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $BackslashPattern = '\\$'
    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($VirtualHost.Index -ne -1) {
        # We need to check the Virtual Host Block
        $LineContinues = $false
        foreach ($line in $VirtualHost.Block) {
            $Test = $line.Line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            $EOLBackslash = $line.Line | Select-String -Pattern $BackslashPattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -eq $Test -or $Test -eq "") {
                if ($LineContinues -eq $true) {
                    $line.Line = $line.Line -replace $BackslashPattern, ""
                    $Directive.ConfigFileLine += $line.Line
                    $LineContinues = $false
                    if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                        $LineContinues = $true
                    }
                }
                continue
            }

            $Directive = [PSCustomObject]@{
                Name           = $DirectiveName
                Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                ConfigFileLine = $line.Line.Trim() # Actual Line in the config file
                LineNumber     = $line.LineNumber
                ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                VirtualHost    = $VirtualHost
            }
            [void]$DirectivesFound.Add($Directive)
            $FoundCount++

            if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                $LineContinues = $true
                $Directive.ConfigFileLine = $Directive.ConfigFileLine -replace $BackslashPattern, ""
            }

        }
    }

    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $VirtualHost
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheBlockFromVirtualBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $foundit = $false
    $inBlock = $false
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($line in $VirtualHost.Block) {
        $isStart = $line.line | Select-String -Pattern "\<$BlockStart.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
        if ($null -ne $isStart -and $isStart -ne "") {
            $inBlock = $true
            $foundIt = $false
            Continue
        }

        if ($inBlock -eq $true) {
            # This is where we would check for the directive.
            $found = $line.line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $found -and $found -ne "") {
                $foundIt = $true

                $Directive = [PSCustomObject]@{
                    Name           = $DirectiveName
                    Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                    ConfigFileLine = $line.Line.Trim() # Actual Line in the config file
                    LineNumber     = $line.LineNumber
                    ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                    VirtualHost    = $VirtualHost
                }
                [void]$DirectivesFound.Add($Directive)
                $FoundCount++
            }

            $isEnd = $line.line | Select-String -Pattern "\<\/$BlockEnd>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $inBlock = $false

                if ($foundIt -eq $false) {
                    $Directive = [PSCustomObject]@{
                        Name           = $DirectiveName
                        Status         = "Not Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                        ConfigFileLine = $ConfigFileLine
                        LineNumber     = $Linenumber
                        ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                        VirtualHost    = $VirtualHost
                    }
                    [void]$DirectivesFound.Add($Directive)
                }
            }
        }
    }

    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $VirtualHost
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheDirective {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($null -eq $VirtualHost) {
        # This will always be a server check.
        $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $DirectiveName)
        $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        foreach ($vhost in $ApacheInstance.VirtualHosts) {
            if ($vhost.Index -eq -1) {
                continue
            }

            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromVirtualBlock -VirtualHost $vhost -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)
        }
    }
    else {
        $FoundCount = 0

        # This will execute if you pass in a Virtual Host to the funciton.
        # Check the Virtual Host for the Directive first.
        if ($VirtualHost.Index -ne -1) {
            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromVirtualBlock -VirtualHost $VirtualHost -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)

            # If the Directive is not found in the Virtual Host, set the FoundCount to 0 and move on.
            foreach ($found in $DirectivesInVirtualHosts) {
                if ($found.Status -eq "Not Found") {
                    $FoundCount = 0
                    break
                }

                $FoundCount++
            }
        }

        # If we haven't found anything in the Virtual Host, try to find it in the global config.
        if ($FoundCount -le 0) {
            # If nothing is found, check the config files ommiting Vhost blocks.
            $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        }
    }

    return $DirectivesFound
}

function Get-ApacheDirectiveFromBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectivePattern
    )

    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($null -eq $VirtualHost) {
        # This will always be a server check.
        $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheBlockFromGlobalConfig -ApacheInstance $ApacheInstance -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
        $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        foreach ($vhost in $ApacheInstance.VirtualHosts) {
            if ($vhost.Index -eq -1) {
                continue
            }

            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheBlockFromVirtualBlock -VirtualHost $vhost -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)
        }
    }
    else {
        $FoundCount = 0

        # This will execute if you pass in a Virtual Host to the funciton.
        # Check the Virtual Host for the Directive first.
        if ($VirtualHost.Index -ne -1) {
            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheBlockFromVirtualBlock -VirtualHost $VirtualHost -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)

            # If the Directive is not found in the Virtual Host, set the FoundCount to 0 and move on.
            foreach ($found in $DirectivesInVirtualHosts) {
                if ($found.Status -eq "Not Found") {
                    $FoundCount = 0
                    break
                }

                $FoundCount++
            }
        }

        # If we haven't found anyything in the Virtual Host, try to find it in the global config.
        if ($FoundCount -le 0) {
            # If nothing is found, check the config files ommiting Vhost blocks.
            $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheBlockFromGlobalConfig -ApacheInstance $ApacheInstance -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        }
    }

    return $DirectivesFound
}

function Get-ApacheFormattedOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [psobject[]] $FoundValues,
        [Parameter(Mandatory)]
        [string] $ExpectedValue,
        [Parameter(Mandatory = $false)]
        [bool] $IsInGlobalConfig,
        [Parameter(Mandatory = $false)]
        [bool] $IsInAllVirtualHosts
    )

    Process {
        $Output = "" # Start with a clean slate.
        foreach ($FoundValue in $FoundValues) {
            #This is a Directive
            if ($FoundValue.Status -eq "Found") {
                $Output += "Directive:`t`t`t$($FoundValue.Name)" | Out-String
                $Output += "Expected Value:`t$($ExpectedValue)" | Out-String
                $Output += "Detected Value:`t$($FoundValue.ConfigFileLine)" | Out-String
                $Output += "In File:`t`t`t$($FoundValue.ConfigFile)" | Out-String
                $Output += "On Line:`t`t`t$($FoundValue.LineNumber)" | Out-String

                if ($null -ne $FoundValue.VirtualHost) {
                    $Output += "Config Level:`t`tVirtual Host" | Out-String
                    $SiteName = $FoundValue.VirtualHost.SiteName + ":" + $FoundValue.VirtualHost.SitePort
                    $Output += "Site Name:`t`t$SiteName" | Out-String
                }
                else {
                    $Output += "Config Level:`t`tGlobal" | Out-String
                }
                $Output += "" | Out-String
            }
            #This is a Directive
            elseif ($FoundValue.Status -eq "Not Found") {
                if (((($null -eq $FoundValue.VirtualHost) -and ($IsInAllVirtualHosts -ne "$false")) -or (($null -ne $FoundValue.VirtualHost) -and ($IsInGlobalConfig -ne "$false")))) {

                    $Output += "Directive:`t`t`t$($FoundValue.Name)" | Out-String
                    $Output += "Expected Value:`t$($ExpectedValue)" | Out-String
                    $Output += "Detected Value:`t$($FoundValue.ConfigFileLine)" | Out-String

                    if ($null -ne $FoundValue.VirtualHost) {
                        $Output += "Config Level:`t`tVirtual Host" | Out-String
                        $SiteName = $FoundValue.VirtualHost.SiteName + ":" + $FoundValue.VirtualHost.SitePort
                        $Output += "Site Name:`t`t$SiteName" | Out-String
                    }
                    else {
                        $Output += "Config Level:`t`tGlobal" | Out-String
                    }
                    $Output += "" | Out-String
                }
            }
            else {
                #This is a Module (Should be  'Enabled' or 'Disabled')
                $Output += "Module:`t`t`t$($FoundValue.Name)" | Out-String
                $Output += "Expected Status:`t$($ExpectedValue)" | Out-String
                $Output += "Detected Status:`t$($FoundValue.Status)" | Out-String
                if ($FoundValue.ConfigFileLine -ne "Not Found") {
                    $Output += "Config File Line:`t$($FoundValue.ConfigFileLine)" | Out-String
                    $Output += "In File:`t`t`t$($FoundValue.ConfigFile)" | Out-String
                    $Output += "On Line:`t`t`t$($FoundValue.LineNumber)" | Out-String
                }
                $Output += "" | Out-String
            }
        }
        return $Output
    }
}

function Test-ApacheDirectiveInAllVirtualHosts {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [psobject[]] $ApacheDirectives
    )

    $VhostCount = 0
    $VirtualHostArray = [System.Collections.ArrayList]@()
    $ApacheVhostsCount = ($ApacheInstance.VirtualHosts | Measure-Object).Count - 1 # -1 to exclude the global config.

    if ($ApacheVhostsCount -eq 0) {
        return $false
    }

    foreach ($directive in $ApacheDirectives) {
        if (($null -eq $directive.VirtualHost) -or ($directive.Status -eq "Not Found")) {
            continue
        }

        $SiteName = $directive.VirtualHost.SiteName + ":" + $directive.VirtualHost.SitePort

        if ($VirtualHostArray.Contains($SiteName)) {
            continue
        }

        $VhostCount++
        [void]$VirtualHostArray.Add($SiteName)
    }

    return ($VhostCount -eq $ApacheVhostsCount)
}

function Test-ApacheDirectiveInGlobal {
    param (
        [Parameter(Mandatory)]
        [psobject[]] $ApacheDirectives
    )

    foreach ($directive in $ApacheDirectives) {
        if ($null -eq $directive.VirtualHost) {
            return ($directive.Status -eq "Found")
        }
    }

    return $false
}

function Get-ApacheLogDirs {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance
    )

    $LogDirs = [System.Collections.ArrayList]@()
    $Null = Get-ChildItem -Path $ApacheInstance.HttpdRootPath -Directory | ForEach-Object {
        if ($_.Name -like "log*") {
            $LogDirs.Add($_.FullName)
        }
    }

    $LogLine = & "$($ApacheInstance.ExecutablePath)" -S

    # Assume we are dealing with a path.
    $PathPattern = '(?=[a-z|A-Z]\:)'
    $ErrorLogLine = (((($LogLine | Select-String -Pattern "ErrorLog:") -replace '"') -replace ".*ErrorLog\:\s+") -replace "Program Files", "PROGRA~1") -replace "Program Files \(x86\)", "PROGRA~2"
    $ErrorLogSplit = $ErrorLogLine -split $PathPattern

    $PipePattern = "\||\|\$"
    # Test for a pipe. It will look something like this "|C:\Some\Path\Here"  or "|$\Some\Path\Here"
    # If we split on white space, test the first path to see if it's a pipe.
    $IsPipePattern = [bool]($ErrorLogSplit[0] | Select-String -Pattern $PipePattern -Quiet)
    if ($IsPipePattern) {
        # At this point I feel like the best we can do is loop over the split values.
        # Skip the first value because we know it's the path to the piped executable.
        for ($i = 2; $i -le ($ErrorLogSplit | Measure-Object).Count; $i++) {
            if ([string]::IsNullOrEmpty($ErrorLogSplit[$i])) {
                continue
            }

            # Resolve the path to get rid of stuff like "PROGRA~1" for comparison.
            $SystemErrorLog = [System.IO.Path]::GetFullPath((Split-Path -Path $ErrorLogSplit[$i]))
            if (Test-Path -Path $SystemErrorLog -PathType Container) {
                if (-not ($LogDirs.Contains($SystemErrorLog))) {
                    [void]$LogDirs.Add($SystemErrorLog)
                }
            }
        }
    }
    else {
        $SystemErrorLog = [System.IO.Path]::GetFullPath((Split-Path -Path $ErrorLogLine))
        if (Test-Path -Path $SystemErrorLog -PathType Container) {
            if (-not ($LogDirs.Contains($SystemErrorLog))) {
                [void]$LogDirs.Add($SystemErrorLog)
            }
        }
    }

    return $LogDirs
}

############################################################
## Apache Functions                                        #
############################################################

############################################################
## Postgres Functions                                      #
############################################################

Function Get-ProcessIds {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessName
    )

    [System.Collections.ArrayList]$ProcessIds = @()

    if ($IsLinux) {
        $pIds = ps f -opid','cmd -C $($ProcessName) --no-headers | awk '$2 !~ /^(\\_)/ {print $1}'
    }
    else {
        try {
            $pIds = Get-Process -Name "$($ProcessName)" -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Output "$($_.Id)"
            }
        }
        catch {
        }
    }

    foreach ($p in $pIds) {
        [void] $ProcessIds.add($p)
    }

    return $ProcessIds
}


Function Get-ProcessString {
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessId
    )

    if ($IsLinux) {
        $processString = ps f -ocmd',' -p $ProcessId --no-headers
    }
    else {
        if (($PsVersionTable.PSVersion).ToString() -match "5.*") {
            $processString = (Get-WmiObject Win32_Process -Filter "ProcessId = '$($ProcessId)'").CommandLine
        }
        else {
            $processString = (Get-Process -Id $ProcessId).CommandLine
        }

    }

    return $processString
}

Function Get-ProcessUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessId
    )

    if ($IsLinux) {
        $ProcessUser = (& ps -o uname= -p $ProcessID)
    }
    else {
        $ProcessUser = (Get-Process -Id $ProcessID -IncludeUserName).Username
    }

    if ($null -eq $ProcessUser -or $ProcessUser -eq "") {
        $ProcessUser = "Unknown"
    }

    return $ProcessUser
}

Function Get-ProcessCommandLine {
    Param (
        [Parameter(Mandatory = $false)]
        [int]$ProcessId,
        [Parameter(Mandatory = $false)]
        [string]$ProcessName
    )

    $retValue = ""
    $commandLine = ""

    if ($ProcessId -gt 0) {
        $commandLine = Get-ProcessString -ProcessId $ProcessId
        $retValue = "$($ProcessId)|$($commandLine)"
    }
    elseif ($null -ne $ProcessName -and $ProcessName -ne "") {
        $pIds = Get-ProcessIds -ProcessName $ProcessName
        $retValue = $pIds | ForEach-Object {
            $commandLine = Get-ProcessString -ProcessId $_
            if ([string]::IsNullOrEmpty($commandLine)) {
                $commandLine = ""
            }
            Write-Output "$($_)|$($commandLine)"
        }
    }

    return $retValue
}

############################################################
## Postgres Functions                                      #
############################################################

############################################################
## Trellix ENS 10x Functions                               #
############################################################

function Get-TrellixOptDirs {
    return @(pgrep -f mfe | xargs ps -h -o cmd | Sort-Object -u | ForEach-Object { Split-Path -Path $_ })
}

############################################################
## Trellix ENS 10x Functions                               #
############################################################

Function Get-FireFox {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Switch]$Policies
    )

    $Results = [System.Collections.Generic.List[System.Object]]::new()

    # Check typical paths for firefox
    $FFPoliciesJSONPaths = @(
        '/usr/lib64/firefox'
        '/usr/lib/firefox'
        '/etc/firefox'
        '/usr/bin/firefox'
    )

    # Check typical paths for firefox-esr
    $FFESRPoliciesJSONPaths = @(
        '/usr/lib64/firefox-esr'
        '/usr/lib/firefox-esr'
        '/etc/firefox-esr'
        '/usr/bin/firefox-esr'
    )

    Function Format-Array {
        [cmdletbinding()]
        param (
            [Parameter(Mandatory = $false)]
            [String[]]$Array,

            [Parameter(Mandatory = $false)]
            [Switch]$Policies
        )

        if ($Policies){
            $Array | Foreach-Object {
                if ($_ -match "/etc/firefox"){
                    "$_/policies/policies.json"
                }
                else{
                    "$_/distrubution/policies.json"
                }
            }
        }
    }

    if ($Policies){
        $PathArray = Modify-Array -Array ($FFPoliciesJSONPaths + $FFESRPoliciesJSONPaths) -Policies
    }
    else{
        $PathArray = ($FFPoliciesJSONPaths + $FFESRPoliciesJSONPaths)
    }
    Foreach ($item in $PathArray) {
        $PSObj = [PSCustomObject]@{
            Path   = $item
            Exists = Test-Path -Path $item
        }
        $Results.Add($PSObj)
    }

    return $Results
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9TOSYOlt1XgmR
# XHz/LtxQD2I9ni30smWw720aMH/XuaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
# KoZIhvcNAQELBQAwWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
# bWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMTDERPRCBJ
# RCBDQS03MjAeFw0yNTAzMjUwMDAwMDBaFw0yODAzMjMyMzU5NTlaMIGOMQswCQYD
# VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0Qx
# DDAKBgNVBAsTA1BLSTEMMAoGA1UECxMDVVNOMTswOQYDVQQDEzJDUy5OQVZBTCBT
# VVJGQUNFIFdBUkZBUkUgQ0VOVEVSIENSQU5FIERJVklTSU9OLjAwMTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBALl8XR1aeL1ARA9c9RE46+zVmtnbYcsc
# D6WG/eVPobPKhzYePfW3HZS2FxQQ0yHXRPH6AS/+tjCqpGtpr+MA5J+r5X9XkqYb
# 1+nwfMlXHCQZDLAsmRN4bNDLAtADzEOp9YojDTTIE61H58sRSw6f4uJwmicVkYXq
# Z0xrPO2xC1/B0D7hzBVKmxeVEcWF81rB3Qf9rKOwiWz9icMZ1FkYZAynaScN5UIv
# V+PuLgH0m9ilY54JY4PWEnNByxM/2A34IV5xG3Avk5WiGFMGm1lKCx0BwsKn0PfX
# Kd0RIcu/fkOEcCz7Lm7NfsQQqtaTKRuBAE5mLiD9cmmbt2WcnfAQvPcCAwEAAaOC
# AcIwggG+MB8GA1UdIwQYMBaAFIP0XzXrzNpde5lPwlNEGEBave9ZMDcGA1UdHwQw
# MC4wLKAqoCiGJmh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElEQ0FfNzIuY3Js
# MA4GA1UdDwEB/wQEAwIGwDAWBgNVHSAEDzANMAsGCWCGSAFlAgELKjAdBgNVHQ4E
# FgQUmWLtMKC6vsuXOz9nYQtTtn1sApcwZQYIKwYBBQUHAQEEWTBXMDMGCCsGAQUF
# BzAChidodHRwOi8vY3JsLmRpc2EubWlsL3NpZ24vRE9ESURDQV83Mi5jZXIwIAYI
# KwYBBQUHMAGGFGh0dHA6Ly9vY3NwLmRpc2EubWlsMIGSBgNVHREEgYowgYekgYQw
# gYExCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNV
# BAsTA0RvRDEMMAoGA1UECxMDUEtJMQwwCgYDVQQLEwNVU04xLjAsBgNVBAMTJUlS
# RUxBTkQuREFOSUVMLkNIUklTVE9QSEVSLjEzODcxNTAzMzgwHwYDVR0lBBgwFgYK
# KwYBBAGCNwoDDQYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQADggEBAI7+Xt5NkiSp
# YYEaISRpmsKDnEpuoKzvHjEKl41gmTMLnj7mVTLQFm0IULnaLu8FHelUkI+RmFFW
# gHwaGTujbe0H9S6ySzKQGGSt7jrZijYGAWCG/BtRUVgOSLlWZsLxiVCU07femEGT
# 2JQTEhx5/6ADAE/ZT6FZieiDYa7CZ14+1yKZ07x+t5k+hKAHEqdI6+gkInxqwunZ
# 8VFUoPyTJDsiifDXj5LG7+vUr6YNWZfVh2QJJeQ3kmheKLXRIqNAX2Ova3gFUzme
# 05Wp9gAT4vM7Zk86cHAqVFtwOnK/IGRKBWyEW1btJGWM4yk98TxGKh5JSPN4EAln
# 3i2bAfl2BLAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwggW4MIID
# oKADAgECAgFIMA0GCSqGSIb3DQEBDAUAMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQK
# Ew9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYw
# FAYDVQQDEw1Eb0QgUm9vdCBDQSA2MB4XDTIzMDUxNjE2MDIyNloXDTI5MDUxNTE2
# MDIyNlowWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEM
# MAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMTDERPRCBJRCBDQS03
# MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALi+DvkbsJrZ8W6Dbflh
# Bv6ONtCSv5QQ+HAE/TlN3/9qITfxmlSWc9S702/NjzgTxJv36Jj5xD0+shC9k+5X
# IQNEZHeCU0C6STdJJwoJt2ulrK5bY919JGa3B+/ctujJ6ZAFMROBwo0b18uzeykH
# +bRhuvNGrpYMJljoMRsqcdWbls+I78qz3YZQQuq5f3LziE03wD5eFRsmXt9PrCaR
# FiftqjezlmoiMOdGbr/DFaLDHkrf/fvtQmreIPKQuQFwmw190LvhdUa4yjshnTV9
# nv1Wo22Yc8US2N3vEOwr5oQPLt/bQyhPHvPt6WNJMqjr7grwSrScJNb2Yr7Fz3I/
# 1fECAwEAAaOCAYYwggGCMB8GA1UdIwQYMBaAFBNPPLvbXUUppZRwttqsnkziL8EL
# MB0GA1UdDgQWBBSD9F8168zaXXuZT8JTRBhAWr3vWTAOBgNVHQ8BAf8EBAMCAYYw
# ZwYDVR0gBGAwXjALBglghkgBZQIBCyQwCwYJYIZIAWUCAQsnMAsGCWCGSAFlAgEL
# KjALBglghkgBZQIBCzswDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMAwGCmCG
# SAFlAwIBAycwEgYDVR0TAQH/BAgwBgEB/wIBADAMBgNVHSQEBTADgAEAMDcGA1Ud
# HwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRFJPT1RDQTYu
# Y3JsMGwGCCsGAQUFBwEBBGAwXjA6BggrBgEFBQcwAoYuaHR0cDovL2NybC5kaXNh
# Lm1pbC9pc3N1ZWR0by9ET0RST09UQ0E2X0lULnA3YzAgBggrBgEFBQcwAYYUaHR0
# cDovL29jc3AuZGlzYS5taWwwDQYJKoZIhvcNAQEMBQADggIBALAs2CLSvmi9+W/r
# cF0rh09yoqQphPSu6lKv5uyc/3pz3mFL+lFUeIdAVihDbP4XKB+wr+Yz34LeeL82
# 79u3MBAEk4xrJOH29uiRBJFTtMdt8GvOecd2pZSGFbDMTt10Bh9N+IvGYclwMkvt
# 26Q+VlZysQr3fQQ8QdO6z4e9jTFR92QmoW4eLyx8CmgZT2CESRl60Ey0A6Gf87Hh
# ntetRp9k0VkFOk7hWfCSUFBhTrmuJBgNB9HP7e5DuPwKUZLICziVxVrZydoyUmyX
# Aki9q6VrUAsm/1/i/YeUInqtXJZ2vs3foMsNa/tVSQ1BG1Wn/1ZfVzWLd+sAA/nk
# CnbsMc61UG8Yec0jC4WMCsmsQKLEfPrt9/U+tEuX9mqeD3dtpR+vq18av8FNd1mY
# zRgFdNc2+P09daj70PslCCb64XAJh1RY4zHPsOA9o+OXdHAX0kpTackvueXyuLb6
# BM0FCaTpq83Y2oH55kM/pPN3brNHUcIkBzqTj48X3WgQbrrwvGTWh4PSGoitnvsB
# nxsBfAFbqugOUEnnIk0an2Vdl3zGXBooAiODnd/n87Ht7psLp7koapfXTGJBClZU
# mSFpdwtI15hvdw9KThK41bC0cLu8lZ4TEFAxSJyuGjxkhBKXeq7LrRSjO8T+bHte
# u6ud36J9k9xg5brIqTW2ripCBEEtMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMi
# DDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0
# MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQw
# OTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxC
# qvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qc
# hUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbD
# hAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pn
# YJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI
# 2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS
# 638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZx
# st7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17y
# Vp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTn
# YCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4
# yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZ
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ
# 7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQE
# AwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJ
# YIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0
# pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN
# 2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a
# +Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7p
# GdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZ
# ruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspI
# HBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku
# /qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZ
# Zd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeu
# kcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA
# 6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvF
# oW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJ
# KoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBS
# U0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMy
# MzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3Bv
# bmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwt
# Esae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjn
# i6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EI
# YLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytx
# NM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ
# 0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Os
# kkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQN
# C3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrA
# tuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi
# 54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJY
# i+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0Ia
# adCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0T
# AQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgw
# FoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdS
# U0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5n
# UlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsG
# CWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNA
# ciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBaj
# YfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5
# qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kze
# kd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr
# 15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHL
# hFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2Od
# Dh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CS
# BXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53V
# JUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yER
# NpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5
# bIbY3TVzgiFI7Gq3zWcxggU9MIIFOQIBATBhMFoxCzAJBgNVBAYTAlVTMRgwFgYD
# VQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJ
# MRUwEwYDVQQDEwxET0QgSUQgQ0EtNzICAxNh1TANBglghkgBZQMEAgEFAKCBhDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEi
# BCB4A2Qxn6H/Nuz6JQ+DhMjlpBniweBoRGQc1RcR1mlkUjANBgkqhkiG9w0BAQEF
# AASCAQBHBgTm0uvQ/HtKjr0h70bprdAO/oduqk1Yc/RqtbbT2rHcPdW9AYJT84IS
# eytdpX0DXAvPSwkYx85oP7F6Z0/A5vk9ZBtwJvy4kjDyxIf0WxbEjV39DQREISAE
# OgjXExs8iGx+AC4sVdYmKD3zXrsk3dIEQgQrwL19RF22UcEb0aoZzo3vmconxWT6
# bWLcMf9BmukZdveuj/5Rx/hPtOXhkj09sndUz++dz3EsfwgfEivHpqXxERHYQtJL
# Ys5A98kq0pe3PZ4Ml0s2QZoU1QMVHIk9CBkN4LYR7YBautd+rR869hqDlbt1a6A0
# kZ5ordICmCdiwoPqvPN9hzKa6VFboYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTAwOVowLwYJKoZIhvcNAQkEMSIEINEkId2QYu+TQoCJI1MOcu+6gN/K
# /OHASlMYJEQEViZsMA0GCSqGSIb3DQEBAQUABIICAKAoZEMCJdwpYHeXeAmUNJ58
# ZpV91oL26KWZ52Y7WztDqzhW9OAvXtcdqD9/bGJstQ7RcUrCk2bgEBmJ6RTXwzZx
# 8iQKEJ/p2FTKIUv+iFS1QnG+yu44NaMD0PNhd1JD7505nkmOCdeG0m6NDWxRWK1/
# zeVjxX3Br5AZCPWn5/vx14DjedxB1tCVs2uZJlQqg3f6pFzbEbOoflhkBGkdpLe2
# JUKzAA3M3M/0wGpajBCB+EXC0LERXmT/mu1nEUOjeYt3pO0h7N2y97mRnqVCdZvT
# 9RJOW1npeuvzKMrsJJ06oSWbfpQTTHSpWKZpt7LUPiYd4pQJ+Bf6+Uo1oEkD8kdt
# DuI2WY2vPm0/lptP5+AfR0np0zrtdP8Jlx3AAb5Xdum/DhPQB/ZgblitTE8c40u7
# SVMupK2wvGbUaIygsTAdp4jf5jDgmpElshJ6f+x8t/Wq/fYAWuRAwuAzqM1zHalF
# 0XaZRWoMdkOT38dMXRILnctHWJe8PtmpL+TmIZjMuEzwr3jU75eajcJ0vnQG5oxD
# N7xxV7HK1srRLHVSEpdXV8b++8WWwrrMh7hdod55G0eAocyldWePcr9OMCYC1gzy
# pFCPfa501xUVERmEmnwKPQFk3WPnh3ilZNrp0Je4LZeX4BgAdQGVn1MeY1r1tUKa
# ObyMrF7XS0cN6YbiqBBt
# SIG # End signature block
