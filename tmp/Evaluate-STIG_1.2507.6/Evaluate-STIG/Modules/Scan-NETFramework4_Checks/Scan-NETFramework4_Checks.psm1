##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft DotNet Framework 4.0
# Version:  V2R7
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-DotNet4Version {
    $RegVersion = Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Version

    $RegRelease = ""
    if ("Release" -in ((Get-ItemProperty -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full') | Get-Member).Name) {
        $RegRelease = Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release
    }

    switch ($RegRelease) {
        { $_ -ge 533320 } { $Version = '4.8.1 or later'; break }
        { $_ -ge 528040 } { $Version = '4.8'; break }
        { $_ -ge 461808 } { $Version = '4.7.2'; break }
        { $_ -ge 461308 } { $Version = '4.7.1'; break }
        { $_ -ge 460798 } { $Version = '4.7'; break }
        { $_ -ge 394802 } { $Version = '4.6.2'; break }
        { $_ -ge 394254 } { $Version = '4.6.1'; break }
        { $_ -ge 393295 } { $Version = '4.6'; break }
        { $_ -ge 379893 } { $Version = '4.5.2'; break }
        { $_ -ge 378675 } { $Version = '4.5.1'; break }
        { $_ -ge 378389 } { $Version = '4.5'; break }
        default {           $Version = $RegVersion; break }
    }

    return $Version
}

Function Get-V225223 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225223
        STIG ID    : APPNET0031
        Rule ID    : SV-225223r961038_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Digital signatures assigned to strongly named assemblies must be verified.
        DiscussMD5 : 5F04625CD2D79D5F38A2C408FA532398
        CheckMD5   : 5998A85DE437DBC8808C74AD505A745C
        FixMD5     : 280413122EF8E3E1BD92E3FF3A19D53E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Values = ""
    $Path = "HKLM:\SOFTWARE\Microsoft\StrongName\Verification"
    if (Test-Path $Path) {
        foreach ($Item in (Get-Item $Path)) {
            if ($Item.Property) {
                $Values += "Path:`t`t`t$($Item.Name)" | Out-String
                $Values += "ValueName:`t$($Item.Property)" | Out-String
                $Values += "" | Out-String
            }
        }
        foreach ($ChildItem in (Get-ChildItem $Path -Recurse)) {
            if ($ChildItem.Property) {
                $Values += "Path:`t`t`t$($ChildItem.Name)" | Out-String
                $Values += "ValueName:`t$($ChildItem.Property)" | Out-String
                $Values += "" | Out-String
            }
        }

        if (-not($Values)) {
            $Status = "NotAFinding"
            $FindingDetails += "HKLM:\SOFTWARE\Microsoft\StrongName\Verification exists but no values were found within." | Out-String
        }
        else {
            $Status = "Open"
            $FindingDetails += "HKLM:\SOFTWARE\Microsoft\StrongName\Verification contains the following values:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Values
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "HKLM:\SOFTWARE\Microsoft\StrongName\Verification does not exist" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225224 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225224
        STIG ID    : APPNET0046
        Rule ID    : SV-225224r961038_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : The Trust Providers Software Publishing State must be set to 0x23C00.
        DiscussMD5 : E829FB25D40FA75698D1565A15E9CA21
        CheckMD5   : 456345100F471F9AC3CF098F05FE5160
        FixMD5     : 1192A66371A8F773BEEED54DC2182FB4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($ScanType -in @("Classified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA." | Out-String
    }
    else {
        $Compliant = $true

        $ProfileList = Get-UsersToEval

        $RegistryValueName = "State"
        foreach ($UserProfile in $ProfileList) {
            $ProcessProfile = $false
            if (Test-Path -Path Registry::HKU\$($UserProfile.SID)) {
                $ProcessProfile = $true

                # User is logged in so check registry direcly
                $RegistryPathToCheck = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
                $RegistryResult = Get-RegistryResult -Path $RegistryPathToCheck -ValueName $RegistryValueName
                $RegistryResult.Value = "0x{0:x8}" -f $RegistryResult.Value # Convert to hex and format to 0x00000000
            }
            elseif (Test-Path -Path "$($UserProfile.LocalPath)\NTUSER.DAT") {
                $ES_Hive_Tasks = @("Eval-STIG_LoadHive", "Eval-STIG_UnloadHive") # Potential scheduled tasks for user hive actions
                $ProcessProfile = $true

                # Load NTUSER.DAT to HKU:\ES_TEMP_(SID)
                $NTUSER_DAT = [Char]34 + "$($UserProfile.LocalPath)\NTUSER.DAT" + [Char]34
                try {
                    $Result = Start-Process -FilePath REG -ArgumentList "LOAD HKU\ES_TEMP_$($UserProfile.SID) $($NTUSER_DAT)" -Wait -PassThru -WindowStyle Hidden
                    if ($Result.ExitCode -ne 0) {
                        throw
                    }
                }
                catch {
                    # REG command failed so attempt to do as SYSTEM
                    try {
                        $Result = Invoke-TaskAsSYSTEM -TaskName $ES_Hive_Tasks[0] -FilePath REG -ArgumentList "LOAD HKU\ES_TEMP_$($UserProfile.SID) $($NTUSER_DAT)" -MaxRunInMinutes 1
                        if ($Result.LastTaskResult -ne 0) {
                            throw "Failed to load user hive '$($NTUSER_DAT)'."
                        }
                    }
                    catch {
                        throw $_.Exception.Message
                    }
                }

                $RegistryPathToCheck = "Registry::HKEY_USERS\ES_TEMP_$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
                $RegistryResult = Get-RegistryResult -Path $RegistryPathToCheck -ValueName $RegistryValueName
                if ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                    $RegistryResult.Value = "0x{0:x8}" -f $RegistryResult.Value # Convert to hex and format to 0x00000000
                }

                # Unload HKU:\ES_TEMP_(SID)
                [System.GC]::Collect() # garbage collection to help unload the hive
                Start-Sleep -Seconds 1
                try {
                    $Result = Start-Process -FilePath REG -ArgumentList "UNLOAD HKU\ES_TEMP_$($UserProfile.SID)" -Wait -PassThru -WindowStyle Hidden
                    if ($Result.ExitCode -ne 0) {
                        throw
                    }
                }
                catch {
                    # REG command failed so attempt to do as SYSTEM
                    try {
                        $Result = Invoke-TaskAsSYSTEM -TaskName $ES_Hive_Tasks[1] -FilePath REG -ArgumentList "UNLOAD HKU\ES_TEMP_$($UserProfile.SID)" -MaxRunInMinutes 1
                        if ($Result.LastTaskResult -ne 0) {
                            throw "Failed to unload user hive 'HKU\ES_TEMP_$($UserProfile.SID)'."
                        }
                    }
                    catch {
                        throw $_.Exception.Message
                    }
                }
            }

            if ($ProcessProfile -eq $true) {
                if (-not($RegistryResult.Value -eq "0x00023c00" -and $RegistryResult.Type -eq "REG_DWORD")) {
                    $FindingDetails += "Username:`t$($UserProfile.Username)" | Out-String
                    $FindingDetails += "User SID:`t`t$($UserProfile.SID)" | Out-String
                    $FindingDetails += "Profile Path:`t$($UserProfile.LocalPath)" | Out-String
                    if ($RegistryResult.Type -eq "(NotFound)") {
                        $Compliant = $false
                        $FindingDetails += "Value Name:`t$RegistryValueName (Not found) [finding]" | Out-String
                    }
                    else {
                        $FindingDetails += "Value Name:`t$($RegistryResult.ValueName)" | Out-String
                    }
                    if ($RegistryResult.Value -ne "0x00023c00") {
                        $Compliant = $false
                        $FindingDetails += "Value:`t`t$($RegistryResult.Value) [expected '0x00023c00']" | Out-String
                    }
                    else {
                        $FindingDetails += "Value:`t`t$($RegistryResult.Value)" | Out-String
                    }
                    if ($RegistryResult.Type -ne "REG_DWORD") {
                        $Compliant = $false
                        $FindingDetails += "Type:`t`t$($RegistryResult.Type) [expected 'REG_DWORD']" | Out-String
                    }
                    else {
                        $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails = "All user profiles have State configured to 0x00023c00"
        }
        else {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225225 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225225
        STIG ID    : APPNET0048
        Rule ID    : SV-225225r961038_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Developer certificates used with the .NET Publisher Membership Condition must be approved by the ISSO.
        DiscussMD5 : B6C699273C10A9BE6189F5DE2DE961C8
        CheckMD5   : 87B6F0C9EB05CCBEF1ED7877146287DC
        FixMD5     : 73F6127C03DCF4CE42285ED327E56A20
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Net4Ver = Get-DotNet4Version
    if ($Net4Ver -notmatch "^4\.0") {
        $Status = "Not_Applicable"
        $FindingDetails += "Installed .NET version is '$($Net4Ver)'.  This check only applies to .NET version 4.0 specifically so this requirement is NA." | Out-String
    }
    else {
        switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
            "32-bit" {
                $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319"
            }
            "64-bit" {
                $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319"
            }
        }

        # Execute CASPOL command and trim header lines
        $CaspolCommand = "$FrameworkPath\caspol.exe -m -lg"
        [System.Collections.ArrayList]$CaspolOutput = Invoke-Expression -Command $CaspolCommand
        $i = 0
        foreach ($Line in $CaspolOutput) {
            if ($Line -like "Please see http:*") {
                $CaspolOutput.RemoveRange(0, ($i + 1))
                break
            }
            $i++
        }
        $CaspolOutput = $CaspolOutput | Where-Object { $_ } # Remove empty lines from array

        $IsMatching = $CaspolOutput | Select-String -Pattern '1.6.' -SimpleMatch
        if ($IsMatching) {
            $Status = 'Not_Reviewed'
            $FindingDetails += "Review the code groups below for FullTrust and publisher keys in section 1.6." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $Status = 'NotAFinding'
            $FindingDetails += "Section 1.6 Publisher section does not exist.  No Publisher Membership Conditions are configured." | Out-String
            $FindingDetails += "" | Out-String
        }

        $FindingDetails += "Executed: $CaspolCommand" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $CaspolOutput.Trim() | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225226 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225226
        STIG ID    : APPNET0052
        Rule ID    : SV-225226r961041_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176
        Rule Title : Encryption keys used for the .NET Strong Name Membership Condition must be protected.
        DiscussMD5 : A9EC90A60848125D4BA5783C1CAA9335
        CheckMD5   : 35339B0570CD4B9BB4238F50BEF7C36D
        FixMD5     : C4888D52A487CDCAB113A1A169BC0ACC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Net4Ver = Get-DotNet4Version
    if ($Net4Ver -notmatch "^4\.0") {
        $Status = "Not_Applicable"
        $FindingDetails += "Installed .NET version is '$($Net4Ver)'.  This check only applies to .NET version 4.0 specifically so this requirement is NA." | Out-String
    }
    else {
        $Compliant = $true

        switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
            "32-bit" {
                $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319"
            }
            "64-bit" {
                $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319"
            }
        }

        # Execute CASPOL command and trim header lines
        $CaspolCommand = "$FrameworkPath\caspol.exe -all -lg"
        [System.Collections.ArrayList]$CaspolOutput = Invoke-Expression -Command $CaspolCommand
        $i = 0
        foreach ($Line in $CaspolOutput) {
            if ($Line -like "Please see http:*") {
                $CaspolOutput.RemoveRange(0, ($i + 1))
                break
            }
            $i++
        }
        $CaspolOutput = $CaspolOutput | Where-Object { $_ } # Remove empty lines from array

        $DefaultKeys = @("002400000480000094000000060200000024000052534131000400000100010007D1FA57C4AED9F0A32E84AA0FAEFD0DE9E8FD6AEC8F87FB03766C834C99921EB23BE79AD9D5DCC1DD9AD236132102900B723CF980957FC4E177108FC607774F29E8320E92EA05ECE4E821C0A5EFE8F1645C4C0C93C1AB99285D622CAA652C1DFAD63D745D6F2DE5F17E5EAF0FC4963D261C8A12436518206DC093344D5AD293", "00000000000000000400000000000000")
        $StrongNameValues = $CaspolOutput | Select-String "StrongName"
        $BetweenPattern = "StrongName - (.*?):"
        foreach ($Line in $StrongNameValues) {
            $Result = [regex]::Match($Line, $BetweenPattern).Groups[1].Value
            if ($Result -notin $DefaultKeys) {
                $Compliant = $false
            }
        }

        if ($Compliant -eq $true) {
            $Status = "Not_Applicable"
            $FindingDetails += "Only operating system (COTS) default code groups have Strong Name Membership Conditions so this requirement is NA." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $Status = "Not_Reviewed"
            $FindingDetails += "Strong Name Membership Condition detected for a not-default code group.  If the application(s) is COTS, this finding should be marked as Not Applicable.  Otherwise, ask the Systems Programmer how the private keys are protected."
            $FindingDetails += "" | Out-String
        }

        $FindingDetails += "Executed: $CaspolCommand" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $caspolOutput.Trim() | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225227 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225227
        STIG ID    : APPNET0055
        Rule ID    : SV-225227r960936_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120
        Rule Title : CAS and policy configuration files must be backed up.
        DiscussMD5 : 4839964DC8271228FE2192119A964B7C
        CheckMD5   : 0189F17DA36D084D4A00804077E42279
        FixMD5     : 78C86C494E6270E07C4F84EB4C1F5081
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Net4Ver = Get-DotNet4Version
    if ($Net4Ver -notmatch "^4\.0") {
        $Status = "Not_Applicable"
        $FindingDetails += "Installed .NET version is '$($Net4Ver)'.  This check only applies to .NET version 4.0 specifically so this requirement is NA." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225228 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225228
        STIG ID    : APPNET0060
        Rule ID    : SV-225228r1043178_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Remoting Services HTTP channels must utilize authentication and encryption.
        DiscussMD5 : 4DD3647667DF4CC530FC350D98C781AA
        CheckMD5   : 0DD08938703A1F8DD2A6C7FFEF7A7927
        FixMD5     : 068082AE10D66A14C5A484467AE36C20
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
        $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
    }
    else {
        $XmlElement = "channel"
        $XmlAttributeName = "ref"
        $XmlAttributeValue = "http server"
        $DotNetRemotingEnabled = $false
        $Compliant = $true # Set initial compliance for this STIG item to true.

        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Select-String -Pattern "(machine\.config$|\.exe\.config$)"
        foreach ($File in $allConfigFiles) {
            if (Test-Path $File) {
                $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
                if ($XML) {
                    $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                    if ($Node) {
                        $DotNetRemotingEnabled = $true
                        if ($Node.Port -ne "443") {
                            $Compliant = $false # Change compliance for this STIG item to false.
                            $FindingDetails += $File | Out-String
                            $FindingDetails += "Channel:`t$($XmlAttributeValue)" | Out-String
                            $FindingDetails += "Port:`t`t$($Node.Port)" | Out-String
                            $FindingDetails += "Confirm that this port is TLS encrypted." | Out-String
                            $FindingDetails += "" | Out-String
                        }
                    }
                }
            }
        }

        if ($DotNetRemotingEnabled -eq $false) {
            $Status = "Not_Applicable"
            $FindingDetails += "No machine.config or *.exe.config files found using .NET remoting with HTTP channel so this requirement is NA." | Out-String
        }
        elseif ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "No misconfigured machine.config or *.exe.config files detected." | Out-String
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225229 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225229
        STIG ID    : APPNET0061
        Rule ID    : SV-225229r1107247_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .Net Framework versions installed on the system must be supported.
        DiscussMD5 : DDDA22DE8C2A7934632CE05DA8D6575F
        CheckMD5   : CA17067EAA9736C09A53BF85C7104ED9
        FixMD5     : B9E18BC368F5AD3E1716CEC17E65725F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Compliant = $true

    # --- Begin Support Lifecycle list ---
    $EOLList = [System.Collections.Generic.List[System.Object]]::new()

    # .NET 3.5 SP1 (For Windows 10 1809+, Windows 11, and Windows Server 2019+)
    # https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework
    $NewObj = [PSCustomObject]@{
        Product     = "Net35"
        MinVersion  = [version]"2.0" # Minimum supported .NET version
        NextVersion = [version]"2.1" # Next .NET version
        EOL         = (Get-Date 01/09/2029)
    }
    $EOLList.Add($NewObj)

    # .NET 4
    # https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework
    $NewObj = [PSCustomObject]@{
        Product     = "Net4"
        MinVersion  = [version]"4.6.2" # Minimum supported .NET version
        NextVersion = [version]"4.7"   # Next .NET version
        EOL         = (Get-Date 01/12/2027)
    }
    $EOLList.Add($NewObj)

    # Windows Server 2012 R2 (.NET 3.5 only supported until Windows Server 2012 R2/2016 eol)
    # https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012-r2
    $NewObj = [PSCustomObject]@{
        Product     = "Server2012R2"
        MinVersion  = "NA" # Caption to be compared
        NextVersion = "NA" # Caption to be compared
        EOL         = (Get-Date 10/13/2026)
    }
    $EOLList.Add($NewObj)

    # Windows Server 2016 (.NET 3.5 only supported until Windows Server 2012 R2/2016 eol)
    # https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016
    $NewObj = [PSCustomObject]@{
        Product     = "Server2016"
        MinVersion  = "NA" # Caption to be compared
        NextVersion = "NA" # Caption to be compared
        EOL         = (Get-Date 01/12/2027)
    }
    $EOLList.Add($NewObj)
    # --- End Support Lifecycle list ---

    # Document operating system
    $OSName = (Get-CimInstance Win32_OperatingSystem).Caption
    if ("DisplayVersion" -in (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").Property) {
        $DisplayVersion = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion
    }
    elseif ("ReleaseId" -in (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").Property) {
        $DisplayVersion = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId
    }
    if ($DisplayVersion) {
        $OSName = "$($OSName) [$($DisplayVersion)]"
    }
    $FindingDetails += "Operating system:" | Out-String
    $FindingDetails += "---------------------------------" | Out-String
    $FindingDetails += "Name:`t$($OSName)" | Out-String
    $FindingDetails += "Version:`t$((Get-CimInstance Win32_OperatingSystem).Version)" | Out-String
    $FindingDetails += "" | Out-String

    # Document enabled .NET features
    $NetFx3 = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^NetFx3$|^NET-Framework-Core$)" -and $_.Enabled -eq $true}
    $NetFx4 = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^NetFx4$|^NET-Framework-45-Core$|^NetFx4-AdvSrvs$|^Microsoft-Windows-NetFx4-US-OC-Package$)" -and $_.Enabled -eq $true}
    $NetFxFeatures = @($NetFx3, $NetFx4)
    if ($NetFxFeatures) {
        $FindingDetails += "Enabled .NET Windows features:" | Out-String
        $FindingDetails += "---------------------------------" | Out-String
        foreach ($Feature in $NetFxFeatures) {
            $FindingDetails += $Feature.Name | Out-String
        }
    }
    else {
        $FindingDetails += "No .NET Windows features are enabled" | Out-String
    }
    $FindingDetails += "" | Out-String

    # Get .Net Frameworks' mscorlib.dll
    $FrameworksPath = @("$env:SYSTEMROOT\Microsoft.NET\Framework", "$env:SYSTEMROOT\Microsoft.NET\Framework64")
    $LibraryFiles = @()
    foreach ($Path in $FrameworksPath) {
        if (Test-Path $Path) {
            $LibraryFiles += Get-ChildItem -Path $Path -Recurse -Include mscorlib.dll
        }
    }
    if ($LibraryFiles) {
        $FindingDetails += "Library files:" | Out-String
        $FindingDetails += "---------------------------------" | Out-String
        foreach ($File in $LibraryFiles) {
            $FindingDetails += "File Path:`t`t`t$($File.VersionInfo.Filename)" | Out-String
            if ($File.VersionInfo.ProductVersion -like "2.0*" -and $NetFx3) {
                switch ($OSName) {
                    {$_ -like "*Windows 10*" -and [Version](Get-CimInstance Win32_OperatingSystem).Version -lt [Version]"10.0.17763"} {
                        if ([Version](Get-CimInstance Win32_OperatingSystem).Version -lt [Version]"10.0.17763") {
                            $Compliant = $false
                            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                            $FindingDetails += "OS Component:`t$true" | Out-String
                            $FindingDetails += "Support Ends:`t`tThis version of Windows 10 is EOL (see below) [finding]" | Out-String
                        }
                    }
                    {$_ -like "*Windows*Server 2012*R2*"} {
                        if ((Get-Date) -gt ($EOLList | Where-Object Product -EQ "Server2012R2").EOL) {
                            $Compliant = $false
                            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                            $FindingDetails += "OS Component:`t$true" | Out-String
                            $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Server2012R2").EOL -Format MM/dd/yyyy) [finding]" | Out-String
                        }
                        else {
                            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                            $FindingDetails += "OS Component:`t$true" | Out-String
                            $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Server2012R2").EOL -Format MM/dd/yyyy)" | Out-String
                        }
                    }
                    {$_ -like "*Windows*Server 2016*"} {
                        if ((Get-Date) -gt ($EOLList | Where-Object Product -EQ "Server2016").EOL) {
                            $Compliant = $false
                            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                            $FindingDetails += "OS Component:`t$true" | Out-String
                            $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Server2016").EOL -Format MM/dd/yyyy) [finding]" | Out-String
                        }
                        else {
                            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                            $FindingDetails += "OS Component:`t$true" | Out-String
                            $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Server2016").EOL -Format MM/dd/yyyy)" | Out-String
                        }
                    }
                    default {
                        if ((Get-Date) -gt ($EOLList | Where-Object Product -EQ "Net35").EOL) {
                            $Compliant = $false
                            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                            $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Net35").EOL -Format MM/dd/yyyy) [finding]" | Out-String
                        }
                        else {
                            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                            $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Net35").EOL -Format MM/dd/yyyy)" | Out-String
                        }
                    }
                }
            }
            elseif ([version]$File.VersionInfo.ProductVersion -ge "4.0") {
                if ([version]$File.VersionInfo.ProductVersion -ge ($EOLList | Where-Object Product -EQ "Net4").MinVersion -and [version]$File.VersionInfo.ProductVersion -lt ($EOLList | Where-Object Product -EQ "Net4").NextVersion) {
                    if ((Get-Date) -gt ($EOLList | Where-Object Product -EQ "Net4").EOL) {
                        $Compliant = $false
                        $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                        $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Net4").EOL -Format MM/dd/yyyy) [finding]" | Out-String
                    }
                    else {
                        $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                        $FindingDetails += "Support Ends:`t`t$(Get-Date ($EOLList | Where-Object Product -EQ "Net4").EOL -Format MM/dd/yyyy)" | Out-String
                    }
                }
                elseif ([version]$File.VersionInfo.ProductVersion -ge ($EOLList | Where-Object Product -EQ "Net4").NextVersion) {
                    $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
                }
                else {
                    $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion) [finding]" | Out-String
                }
            }
            else {
                $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion) [finding]" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        $FindingDetails += "Ref - https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Ref - https://support.microsoft.com/en-us/topic/clarification-on-the-support-life-cycle-for-the-net-framework-3-5-the-net-framework-3-0-and-the-net-framework-2-0-28621c7b-226c-7682-27f5-2e2a42db39c3" | Out-String
    }
    else {
        $FindingDetails = "A .Net Framework was not found."
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225230 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225230
        STIG ID    : APPNET0062
        Rule ID    : SV-225230r961908_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000635
        Rule Title : The .NET CLR must be configured to use FIPS approved encryption modules.
        DiscussMD5 : DD644CF29F7F45ACFF4538B95D2A89E8
        CheckMD5   : 82C7FB3F2CDA1EC0A6939854DF0BE281
        FixMD5     : 46071EE3AC1BC3C332B537C97332FB8D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
        $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
    }
    else {
        $XmlElement = "enforceFIPSPolicy"
        $XmlAttributeName = "enabled"
        $XmlAttributeValue = "false" # Non-compliant setting
        $Compliant = $true # Set initial compliance for this STIG item to true.

        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Select-String -Pattern "(machine\.config$|\.exe\.config$)"
        foreach ($File in $allConfigFiles) {
            if (Test-Path $File) {
                $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
                if ($XML) {
                    $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                    if ($Node) {
                        $Compliant = $false # Change compliance for this STIG item to false.
                        $FindingDetails += $File | Out-String
                        $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                        $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                        $FindingDetails += "`r`n"
                    }
                }
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "No machine.config or *.exe.config files found with 'enforceFIPSPolicy enabled=false'."
        }
        else {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225231 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225231
        STIG ID    : APPNET0063
        Rule ID    : SV-225231r961038_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : .NET must be configured to validate strong names on full-trust assemblies.
        DiscussMD5 : E211196DA56A0B202C24614BFB4DED4C
        CheckMD5   : 174A7179BD3F98C632A17BCC92834B52
        FixMD5     : 2C2EDE38EACB2C869380DBE28E2443D8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RegistryValueName = "AllowStrongNameBypass"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG

    $Compliant = $true

    switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
        "32-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework")
        }
        "64-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework")
        }
    }

    foreach ($RegistryPath in $RegistryPaths) {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        if ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        else {
            $RegistryResultValue = $RegistryResult.Value
        }

        if ($RegistryResult.Type -eq "(NotFound)") {
            $Compliant = $false
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        else {
            if ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            else {
                $Compliant = $false
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                if ($RegistryResult.Value -in $RegistryValue) {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                else {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                if ($RegistryResult.Type -eq $RegistryType) {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                else {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                }
            }
        }
        $FindingDetails += "" | Out-String
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225232 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225232
        STIG ID    : APPNET0064
        Rule ID    : SV-225232r1050651_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .Net applications that invoke NetFx40_LegacySecurityPolicy must apply previous versions of .NET STIG guidance.
        DiscussMD5 : 141C4CEC832605868C6670F260133A32
        CheckMD5   : D81973BA43B118D609B5530EBF43F24E
        FixMD5     : 22411F04642446AE070C7D81D2653ECA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Net4Ver = Get-DotNet4Version
    if ($Net4Ver -notmatch "^4\.0") {
        $Status = "Not_Applicable"
        $FindingDetails += "Installed .NET version is '$($Net4Ver)'.  This check only applies to .NET version 4.0 specifically so this requirement is NA." | Out-String
    }
    else {
        if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
            $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
        }
        else {
            $XmlElement = "NetFx40_LegacySecurityPolicy"
            $XmlAttributeName = "enabled"
            $XmlAttributeValue = "true" # Non-compliant setting
            $Compliant = $true # Set initial compliance for this STIG item to true.

            $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Select-String -Pattern "\.exe\.config$"
            foreach ($File in $allConfigFiles) {
                if ($File -like "*.exe.config" -and $File -notlike "$env:windir*" -and (Test-Path $File)) {
                    $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
                    if ($XML) {
                        $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                        if ($Node) {
                            $Compliant = $false # Change compliance for this STIG item to false.
                            $FindingDetails += $File | Out-String
                            $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                            $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                            $FindingDetails += "`r`n"
                        }
                    }
                }
            }

            if ($Compliant -eq $true) {
                $Status = "NotAFinding"
                $FindingDetails += "No *.exe.config files found with 'NetFx40_LegacySecurityPolicy enabled=true'."
            }
            else {
                $Status = "Open"
            }
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225233 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225233
        STIG ID    : APPNET0065
        Rule ID    : SV-225233r961608_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431
        Rule Title : Trust must be established prior to enabling the loading of remote code in .Net 4.
        DiscussMD5 : 0F0CA008731159C404BA2A0C6AF1DE38
        CheckMD5   : 4CEC356A4FF43E6F70EC89F92497AE4C
        FixMD5     : 0821C76AD87DA35131027E65AE40BB91
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
        $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
    }
    else {
        $XmlElement = "loadFromRemoteSources"
        $XmlAttributeName = "enabled"
        $XmlAttributeValue = "true" # Non-compliant setting
        $Compliant = $true # Set initial compliance for this STIG item to true.

        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Select-String -Pattern "\.exe\.config$"
        foreach ($File in $allConfigFiles) {
            if ($File -like "*.exe.config" -and (Test-Path $File)) {
                $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
                if ($XML) {
                    $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                    if ($Node) {
                        $Compliant = $false # Change compliance for this STIG item to false.
                        $FindingDetails += $File | Out-String
                        $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                        $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                        $FindingDetails += "`r`n"
                    }
                }
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "No *.exe.config files found with 'loadFromRemoteSources enabled=true'."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225234 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225234
        STIG ID    : APPNET0066
        Rule ID    : SV-225234r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .NET default proxy settings must be reviewed and approved.
        DiscussMD5 : 8114D96DAA09C2069E3735E7395E8054
        CheckMD5   : F7BC9911DD6AA2CB1689C1C23BF2840C
        FixMD5     : C2D53696F5251E36210ECD82D87934E1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
        $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
    }
    else {
        $Compliant = $true # Set initial compliance for this STIG item to true.

        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Select-String -Pattern "(machine\.config$|\.exe\.config$)"
        foreach ($File in $allConfigFiles) {
            if (Test-Path $File) {
                $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
                if ($XML) {
                    $DefaultProxy = ($XML | Select-Xml -XPath "//defaultProxy" | Select-Object -ExpandProperty "Node" | Select-Object *)
                    $BypassList = ($XML | Select-Xml -XPath "//defaultProxy/bypasslist" | Select-Object -ExpandProperty "Node" | Select-Object *)
                    $Module = ($XML | Select-Xml -XPath "//defaultProxy/module" | Select-Object -ExpandProperty "Node" | Select-Object *)
                    $Proxy = ($XML | Select-Xml -XPath "//defaultProxy/proxy" | Select-Object -ExpandProperty "Node" | Select-Object *)
                    if (-not((($DefaultProxy.enabled -eq $true) -or ($DefaultProxy.IsEmpty -eq $true -and $DefaultProxy.HasAttributes -eq $true)) -or ((($DefaultProxy.ChildNodes | Where-Object name -NE "#Whitespace") | Measure-Object).Count -eq 0) -or $Proxy.useSystemDefault -eq $true)) {
                        if ($DefaultProxy.enabled -eq $false -or $BypassList -or $Module -or $Proxy) {
                            $FindingDetails += $File | Out-String
                            if ($DefaultProxy.enabled -eq $false) {
                                $Compliant = $false
                                $FindingDetails += "Enabled:`t`t$($DefaultProxy.enabled)" | Out-String
                            }
                            if ($BypassList) {
                                $Compliant = $false
                                $FindingDetails += "BypassList:`tNOT CLEARED" | Out-String
                            }
                            if ($Module) {
                                $Compliant = $false
                                $FindingDetails += "Module:`t`tNOT CLEARED" | Out-String
                            }
                            if ($Proxy -and $Proxy.useSystemDefault -ne $true) {
                                $Compliant = $false
                                $FindingDetails += "Proxy:`t`tNOT CLEARED and 'useSystemDefault' is NOT True" | Out-String
                            }
                            $FindingDetails += "" | Out-String
                        }
                    }
                }
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "No machine.config or *.exe.config files found with 'defaultProxy enabled=false' or with 'bypasslist', 'module', or 'proxy' elements."
        }
        else {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225235 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225235
        STIG ID    : APPNET0067
        Rule ID    : SV-225235r960891_rule
        CCI ID     : CCI-000130
        Rule Name  : SRG-APP-000095
        Rule Title : Event tracing for Windows (ETW) for Common Language Runtime events must be enabled.
        DiscussMD5 : 507AF0046E8610FDBBC82E53383302AB
        CheckMD5   : BCE9D46590D017144C07E117515388F3
        FixMD5     : DD9F43992E4C2B0E378DE9552330AB63
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
        $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
    }
    else {
        $XmlElement = "etwEnable"
        $XmlAttributeName = "enabled"
        $XmlAttributeValue = "false" # Non-compliant setting
        $Compliant = $true # Set initial compliance for this STIG item to true.

        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Select-String -Pattern "(machine\.config$|\.exe\.config$)"
        foreach ($File in $allConfigFiles) {
            if (Test-Path $File) {
                $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
                if ($XML) {
                    $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                    if ($Node) {
                        $Compliant = $false # Change compliance for this STIG item to false.
                        $FindingDetails += $File | Out-String
                        $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                        $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                        $FindingDetails += "`r`n"
                    }
                }
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "No machine.config or *.exe.config files found with 'etwEnable enabled=false'."
        }
        else {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225236 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225236
        STIG ID    : APPNET0070
        Rule ID    : SV-225236r1069477_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431
        Rule Title : Software utilizing .Net 4.0 must be identified and relevant access controls configured.
        DiscussMD5 : D7F9FEE86F2ADACAA15D6D1CA8E21E4B
        CheckMD5   : 658BE0EB7D5CC3FA6199F42DE728523F
        FixMD5     : 0800EAC891D5DB49631D6BB19F6BEA7C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
        $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
    }
    else {
        $Net40Files = [System.Collections.Generic.List[System.Object]]::new()
        foreach ($File in (Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Where-Object {$_ -notlike "$($env:windir)*"})) {
            $ExePath = $File -replace "\.config$"
            if (Test-Path $ExePath) {
                $Line = (Select-String -Path $ExePath -Pattern "NETFramework,Version=v4\.\d{1,}\.{0,1}\d{0,}" -AllMatches)
                if ($Line.Matches) {
                    $Versions = @()
                    foreach ($Value in $Line.Matches.Value) {
                        $Versions += $(((($Value -split "=v")[1] -split " ")[0]).Trim())
                    }
                    if ("4.0" -in $Versions) {
                        $NewObj = [PSCustomObject]@{
                            ExePath  = $ExePath
                            Versions = $(($Versions | Select-Object -Unique) -join ', ')
                        }
                        $Net40Files.Add($NewObj)
                    }
                }
            }
        }
        if (($Net40Files | Measure-Object).Count -gt 0) {
            foreach ($File in $Net40Files) {
                $FindingDetails += $File.ExePath | Out-String
                $FindingDetails += "Net4Runtimes: $($File.Versions)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $Status = "NotAFinding"
            $FindingDetails += "No applications found requiring .NET 4.0 specifically."
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225237 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225237
        STIG ID    : APPNET0071
        Rule ID    : SV-225237r1043178_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Remoting Services TCP channels must utilize authentication and encryption.
        DiscussMD5 : B131C0105162474C2CB36DAC9C8B58AA
        CheckMD5   : 580BCAD304DACC43E991D7A790AFC7F1
        FixMD5     : 32C581F83639C31BC9A8B3ECE9B24F39
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (-not(Test-Path -Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt)) {
        $FindingDetails += "*** $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt does not exist so unable to complete this check.  Consider increasing the -FileSearchTimeout parameter. ***" | Out-String
    }
    else {
        $XmlElement = "channel"
        $XmlAttributeName = "ref"
        $XmlAttributeValue = "tcp"
        $DotNetRemotingEnabled = $false
        $Compliant = $true # Set initial compliance for this STIG item to true.

        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_FilesToScan.txt | Select-String -Pattern "(machine\.config$|\.exe\.config$)"
        foreach ($File in $allConfigFiles) {
            if (Test-Path $File) {
                $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
                if ($XML) {
                    $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                    if ($Node) {
                        $DotNetRemotingEnabled = $true
                        if ($Node.Secure -ne $true) {
                            if (-not($Node.Secure)) {
                                $Secure = "(NOT CONFIGURED)"
                            }
                            else {
                                $Secure = $Node.Secure
                            }
                            $Compliant = $false # Change compliance for this STIG item to false.
                            $FindingDetails += $File | Out-String
                            $FindingDetails += "Channel:`t$($XmlAttributeValue)" | Out-String
                            $FindingDetails += "Secure:`t$Secure" | Out-String
                            $FindingDetails += "" | Out-String
                        }
                    }
                }
            }
        }

        if ($DotNetRemotingEnabled -eq $false) {
            $Status = "Not_Applicable"
            $FindingDetails += "No machine.config or *.exe.config files found using .NET remoting with TCP channel so this requirement is NA." | Out-String
        }
        elseif ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "No misconfigured *.exe.config files detected." | Out-String
        }
        else {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V225238 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225238
        STIG ID    : APPNET0075
        Rule ID    : SV-225238r1069480_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383
        Rule Title : Update and configure the .NET Framework to support TLS.
        DiscussMD5 : 29BCCFF06B9CC0EB41C5DF69B941F7B3
        CheckMD5   : 43ECED46952E69795E5AC2372E022DA2
        FixMD5     : 56D6C7B73A0F3447DF59B4F051C5A092
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Release = Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue
    if ($Release -ge 393295) {
        $FindingDetails += ".NET Framework 4 version is 4.6 or later." | Out-String
        $FindingDetails += "" | Out-String
        $RegistryValueName = "SystemDefaultTlsVersions"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
    }
    else {
        $FindingDetails += ".NET Framework 4 version is less than 4.6." | Out-String
        $FindingDetails += "" | Out-String
        $RegistryValueName = "SchUseStrongCrypto"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
    }

    $Compliant = $true

    switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
        "32-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")
        }
        "64-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319")
        }
    }

    foreach ($RegistryPath in $RegistryPaths) {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        if ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        else {
            $RegistryResultValue = $RegistryResult.Value
        }

        if ($RegistryResult.Type -eq "(NotFound)") {
            $Compliant = $false
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        else {
            if ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            else {
                $Compliant = $false
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                if ($RegistryResult.Value -in $RegistryValue) {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                else {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                if ($RegistryResult.Type -eq $RegistryType) {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                else {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                }
            }
        }
        $FindingDetails += "" | Out-String
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCtVAqqFBVynQmZ
# cKrJRdLErVltWAe/qU2zL4Rwc6Dk/6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDv31S+GX/qJk57Z/nc68+/krOOSMKR+7PVFLwDiE8SsTANBgkqhkiG9w0BAQEF
# AASCAQCV4QM5xWuA4X5QU1ZGzPVEpGpocZ5MuPMH3/AqnIvg9DLH862QXGHGlsju
# /arJH2ywZZ7GYsfR0RvRFellc+8VGF3M5QZ6iHOfq50CmMrtF+qBpgGAgmslv4Np
# 9D9Uv63Mhw6548rD/4eAqfkhoVeYtYeTogR5+B/5LCIY8ccanVbcllIzQ1GTkjq4
# FSRz7Qg4PeC9FHH53t4prvKCAzgAvSLkXLwVlUHS5QDQwqk99IlJSKOJ8hYvFQK3
# /MvC2A1oEUvuAsPG8GqxoEEWUbKY//B+9CRnJXfqhYIxjplv0WnD1s9ARV7/2r20
# QOYU9R/waPfL/yfvOA4ouLmsHrfwoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTYyMlowLwYJKoZIhvcNAQkEMSIEINBccnm/JLyM3ITWwwYGchMeXz7F
# SEnqKJITe8+GSa2vMA0GCSqGSIb3DQEBAQUABIICAKY1adnOLIbxjsr5AXcSvF3K
# EE7L0LmhoXTzxQP3TtbY1v2U/VVSrLm6cPiMAVUIhjPFTAW2uwIHrkO8L97jxScI
# vAR0JErEOfs+WfN8YyF9O/yH05ghg7fguHDqT0f8Pt1GnHbWjakleqgy47WFHPF2
# NRViZNapoLOQH8uPZcLeeXSqZmxeAcmFw0p75rBheY8pF3MMIf6joRDSFB/WoY3L
# mCxvpu91LW4mHRzVTmi1GwxoqL3YzS5GrQ4VvOFoyY89oJkl8t9tLoT7GosqyPKh
# G551tIRAjpmcJAJFHnYnj2gChDZGAcrg4Lr19np/GpLg+24bScJ6orGAoHW1WG8b
# 7ftS0drrK9uLZOUln1/eUiaAlmobrOlkU+YgEtzpl5PDOS2/o0XVc1jDvzNgLX3k
# /yBCukGZ1Lg0ta/wcxZpoAZ7Zj5GxId+pwndBSqe353voIEGCRoFOfMc/Ao3TeFV
# 93TPSJzyy/PsB9iiRZ6uSqWIAZfXYi5NXGI1TxnkIqNFm3u0LrqTsmhG4KHAv97C
# p9o634etUM6OrbJX/4pdnHCSMIAVPeYnuJ71ddxbRbv4oeIQ/Bb+mX3CntJOfz/5
# RQyEq46lScz1jVwpzV+P1MB+DDh2BnqRh+8KfFsyzuQ1z4QhunyY5EbzcUl3YV4b
# wVba0AcbZV+6rACJHr+n
# SIG # End signature block
