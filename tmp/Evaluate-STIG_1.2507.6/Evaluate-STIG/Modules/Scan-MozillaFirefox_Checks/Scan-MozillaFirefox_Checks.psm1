##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Mozilla Firefox
# Version:  V6R6
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V251545 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251545
        STIG ID    : FFOX-00-000001
        Rule ID    : SV-251545r961683_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The installed version of Firefox must be supported.
        DiscussMD5 : 48E75F6BECA53D0015CEAA6797EC0D84
        CheckMD5   : A4402EE69FE655D0314D04783C2F6C92
        FixMD5     : 804D3101A78E5774C6F7EDADD85B6FD2
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
    If ($IsLinux) {
        # Get Firefox install on Linux systems
        if ((Test-Path /usr/lib64/firefox/) -or (Test-Path /usr/lib/firefox/) -or (Test-Path /etc/firefox/) -or (Test-Path /usr/bin/firefox/)) {
            $pkg_mgr = (Get-Content /etc/os-release | grep "ID_LIKE=").replace("ID_LIKE=", "").replace('"', "")
            switch ($pkg_mgr) {
                "debian" {
                    $FirefoxInstalls = @{
                        DisplayName     = $(apt -qq list firefox 2>/dev/null | grep installed)
                        DisplayVersion  = ""
                        InstallLocation = ""
                    }
                }
                "fedora" {
                    $FirefoxInstalls = @{
                        DisplayName     = $(rpm -qa | grep -i Firefox)
                        DisplayVersion  = ""
                        InstallLocation = ""
                    }
                }
            }
        }
        $FindingDetails += "Package entries for Firefox:" | Out-String
    }
    Else {
        $FirefoxInstalls = Get-InstalledSoftware | Where-Object DisplayName -match "^(Mozilla Firefox|Firefox Developer)"
        $FindingDetails += "Apps and Features entries for Firefox:" | Out-String
    }

    $FindingDetails += "" | Out-String
    ForEach ($Item in $FirefoxInstalls) {
        $FindingDetails += "Name:`t$($Item.DisplayName)" | Out-String
        $FindingDetails += "Version:`t$($Item.DisplayVersion)" | Out-String
        $FindingDetails += "Path:`t`t$($Item.InstallLocation)" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V251546 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251546
        STIG ID    : FFOX-00-000002
        Rule ID    : SV-251546r961869_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000560
        Rule Title : Firefox must be configured to allow only TLS 1.2 or above.
        DiscussMD5 : 42BC509DB9620CA2B89F6CCF4A774C31
        CheckMD5   : 7B93C99F4490748E6CE94F158C7D9DCB
        FixMD5     : 776E48FC8DC0E8A2A22E4D1E2B13D3B9
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
    $RegistryValueName = "SSLVersionMin"  # Value name identified in STIG
    $RegistryValue = @("tls1.2","tls1.3")  # Value(s) expected in STIG
    $SettingName = "Minimum SSL version enabled"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251547 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251547
        STIG ID    : FFOX-00-000003
        Rule ID    : SV-251547r1067550_rule
        CCI ID     : CCI-000187
        Rule Name  : SRG-APP-000177
        Rule Title : Firefox must be configured to ask which certificate to present to a website when a certificate is required.
        DiscussMD5 : C5CA27EBA1C54D26B0EA9F7281771A61
        CheckMD5   : FE9FEF11525DF283F4713BD551E988A9
        FixMD5     : 7BB34BB52F7DA6D2C28291B39D4B520A
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName) | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)."security.default_personal_cert"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "security.default_personal_cert"; Value = "Ask Every Time"; Status = "locked" })

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251548 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251548
        STIG ID    : FFOX-00-000004
        Rule ID    : SV-251548r1067552_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not automatically check for updated versions of installed search plugins.
        DiscussMD5 : 6349895DA4BBEEB8546993F941EF6E39
        CheckMD5   : 388707D3D4DDCC0047881DC0266DD003
        FixMD5     : 54E596995778D3D697CD8B842A28C03B
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName) | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)."browser.search.update"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "browser.search.update"; Value = "false"; Status = "locked"})


    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251549 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251549
        STIG ID    : FFOX-00-000005
        Rule ID    : SV-251549r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not automatically update installed add-ons and plugins.
        DiscussMD5 : 79AD0AA0865CA1BD20A5287BD6A83024
        CheckMD5   : E07067845A2C874FAA95629080CAA37B
        FixMD5     : 648355C8DEFB7F99B591801D1C462EB4
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
    $RegistryValueName = "ExtensionUpdate"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Extension Update"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251550 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251550
        STIG ID    : FFOX-00-000006
        Rule ID    : SV-251550r961194_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : Firefox must be configured to not automatically execute or download MIME types that are not authorized for auto-download.
        DiscussMD5 : 1DBA719D0489DE6C0D64E0FB098FC2F3
        CheckMD5   : FF87054B2E2A093272249803BD9A4027
        FixMD5     : 38575D76F287FB8BE93038497185F1D1
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
    If ($IsLinux) {
        $Status = "Not_Reviewed"
    }
    Else {
        $ExtensionsToEval = @("HTA","JSE","JS","MOCHA","SHS","VBE","VBS","SCT","WSC","FDF","XFDF","LSL","LSO","LSS","IQY","RQY","DOS","BAT","PS","EPS","WCH","WCM","WB1","WB3","WCH","WCM","AD")
        $Compliant = $true
        $ProfileFound = $false

        # Check if the UserToProcess has utilized Firefox
        $ProfileList = Get-UsersToEval
        $UserProfilePath = ($ProfileList | Where-Object SID -EQ $UserSID).LocalPath

        If ($UserProfilePath -and (Test-Path -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles")) {
            $ProfileFound = $true
            $AF_UserHeader = $true

            $HandlersJson = @(Get-ChildItem -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles" -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "handlers.json")
        }
        Else {
            # Find a user that has utilized Firefox
            Foreach ($UserProfile in $ProfileList) {
                $UserProfilePath = $UserProfile.LocalPath
                If ((Test-Path -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles")) {
                    $ProfileFound = $true
                    $FindingDetails += "Evaluate-STIG intended to utilize $($Username), but the user has NOT utilized Firefox on this system." | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "User Profile Evaluated: $($UserProfile.Username)" | Out-String
                    $FindingDetails += "" | Out-String

                    $HandlersJson = @(Get-ChildItem -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles" -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "handlers.json")
                    break
                }
            }
        }
        If ($ProfileFound) {
            If ($HandlersJson) {
                $Config = New-Object System.Collections.Generic.List[System.Object]
                $Json = (Get-Content $HandlersJson.FullName | ConvertFrom-Json).mimeTypes
                ForEach ($Item in $Json.PSObject.Properties) {
                    If ($Item.Value.extensions -in $ExtensionsToEval) {
                        If ($Item.Value.ask -eq $true) {
                            $Action = "Always Ask"
                        }
                        ElseIf ($Item.Value.action -eq 0) {
                            $Action = "Save File"
                        }
                        Else {
                            $Compliant = $false
                            $Action = "NOT set to 'Save File' or 'Always Ask' [Finding]"
                        }
                        $Extensions
                        $Handlers = $Item.Value.handlers

                        $NewObj = [PSCustomObject]@{
                            Extension = $Item.Value.extensions
                            Action    = $Action
                            Handlers  = $Handlers
                        }
                        $Config.Add($NewObj)
                    }
                }
                If ($Config) {
                    $FindingDetails += "The following extensions in question are configured:" | Out-String
                    $FindingDetails += "" | Out-String
                    ForEach ($Item in $Config) {
                        $FindingDetails += "Extension:`t$($Item.Extension)" | Out-String
                        $FindingDetails += "Action:`t`t$($Item.Action)" | Out-String
                        $FindingDetails += "Handlers:`t`t$($Item.Handlers)" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                Else {
                    $FindingDetails += "None of the extensions in question are configured." | Out-String
                }
            }
            Else {
                $FindingDetails += "None of the extensions in question are configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        Else {
            $FindingDetails += "NO users have utilized Firefox on this system." | Out-String
            $FindingDetails += "" | Out-String
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
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

Function Get-V251551 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251551
        STIG ID    : FFOX-00-000007
        Rule ID    : SV-251551r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to disable form fill assistance.
        DiscussMD5 : 88FE2984AD76E405475B777807354CAF
        CheckMD5   : 23FB987C050D295FC77D259EC0F925F2
        FixMD5     : 5DD9EE9BE48333FE2A77892B74E34A2B
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
    $RegistryValueName = "DisableFormHistory"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Form History"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251552 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251552
        STIG ID    : FFOX-00-000008
        Rule ID    : SV-251552r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not use a password store with or without a master password.
        DiscussMD5 : 98E30F776E84AEF02F690860D466B8EA
        CheckMD5   : EFFD52F791C6A749929080B77678D29B
        FixMD5     : 4D1E3AD842344B5CBEE6E1F7288C23C5
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
    $RegistryValueName = "PasswordManagerEnabled"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Password Manager"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG


        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251553 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251553
        STIG ID    : FFOX-00-000009
        Rule ID    : SV-251553r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to block pop-up windows.
        DiscussMD5 : 3E063DB24C03DA1E75156BA7B57B0FAD
        CheckMD5   : 9E3BA0E4C37C7F8A6D7CDEF7CCAC2C61
        FixMD5     : 8C9242E6675C242C419DCD058489E10D
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
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking"  # Registry path identified in STIG
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Default"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Block pop-ups from websites"; SettingState = "Enabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Do not allow preferences to be changed"; SettingState = "Enabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.PopupBlocking.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $RegistryResult.Value
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType = $Item.Type[0]
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType)']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
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

Function Get-V251554 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251554
        STIG ID    : FFOX-00-000010
        Rule ID    : SV-251554r1067554_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to prevent JavaScript from moving or resizing windows.
        DiscussMD5 : 6654A8EFC5E6BCA4EBA39F0B4EAFAD80
        CheckMD5   : A1743B428D603E58F991F57081E8B21A
        FixMD5     : FEE8D6DE0120380FFC49435B1969518B
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName) | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)."dom.disable_window_move_resize"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "dom.disable_window_move_resize"; Value = "true"; Status = "locked"})

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251555
        STIG ID    : FFOX-00-000011
        Rule ID    : SV-251555r1067556_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to prevent JavaScript from raising or lowering windows.
        DiscussMD5 : 818F18A7C868F6966E2504F36ED3F4D6
        CheckMD5   : 79A155EC3FEA253D2AFEC71ED8AF12FD
        FixMD5     : B92AC0DF225A6FCB565F59E52C21AC9D
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName) | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)."dom.disable_window_flip"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "dom.disable_window_flip"; Value = "true"; Status = "locked"})

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251557
        STIG ID    : FFOX-00-000013
        Rule ID    : SV-251557r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to disable the installation of extensions.
        DiscussMD5 : 17B03497D19A1099908A76309E8B381D
        CheckMD5   : C0B2C534ECFB22FDFED00D0222898BA0
        FixMD5     : 4623451ABD9C4C22460573EF43A6A87F
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
    $RegistryValueName = "Default"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Allow add-on installs from websites"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.InstallAddonsPermission.$($RegistryValueName) | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.InstallAddonsPermission
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251558 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251558
        STIG ID    : FFOX-00-000014
        Rule ID    : SV-251558r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Background submission of information to Mozilla must be disabled.
        DiscussMD5 : 5F703415B65F993877D699BEA1049DD0
        CheckMD5   : 67C089AFA448193C179253EEBA37CA34
        FixMD5     : 8794B12107E7F4C02B6D436802F20F29
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
    $RegistryValueName = "DisableTelemetry"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Telemetry"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251559
        STIG ID    : FFOX-00-000015
        Rule ID    : SV-251559r961167_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266
        Rule Title : Firefox development tools must be disabled.
        DiscussMD5 : 3DAF22C9517AED30C4B86134A6183A30
        CheckMD5   : 51731277B4E484019D848F39BB0F419C
        FixMD5     : 8D89E3E3B121307741FE626A0841EE2E
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
    $RegistryValueName = "DisableDeveloperTools"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Developer Tools"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251560 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251560
        STIG ID    : FFOX-00-000016
        Rule ID    : SV-251560r1067559_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Firefox must have the DOD root certificates installed.
        DiscussMD5 : EACF71C2B190094FF50A1E5A4AEECB9C
        CheckMD5   : F5E02166005CAD1B21EC995B85CEA542
        FixMD5     : 2072C0CF5D3343B163160745C3F94897
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
    If ($IsLinux) {
        $Status = "Not_Reviewed"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Certificates"  # Registry path identified in STIG
        $RegistryValueName = "ImportEnterpriseRoots"  # Value name identified in STIG
        $RegistryValue = @("1", "true")  # Value(s) expected in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Import Enterprise Roots"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | Out-String

            If ($ScanType -in "Classified") {
                $InstalledCAs = Get-ChildItem -Path Cert:Localmachine\root | Where-Object Subject -Match "^CN=NSS Root" | Select-Object Subject, Thumbprint, NotAfter
                $Compliant = $true
                If ($InstalledCAs) {
                    ForEach ($CA in $InstalledCAs) {
                        $FindingDetails += "Subject:`t`t$($CA.Subject)" | Out-String
                        $FindingDetails += "Thumbprint:`t$($CA.Thumbprint)" | Out-String
                        $FindingDetails += "NotAfter:`t`t$($CA.NotAfter)" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "SIPR root certs not installed."
                }
            }
            Else {
                # Build list of DoD Root CAs
                $CAs = New-Object System.Collections.Generic.List[System.Object]
                $CAs.Add([PSCustomObject]@{CA = "DoD Root CA 3"; Subject = "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US"; Thumbprint = "D73CA91102A2204A36459ED32213B467D7CE97FB"; NotAfter = "12/30/2029"})
                $CAs.Add([PSCustomObject]@{CA = "DoD Root CA 4"; Subject = "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US"; Thumbprint = "B8269F25DBD937ECAFD4C35A9838571723F2D026"; NotAfter = "7/25/2032"})
                $CAs.Add([PSCustomObject]@{CA = "DoD Root CA 5"; Subject = "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US"; Thumbprint = "4ECB5CC3095670454DA1CBD410FC921F46B8564B"; NotAfter = "6/14/2041"})

                $InstalledCAs = Get-ChildItem -Path Cert:Localmachine\root | Where-Object Subject -Like "*DoD*" | Select-Object Subject, Thumbprint, NotAfter
                $Compliant = $true
                ForEach ($CA in $CAs) {
                    $FindingDetails += "Subject:`t`t$($CA.Subject)" | Out-String
                    $FindingDetails += "Thumbprint:`t$($CA.Thumbprint)" | Out-String
                    $FindingDetails += "NotAfter:`t`t$($CA.NotAfter)" | Out-String
                    If ($InstalledCAs | Where-Object { ($_.Subject -eq $CA.Subject) -and ($_.Thumbprint -eq $CA.Thumbprint) }) {
                        $FindingDetails += "Installed:`t`t$true" | Out-String
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Installed:`t`t$false" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }
            }
            If ($Compliant -eq $true) {
                $Status = "NotAFinding"
            }
            Else {
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

Function Get-V251562 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251562
        STIG ID    : FFOX-00-000018
        Rule ID    : SV-251562r987660_rule
        CCI ID     : CCI-002355
        Rule Name  : SRG-APP-000326
        Rule Title : Firefox must prevent the user from quickly deleting data.
        DiscussMD5 : BADFB87F4895A4747C43FDF6F2F99BF5
        CheckMD5   : E44F4B8109B4A65B18E2790D5C87BC93
        FixMD5     : EC4241CED4EFC89ABD4688C58B286167
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
    $RegistryValueName = "DisableForgetButton"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Forget Button"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251563 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251563
        STIG ID    : FFOX-00-000019
        Rule ID    : SV-251563r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox private browsing must be disabled.
        DiscussMD5 : 7E5199D7CD52B163162481B181FA442D
        CheckMD5   : CFACF046576FD2711D79A9D1C30A53C4
        FixMD5     : 8899888081399441CB9899970D57E465
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
    $RegistryValueName = "DisablePrivateBrowsing"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Private Browsing"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251564 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251564
        STIG ID    : FFOX-00-000020
        Rule ID    : SV-251564r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox search suggestions must be disabled.
        DiscussMD5 : 6EBAD9A9BD06B4AFC9958B8F165BBDFD
        CheckMD5   : FE8F0ED94DAC8BA8F0B39AFB89AC7048
        FixMD5     : D6638820EAAACFC49B33C272884C4808
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
    $RegistryValueName = "SearchSuggestEnabled"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Search Suggestions"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251565 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251565
        STIG ID    : FFOX-00-000021
        Rule ID    : SV-251565r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox autoplay must be disabled.
        DiscussMD5 : 2CD8486230D262657F5766A0A57F2CDF
        CheckMD5   : A5F4D9A4B2461D134F2703C4709F9471
        FixMD5     : 8D67CCBCB32FD4A5BE8331CB77767994
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
    $RegistryValueName = "Default"  # Value name identified in STIG
    $RegistryValue = @("block-audio-video")  # Value(s) expected in STIG
    $SettingName = "Default autoplay level"  # GPO setting name identified in STIG
    $SettingState = "Enabled (Block Audio and Video)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Permissions.AutoPlay.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.Permissions.Autoplay
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay"  # Registry path identified in STIG
        $RegistryType = "REG_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251566 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251566
        STIG ID    : FFOX-00-000022
        Rule ID    : SV-251566r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox network prediction must be disabled.
        DiscussMD5 : 98804EC71EC1C15743827CCA0C7ACCE9
        CheckMD5   : EBF391BECFA630D0EC7AA822B3232842
        FixMD5     : 84A97B8399702BD6AD9BFB306AE71DC7
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
    $RegistryValueName = "NetworkPrediction"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Network Prediction"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251567 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251567
        STIG ID    : FFOX-00-000023
        Rule ID    : SV-251567r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox fingerprinting protection must be enabled.
        DiscussMD5 : CC358F14E9B08A7D7A8634525B44DF1D
        CheckMD5   : 34DA9E15267FAD4FEA120561938306BB
        FixMD5     : 7CED632A45B76831C207F2672C39B9F5
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
    $RegistryValueName = "Fingerprinting"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Fingerprinting"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.EnableTrackingProtection.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.EnableTrackingProtection
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251568 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251568
        STIG ID    : FFOX-00-000024
        Rule ID    : SV-251568r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox cryptomining protection must be enabled.
        DiscussMD5 : F082A6EC19DA75AC4138EFFF0BCFC265
        CheckMD5   : BAAAFB8166D005389670C94CFDF3CF08
        FixMD5     : ADC6F87FCFF4D5997D822184C698151A
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
    $RegistryValueName = "Cryptomining"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Cryptomining"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.EnableTrackingProtection.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.EnableTrackingProtection
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251569 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251569
        STIG ID    : FFOX-00-000025
        Rule ID    : SV-251569r1067561_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox Enhanced Tracking Protection must be enabled.
        DiscussMD5 : E60BC4E6E77FC8457EF94C9D68EA6D42
        CheckMD5   : 6F8908186352DAFAD7308157DC2F176A
        FixMD5     : A00C1149FE1BAF32FFBA97E64A12D862
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName) | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)."browser.contentblocking.category"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "browser.contentblocking.category"; Value = "strict"; Status = "locked"})

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251570 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251570
        STIG ID    : FFOX-00-000026
        Rule ID    : SV-251570r1067563_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox extension recommendations must be disabled.
        DiscussMD5 : 3E80DE6FB18FF08EBD2C9A8BF96308FC
        CheckMD5   : 4BE2131B716CBB4A7D36EDF6198614E7
        FixMD5     : 54D9E8D11B77407EE23FCF78CEA7689E
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName) | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)."extensions.htmlaboutaddons.recommendations.enabled"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "extensions.htmlaboutaddons.recommendations.enabled"; Value = "false"; Status = "locked" })

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251571 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251571
        STIG ID    : FFOX-00-000027
        Rule ID    : SV-251571r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox deprecated ciphers must be disabled.
        DiscussMD5 : A375284A039877F7774E78056CD1D6D7
        CheckMD5   : 965AB827D44C5D7B5D9037EB4A61DCBD
        FixMD5     : 98B7C1968813E3446564D8B21FE95AE9
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
    $RegistryValueName = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisabledCiphers.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.DisabledCiphers
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251572
        STIG ID    : FFOX-00-000028
        Rule ID    : SV-251572r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must not recommend extensions as the user is using the browser.
        DiscussMD5 : 8ACD6EFFF0FEE443CC46754594E5B3FE
        CheckMD5   : 148A479BB6E0222E030F08943D7025AC
        FixMD5     : 84AA96469607E55B058C9717C0C4FC59
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
    $RegistryValueName = "ExtensionRecommendations"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Extension Recommendations"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.UserMessaging.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.UserMessaging
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\UserMessaging"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251573 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251573
        STIG ID    : FFOX-00-000029
        Rule ID    : SV-251573r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Firefox New Tab page must not show Top Sites, Sponsored Top Sites, Pocket Recommendations, Sponsored Pocket Stories, Searches, Highlights, or Snippets.
        DiscussMD5 : 0375150630A5D4BA5B987734139BAD93
        CheckMD5   : 4F0E8A1737E71061B075CA03656497FB
        FixMD5     : 4EA87054FB25E7871D624459F99AB11C
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
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Search"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Search"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "TopSites"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Top Sites"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "SponsoredTopSites"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Sponsored Top Sites"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Pocket"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Recommended by Pocket"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "SponsoredPocket"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Sponsored Pocket Stories"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Highlights"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Download History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Snippets"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Snippets"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Do not allow settings to be changed"; SettingState = "Enabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType  = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.FirefoxHome.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $RegistryResult.Value
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType  = $Item.Type[0]
            $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome"  # Registry path identified in STIG

            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -in $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType )']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
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

Function Get-V251577 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251577
        STIG ID    : FFOX-00-000033
        Rule ID    : SV-251577r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured so that DNS over HTTPS is disabled.
        DiscussMD5 : B36F3F6FED9C9ACA37F5463983532DC1
        CheckMD5   : C60AC6A41D18FEE8151F78B83DD37D8E
        FixMD5     : 6CFA9D232737E287EE594AEE606A01B5
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
    $RegistryValueName = "Enabled"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Enabled"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DNSOverHTTPS.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.DNSOverHTTPS
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251578 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251578
        STIG ID    : FFOX-00-000034
        Rule ID    : SV-251578r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox accounts must be disabled.
        DiscussMD5 : F99A40571A2B3AE5EA215E43DC76F96D
        CheckMD5   : 3062FBA07BA9F5B5DAB7B2462352CDB9
        FixMD5     : 4804665993FF3CC783D5183559C4124D
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
    $RegistryValueName = "DisableFirefoxAccounts"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Firefox Accounts"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251580 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251580
        STIG ID    : FFOX-00-000036
        Rule ID    : SV-251580r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox feedback reporting must be disabled.
        DiscussMD5 : 27F2A5F22A46A465359378F174F60B11
        CheckMD5   : 04FAFEFC27383AE0D7D29F67078827D7
        FixMD5     : 96654594A3D8C2E86EEA29B4346E4DFC
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
    $RegistryValueName = "DisableFeedbackCommands"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Feedback Commands"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251581 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251581
        STIG ID    : FFOX-00-000037
        Rule ID    : SV-251581r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox encrypted media extensions must be disabled.
        DiscussMD5 : 9752BB4D67E74615E29F4C2001E9ED0F
        CheckMD5   : 3AE7E8F0F201984F502C698CDE7E3F77
        FixMD5     : FACD37E4BBFA13F6C2146D5D9F67FA73
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
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions"  # Registry path identified in STIG
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Enabled"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Enable Encrypted Media Extensions"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Lock Encrypted Media Extensions"; SettingState = "Enabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType  = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.EncryptedMediaExtensions.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $RegistryResult.Value
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType  = $Item.Type[0]
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType)']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
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

Function Get-V252881 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252881
        STIG ID    : FFOX-00-000017
        Rule ID    : SV-252881r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not delete data upon shutdown.
        DiscussMD5 : D9AEB3CCF455E02DC1665B827ECA5498
        CheckMD5   : 2C2F6F7E5961E77B55D0E5FB3CF34E4F
        FixMD5     : 7AD9A660966DCBBB82671E0F5ED4913F
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
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Sessions"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Active Logins"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "History"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Browsing History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Cache"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Cache"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Cookies"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Cookies"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Downloads"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Download History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "FormData"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Form & Search History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Locked"; SettingState = "Enabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "OfflineApps"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Offline Website Data"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "SiteSettings"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Site Preferences"; SettingState = "Disabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType  = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.SanitizeOnShutdown.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $RegistryResult.Value
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType  = $Item.Type[0]
            $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown"  # Registry path identified in STIG

            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType)']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
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

Function Get-V252908 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252908
        STIG ID    : FFOX-00-000038
        Rule ID    : SV-252908r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Pocket must be disabled.
        DiscussMD5 : 85D11C29735E5A2BAE33A19F540232DE
        CheckMD5   : 3E25841FABC1C531D9DB4F7F34C3C464
        FixMD5     : 6DB187648EBADD7A4083B9E5EB5A6709
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
    $RegistryValueName = "DisablePocket"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Pocket"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V252909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252909
        STIG ID    : FFOX-00-000039
        Rule ID    : SV-252909r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox Studies must be disabled.
        DiscussMD5 : F81F60F5B382BDD0EBE09D7BB9760C4D
        CheckMD5   : 2B3F2035CCC8FD03896C0A5A2BB72A7F
        FixMD5     : 87D3E06DC2EC398E6E98CB4838C5D386
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
    $RegistryValueName = "DisableFirefoxStudies"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Firefox Studies"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox*/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox*/policies/policies.json") {
            $RegistryPath = "/etc/firefox*/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/bin/firefox*/distribution/policies.json") {
            $RegistryPath = "/usr/bin/firefox*/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/bin/firefox*/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.$($RegistryValueName)
        $RegistryResultValue = $Policies_JSON.$($RegistryValueName)
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDVPf9UYBvn13ha
# 0BDkDVtsRZqjshPDa3WJH5SkAgd8QqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCCcmTZNpoSmnhGhzzvrMVGeR8jJCKR/MxE1gPJDnqMFazANBgkqhkiG9w0BAQEF
# AASCAQB2g6oFS5Zm96NKtXM27uWV3d8ouSE5moQc16RJR+OXM4ml/PWD4W/J/aJC
# tMSZSZaMppyOlCJFjvwvBFXcS51yCwL0LdEg+tJNDFTPkcuCw8wSbht4lDz0Gq7r
# C9gyJZwHZPpc06r5sL2NcAwAtPtbnsgiO8IaBnnfyUhTkTRgLc8jGIJt5O99fm/F
# tEisiTNn/htw8qyCZtazOwVSPd5+r5nzdTUwNeMBfGeRkeYLEdSgqxlEo99zUKWz
# sqfWhBjNIlLBceUtMmCMt3AIn6/x8j1mJZKqwX6iv/479tWeop+8CGEBMwmEj7+V
# FBxsnEjo8wv5xpb+gop5sGFlM6IyoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTY0MVowLwYJKoZIhvcNAQkEMSIEIMGGwXyKlXI9TAY983gwaeHHchax
# jVOinysTWtmTNvzAMA0GCSqGSIb3DQEBAQUABIICADrJrm2TZLEkTNTZhMLaPdAt
# G8+Yvp84N9XOHNvAHTuY5NFsn8aTD1XJR1z3Cw4Z6iP7dvBsurqrOHMFsw6DSPsk
# +UJdWA8IajNxeBs4VR2S7nAKJMDi0sfiMN+UZuh4NP3UbJY/XkQsPMtzlMdQuZtT
# wgKh7YSMgAd5IxN3nH2xNV+rsd2MVCWzn4GECqs8icRs6khxvisvD2A4qSTV3vtH
# Sur++zTfg4whj3z8hXDej5yN7gpuJOPeF4lqRC2jSDu/BmYF2jPMHQUUEFrcvoPb
# jfjrEgdjRRxqTr85qmj7plpNcfjeZ2uD59fg49q6W9TD+xaVgA1exvVeMZl/IroI
# CXdGzwDruxOP6aLrq4M6OcK8OHTUdS+by+Uqtvr4hf1q/Rt4WsVh2AN2eNM3gSbB
# hG49yTFEveYvskuqNNr6uT2hIDWFYX+MQTTGK7QRZieFBtqijpImccUEX6aJQC47
# D4sUdIShV373DF/oNnjAJhZlwx+vdJpt9Jx87GZxz2NNonH0s6czKDNnhDeYamKr
# eOL4mdn78KR/pSjfSPJZ0f/3fNAMN5OxvNgOvcS0Givtu2ae7cyD+D+PFlsXZg+2
# LTF+94WdIKZ1uAsZBT3T47N4ynIaZJoXHodgi+iSY9fus8X656prABkYcnGFmF9j
# 1iDzigspcxFpYcrXP5Tb
# SIG # End signature block
