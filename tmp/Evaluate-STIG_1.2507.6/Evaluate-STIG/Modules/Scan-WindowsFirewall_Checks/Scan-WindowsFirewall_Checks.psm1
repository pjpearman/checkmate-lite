##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Windows Defender Firewall with Advanced Security
# Version:  V2R2
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Confirm-FWProfileEnabled {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Domain", "Private", "Public")]
        [String]$Profile
    )

    Switch ($Profile) {
        "Domain" {
            $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
            $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
        }
        "Private" {
            $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
            $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
        }
        "Public" {
            $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
            $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
        }
    }

    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = "1"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $Enabled = $false

    $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
    $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

    If ($Profile1.Value -eq $ProfileValue -and $Profile1.Type -eq $RegistryType) {
        $Enabled = $true
    }
    ElseIf ($Profile1.Value -eq "(NotFound)" -and $Profile2.Value -eq $ProfileValue -and $Profile2.Type -eq $RegistryType) {
        $Enabled = $true
    }

    Return $Enabled
}

Function Get-V241989 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241989
        STIG ID    : WNFWA-000001
        Rule ID    : SV-241989r922928_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must be enabled when connected to a domain.
        DiscussMD5 : A4ED1ACACBEDBF05FF6B6CB4599C3999
        CheckMD5   : 2CCF64661AE95B8CEE2A4F5421CBAF98
        FixMD5     : 1BA51E338E5281FED75E2B1959ADD0B3
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
        $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

        # Format the DWORD values
        If ($Profile1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Profile1Value = "0x{0:x8}" -f $Profile1.Value + " ($($Profile1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Profile1Value = $Profile1.Value
        }

        If ($Profile2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Profile2Value = "0x{0:x8}" -f $Profile2.Value + " ($($Profile2.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Profile2Value = $Profile2.Value
        }

        # Check if profile is enabled
        If ($Profile1.Type -eq "(NotFound)") {
            If ($Profile2.Value -in $ProfileValue -and $Profile2.Type -eq $RegistryType) {
                # Profile is enabled
                $ProfileEnabled = "Enabled"
            }
            Else {
                # Profile is disabled
                $ProfileEnabled = "Disabled (Finding)"
                $Compliant = $false
            }
        }
        ElseIf ($Profile1.Value -in $ProfileValue -and $Profile1.Type -eq $RegistryType) {
            # Profile is enabled
            $ProfileEnabled = "Enabled"
        }
        Else {
            # Profile is disabled
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
        $FindingDetails += "Value:`t`t$Profile1Value" | Out-String
        $FindingDetails += "Type:`t`t$($Profile1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
        $FindingDetails += "Value:`t`t$Profile2Value" | Out-String
        $FindingDetails += "Type:`t`t$($Profile2.Type)" | Out-String
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

Function Get-V241990 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241990
        STIG ID    : WNFWA-000002
        Rule ID    : SV-241990r922930_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must be enabled when connected to a private network.
        DiscussMD5 : 571B6F72CCBF43B43679ADB436581A17
        CheckMD5   : 318D75E78162D20FB97427AE8C3BA95C
        FixMD5     : 2FED2B43F468BAA925D8F78AD4F77BFF
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true

    $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
    $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

    # Format the DWORD values
    If ($Profile1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile1Value = "0x{0:x8}" -f $Profile1.Value + " ($($Profile1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Profile1Value = $Profile1.Value
    }

    If ($Profile2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile2Value = "0x{0:x8}" -f $Profile2.Value + " ($($Profile2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Profile2Value = $Profile2.Value
    }

    # Check if profile is enabled
    If ($Profile1.Type -eq "(NotFound)") {
        If ($Profile2.Value -in $ProfileValue -and $Profile2.Type -eq $RegistryType) {
            # Profile is enabled
            $ProfileEnabled = "Enabled"
        }
        Else {
            # Profile is disabled
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }
    }
    ElseIf ($Profile1.Value -in $ProfileValue -and $Profile1.Type -eq $RegistryType) {
        # Profile is enabled
        $ProfileEnabled = "Enabled"
    }
    Else {
        # Profile is disabled
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile1Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile1.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile2Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile2.Type)" | Out-String
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

Function Get-V241991 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241991
        STIG ID    : WNFWA-000003
        Rule ID    : SV-241991r922932_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must be enabled when connected to a public network.
        DiscussMD5 : 0387A88B744DF16B9780CA1065C7BA7D
        CheckMD5   : 1B98BFD2A5DCE67C33215F89609202D0
        FixMD5     : 5E939E88415CEF5C8DB3EF7B99DA1A3D
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true

    $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
    $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

    # Format the DWORD values
    If ($Profile1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile1Value = "0x{0:x8}" -f $Profile1.Value + " ($($Profile1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Profile1Value = $Profile1.Value
    }

    If ($Profile2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile2Value = "0x{0:x8}" -f $Profile2.Value + " ($($Profile2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Profile2Value = $Profile2.Value
    }

    # Check if profile is enabled
    If ($Profile1.Type -eq "(NotFound)") {
        If ($Profile2.Value -in $ProfileValue -and $Profile2.Type -eq $RegistryType) {
            # Profile is enabled
            $ProfileEnabled = "Enabled"
        }
        Else {
            # Profile is disabled
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }
    }
    ElseIf ($Profile1.Value -in $ProfileValue -and $Profile1.Type -eq $RegistryType) {
        # Profile is enabled
        $ProfileEnabled = "Enabled"
    }
    Else {
        # Profile is disabled
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile1Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile1.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile2Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile2.Type)" | Out-String
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

Function Get-V241992 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241992
        STIG ID    : WNFWA-000004
        Rule ID    : SV-241992r922934_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a domain.
        DiscussMD5 : 60EE4DE54D75021E16358FE8568CB850
        CheckMD5   : 4392212EACEE280D82EC2526287972DC
        FixMD5     : 22B1F4A681CFACB24FEAE872FD393798
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultInboundAction"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241993 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241993
        STIG ID    : WNFWA-000005
        Rule ID    : SV-241993r922936_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a domain.
        DiscussMD5 : 572F0DABD7D2DBC07692ACD94D1F77DD
        CheckMD5   : FB09C2A1876162DF7095D18C9D18447A
        FixMD5     : C87F983DF57C793B8DC7F5CB31FB5FC8
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultOutboundAction"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241994 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241994
        STIG ID    : WNFWA-000009
        Rule ID    : SV-241994r922938_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security log size must be configured for domain connections.
        DiscussMD5 : C47980FA173FB79680784CF0E8DA4B8D
        CheckMD5   : E280D26633D61A392C90F39EA0831C16
        FixMD5     : 0ABCB3B45FF8971BA14090030E10E8EF
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogFileSize"  # Value name identified in STIG
    $SettingValue = "16384"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -ge $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -ge $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241995 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241995
        STIG ID    : WNFWA-000010
        Rule ID    : SV-241995r922940_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log dropped packets when connected to a domain.
        DiscussMD5 : 7662DF28CBC859EC0E3C65877C6351DA
        CheckMD5   : 47BD982BAD7A845704ECE38D62E6C7C4
        FixMD5     : 732F8C0F1EE1F79BB908F7C3FF6FFC97
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogDroppedPackets"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241996 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241996
        STIG ID    : WNFWA-000011
        Rule ID    : SV-241996r922942_rule
        CCI ID     : CCI-001462
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log successful connections when connected to a domain.
        DiscussMD5 : E8550F6B36DF5457CE263582E6306F80
        CheckMD5   : FCF37F873FD4DDDEFD7F1B1CC89C448A
        FixMD5     : 1B49E48AEB84D5E7F32EFCFB767A7072
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogSuccessfulConnections"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241997 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241997
        STIG ID    : WNFWA-000012
        Rule ID    : SV-241997r922944_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a private network.
        DiscussMD5 : 3EA3C2EFB7A6C91C46C2D05C76363A75
        CheckMD5   : 4FC96F625BC12E6209F38C44A3CA623A
        FixMD5     : 59E3792088D0648ACC62A80E3FDC59F8
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultInboundAction"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241998 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241998
        STIG ID    : WNFWA-000013
        Rule ID    : SV-241998r922946_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a private network.
        DiscussMD5 : B171C848CEE8EEA7A36B3239EF53F200
        CheckMD5   : ACE85394F5279D16B1FA41C661184A82
        FixMD5     : DF281FD83607CE6C47E8D2A0F7BCA304
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultOutboundAction"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241999 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241999
        STIG ID    : WNFWA-000017
        Rule ID    : SV-241999r922948_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security log size must be configured for private network connections.
        DiscussMD5 : 5DC729495B7B2F2EC12CBF22459171F6
        CheckMD5   : 22D3D72F3BD55C07BA8766881A536732
        FixMD5     : FA91E351AD877180706D977F74ADC5E0
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogFileSize"  # Value name identified in STIG
    $SettingValue = "16384"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -ge $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -ge $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242000 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242000
        STIG ID    : WNFWA-000018
        Rule ID    : SV-242000r922950_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log dropped packets when connected to a private network.
        DiscussMD5 : 3FEA37CB0CADBB95A13D707E09B533B4
        CheckMD5   : 4B6E6C4BCEE91C6001DB698F29BA107C
        FixMD5     : 8D7D6978317471E9B3830144CEC855C7
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogDroppedPackets"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242001 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242001
        STIG ID    : WNFWA-000019
        Rule ID    : SV-242001r922952_rule
        CCI ID     : CCI-001462
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log successful connections when connected to a private network.
        DiscussMD5 : 7050FE88BB96947D547DD7B11CBA042E
        CheckMD5   : 4A776279E6709C1D598211B67A9A47EF
        FixMD5     : C91ACF5A8DB437CB0155388FBFAC8FBA
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogSuccessfulConnections"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242002 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242002
        STIG ID    : WNFWA-000020
        Rule ID    : SV-242002r922954_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a public network.
        DiscussMD5 : DA7ABC450121558E89A0D92509F38CF1
        CheckMD5   : 8ACC8A6E764371BD01102E3B9942951F
        FixMD5     : 016D1FD83EC859DEADEC20C1F08F94FA
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultInboundAction"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242003 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242003
        STIG ID    : WNFWA-000021
        Rule ID    : SV-242003r922956_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a public network.
        DiscussMD5 : 7CC73625792370833CB7828E217B460A
        CheckMD5   : 472CCD7428370B21CC6D7B4DC40D2B6B
        FixMD5     : BEB501E73E44B0F625D4A0A5546228E3
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultOutboundAction"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242004 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242004
        STIG ID    : WNFWA-000024
        Rule ID    : SV-242004r922958_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security local firewall rules must not be merged with Group Policy settings when connected to a public network.
        DiscussMD5 : E955C0FC0562CD2B44F23C4894BD421B
        CheckMD5   : 07A496F9464D559FCBDE8E9F76DBD646
        FixMD5     : 5DFE45A303B379D3AFE12746E480DC3A
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "AllowLocalPolicyMerge"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Public) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
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

Function Get-V242005 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242005
        STIG ID    : WNFWA-000025
        Rule ID    : SV-242005r922960_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security local connection rules must not be merged with Group Policy settings when connected to a public network.
        DiscussMD5 : D9A51000B1877ACE4793DF72F441C40F
        CheckMD5   : DE26931B2A1CFF4F78E829A47E7F0F33
        FixMD5     : 2B1864873A6C42B6B86F919DC238B5A2
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "AllowLocalIPsecPolicyMerge"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.DomainMember)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Public) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
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

Function Get-V242006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242006
        STIG ID    : WNFWA-000027
        Rule ID    : SV-242006r922962_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security log size must be configured for public network connections.
        DiscussMD5 : EBEB5FE59955705C4F268594EC0075C0
        CheckMD5   : 1A1F045408B0FD5C5FA12EB8DDDC2794
        FixMD5     : 073728ACB3A80A243DA3DB3A482C6512
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogFileSize"  # Value name identified in STIG
    $SettingValue = "16384"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -ge $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -ge $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242007 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242007
        STIG ID    : WNFWA-000028
        Rule ID    : SV-242007r922964_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log dropped packets when connected to a public network.
        DiscussMD5 : 2496E9CDF47038B892ADDBC0E37599E0
        CheckMD5   : 9FD41687C34A3BC292EE6C6EB20ACCDF
        FixMD5     : B76434F2539A697A351D38121F1B0D26
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogDroppedPackets"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242008
        STIG ID    : WNFWA-000029
        Rule ID    : SV-242008r922966_rule
        CCI ID     : CCI-001462
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log successful connections when connected to a public network.
        DiscussMD5 : 790CA7E9D853E1F31178773CE4D39A94
        CheckMD5   : 124A093F444858A272CED388AEF86B47
        FixMD5     : E767E0DC9FCEF8D6BCDFAEA9923085F6
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogSuccessfulConnections"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and format to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242009 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242009
        STIG ID    : WNFWA-000100
        Rule ID    : SV-242009r922967_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts.
        DiscussMD5 : 3BC4674C024C4F71C1D5F33E175C22E3
        CheckMD5   : 36940C7CC32E94F37900BBFE291F90AB
        FixMD5     : B9D1B968178A95A3F915E7425528A0F2
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
    $DomainRole = Get-DomainRoleStatus
    If (-Not($DomainRole.RoleFriendlyName -in @("Member Workstation"))) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is a '$($DomainRole.RoleFriendlyName)' so this requirement is NA." | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDd1nA9zFBROifg
# LAoRdK3mWnTue2nBQEXgMp6MXEljlaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCBausuaMsK79KkTf1LZxWFH1nn1gj0MQPRDDljh5Rr6NjANBgkqhkiG9w0BAQEF
# AASCAQBXLvKLaGWTllImkxTd97w7YRNkwaZDa4l5DngvsOD8FsRz0bExkDeRBlk+
# phbL+0ZWto/RX3l99M8MtKbuGqsMNTxy013Ep19ruS552C4iTng5xFQympORPYY2
# iaEMmteAH0+lX/Z9MEabV1R+o5ux9wg5hmmxUT2n7kqDBMIzssNSU5FaemOt7uyk
# S35T3dEkAeiIQbqHRREhLVJM1/IaRGm9jD/egZlEXx4tgkEzn2EhZO9A+KQBTYj0
# CnDsiWqLFnuVMF+UzHRsleTvybEwB5J1ElmaK1pjxhJdKjzMPQSkhuD7UZ7npeDU
# BUR996+cO97SUvlBIgEeMX7YdgP0oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTkyM1owLwYJKoZIhvcNAQkEMSIEIBTdhWBLuKtHKB1ZNjZsfr0GPHwN
# ZaxsMDOkzq8+qTooMA0GCSqGSIb3DQEBAQUABIICALU0FmUHpeffVNmwLnDkvHXY
# BcOXqaqqSTq2jmkT0qQmIl3OXT5Gqrsj+6G6grxLLx35hKlHoCndyq4C3LeLUlh9
# QQVyhjGJJzYbIRBHlUdwq/ySWPKjB+GezTzCCQZSUOo/UzdA6CSSnuscsBebpnhR
# NcWFsAQfFaeVQx5LycdQ3Iv3OeeFvN9Q7QPoOSmfhjufMQSI0V3wWbqAg1sUruM/
# sd2zzA6jed5EG9KSCi+3jJH4fPGGyi0rt2uYlghLbyBycJjkbwawvWrMBdWFubFk
# AjmBAaTGKgB675kYM4ZLyKLx2uq+Q2kiw2ApC56U3WROUdXJWdSVTunRrzj4c9j6
# 0+2yfc8buK9XMYZTN1kK9i+BxP6mHlQyubhB+Zhbql6IG5NtUMhh/3AORw9+T30W
# T4yTgMF6SqirZaIF25F/2VUkFQYCvDAbBxMeJygNNN+d/5cX4imFzlAw2wAKfyda
# 8VVyl5v+gMEsaCPEm1iV9jGC3lfW0XkaJ9nGI1o0BoQ+5+x7Gaq+cQTdx4Z5Qwyq
# wgUZYyIW8q17NW40UObLxqFWSaEvPbRt6E33ZtWZ1Him9sPBP92CXaLHr1ttYzvh
# znEEWtgtLF37I0MfcWuxzk+fqLfN/xMB7q2qyrSULju8O2yqI94za11VLCqcq3Nm
# 6aQJ8I/xLloewwsfqPGC
# SIG # End signature block
