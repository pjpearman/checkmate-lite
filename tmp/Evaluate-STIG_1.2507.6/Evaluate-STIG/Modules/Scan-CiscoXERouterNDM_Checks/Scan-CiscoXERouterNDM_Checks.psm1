##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XE Router NDM
# Version:  V3R5
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V215807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215807
        STIG ID    : CISC-ND-000010
        Rule ID    : SV-215807r960735_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-NDM-000200
        Rule Title : The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.
        DiscussMD5 : F19B0AA112F328426C40CFAB1E86CA11
        CheckMD5   : 5CDDAA36C4D9F1CA41CB6981B258D277
        FixMD5     : 9CF00F68C4F33B5D5D83473D810B5F4F
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
    $OpenFinding = $False
    $CompliantConfig = @()
    $Status = "Not_Reviewed"
    $InputNone = 0
    $Session = 0
    $VTYLines = $ShowRunningConfig | Select-String -Pattern "^line vty"
    $HttpSecureServer = $ShowRunningConfig | Select-String -Pattern "^ip http secure-server"
    $NoHttpSecureServer = $ShowRunningConfig | Select-String -Pattern "^no ip http secure-server"
    $HttpMaxConn = $ShowRunningConfig | Select-String -Pattern "^ip http max-connections"

    IF ($VTYLines) {
        $CompliantConfig += ("" | Out-String).Trim()
        $CompliantConfig += ("Below is the 'line vty' configuration for this device:" | Out-String).Trim()
        $CompliantConfig += ("------------------------------------------------------" | Out-String).Trim()
        ForEach ($line in $VTYLines) {
            IF (-not $line) { continue }
            $VtyLinesConfig = Get-Section $ShowRunningConfig $line.ToString()
            IF (-not $VtyLinesConfig) { continue }
            $TransportInput = $VtyLinesConfig | Select-String -Pattern "transport input"
            $SessionLimit = $VtyLinesConfig | Select-String -Pattern "session-limit"
            IF ($TransportInput) {
                $CompliantConfig += ($line | Out-String).Trim()
                $CompliantConfig += ($TransportInput.ToString() | Out-String).Trim()
                IF ($SessionLimit) {
                    $CompliantConfig += ($SessionLimit.ToString() | Out-String).Trim()
                    $Session += 1
                }
                ELSEIF ($TransportInput | Select-String -Pattern "none") {
                    $InputNone += 1
                }
            }
            ELSE {
                $CompliantConfig += ("" | Out-String).Trim()
                $CompliantConfig += ("'transport input' is not configured under $line" | Out-String).Trim()
                IF ($SessionLimit) {
                    $CompliantConfig += ($line | Out-String).Trim()
                    $CompliantConfig += ($SessionLimit.ToString() | Out-String).Trim()
                }
            }
        }
        IF (($InputNone -eq 0) -AND ($Session -eq 0) -AND $TransportInput) {
            $OpenFinding = $True
            $CompliantConfig += ("" | Out-String).Trim()
            $CompliantConfig += ("SSH sessions are not limited on this device. This is a finding." | Out-String).Trim()
        }
        ELSEIF (!($TransportInput)) {
            $CompliantConfig += ("" | Out-String).Trim()
            $CompliantConfig += ("'transport input' is not configured under any VTY line on this device." | Out-String).Trim()
        }
        ELSE {
            $CompliantConfig += ("" | Out-String).Trim()
            $CompliantConfig += ("SSH sessions are limited on this device." | Out-String).Trim()
        }
    }

    IF ($NoHttpSecureServer) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is configured with 'no ip http secure-server'." | Out-String
        $FindingDetails += "" | Out-String
        IF ($CompliantConfig) {
            $FindingDetails += $CompliantConfig | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    ELSEIF ($HttpSecureServer -AND $HttpMaxConn) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is configured to limit the number of concurrent HTTP/HTTPS management sessions:" | Out-String
        $FindingDetails += "-------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += ($HttpSecureServer.ToString() | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($HttpMaxConn.ToString() | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += $CompliantConfig | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $OpenFinding = $True
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device must be configured to limit the number of concurrent management sessions to an organization-defined number. Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        IF ($HttpSecureServer) {
            $FindingDetails += "The below configuration is present on this device:" | Out-String
            $FindingDetails += "--------------------------------------------------" | Out-String
            $FindingDetails += ($HttpSecureServer.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        IF ($HttpMaxConn) {
            $FindingDetails += "The below configuration is present on this device:" | Out-String
            $FindingDetails += "--------------------------------------------------" | Out-String
            $FindingDetails += ($HttpMaxConn.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        IF ($CompliantConfig) {
            $FindingDetails += $CompliantConfig | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        $Status = "NotAFinding"
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

Function Get-V215808 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215808
        STIG ID    : CISC-ND-000090
        Rule ID    : SV-215808r960777_rule
        CCI ID     : CCI-000018
        Rule Name  : SRG-APP-000026-NDM-000208
        Rule Title : The Cisco router must be configured to automatically audit account creation.
        DiscussMD5 : 5BD5A3EBA7A250544DCD9F1F2F52573C
        CheckMD5   : E5A157B58B4289FE666AC39A19EAF8C1
        FixMD5     : 16681BC83DAADBA1FF8174A329566CD1
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215809
        STIG ID    : CISC-ND-000100
        Rule ID    : SV-215809r960780_rule
        CCI ID     : CCI-001403
        Rule Name  : SRG-APP-000027-NDM-000209
        Rule Title : The Cisco router must be configured to automatically audit account modification.
        DiscussMD5 : FE4ADA94FF7F50F50F5543749CDD697D
        CheckMD5   : D1391FD3B37D682BB4A4551A91CB1FC9
        FixMD5     : 15FF253BC23AF34E318EA783129A84CA
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215810
        STIG ID    : CISC-ND-000110
        Rule ID    : SV-215810r960783_rule
        CCI ID     : CCI-001404
        Rule Name  : SRG-APP-000028-NDM-000210
        Rule Title : The Cisco router must be configured to automatically audit account disabling actions.
        DiscussMD5 : 64F37D91E5CA5F3B115451673F8DCFD8
        CheckMD5   : 1F6CDE9ECDF734B9F221157684CD0A35
        FixMD5     : 6633439FCA1BA8706389AF05BEF4825E
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215811 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215811
        STIG ID    : CISC-ND-000120
        Rule ID    : SV-215811r960786_rule
        CCI ID     : CCI-001405
        Rule Name  : SRG-APP-000029-NDM-000211
        Rule Title : The Cisco router must be configured to automatically audit account removal actions.
        DiscussMD5 : 75F19E046AC7A61605629AF0B990D588
        CheckMD5   : 92E6E4BDCBB2E97246FC1D4D491E9BC7
        FixMD5     : EB27682BEF141DBFE049B76CECB15EB4
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215812
        STIG ID    : CISC-ND-000140
        Rule ID    : SV-215812r991874_rule
        CCI ID     : CCI-001368, CCI-004192
        Rule Name  : SRG-APP-000038-NDM-000213
        Rule Title : The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
        DiscussMD5 : 61B3FF6909A1F8732EFBB220FB482128
        CheckMD5   : 084E864D1D6EF4F5DC14F68289338DB2
        FixMD5     : 1A219AA6E552288291F55BF978E085ED
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
    $OpenFinding = $False
    $Exception = $False
    $NonCompliantSsh = @()
    $CompliantSsh = @()
    $NonCompliantAcl = @()
    $CompliantAcl = @()
    $ACLConfigStandard = @()
    $ACLConfigExtended = @()

    # Get line vty configuration.
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "^line vty"
    ForEach ($LineVty in $LineVtys) {
        $LineVtyConfig = Get-Section $ShowRunningConfig $LineVty.ToString()
        IF (!($LineVtyConfig -like "transport input ssh")) {
            # Add line vty without transport input ssh to FindingDetails
            $NonCompliantSsh += $LineVty.ToString()
            $OpenFinding = $True
        }
        ELSE {
            # Add line vty with transport input ssh to FindingDetails
            $CompliantSsh += $LineVty.ToString()
        }
        IF (!($LineVtyConfig -like "access-class * in")) {
            # Add line vty without an inbound ACL to FindingDetails
            $NonCompliantAcl += $LineVty.ToString()
            $OpenFinding = $True
        }
        ELSE {
            $ACLName = ($LineVtyConfig | Select-String -Pattern "access-class .* in").ToString().Split([char[]]"") | Select-Object -Index 1
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            $ACLStandard = $ShowRunningConfig | Select-String -Pattern "^access-list $ACLName *"
            $CompliantAcl += $LineVty.ToString()
            IF ($ACLExtended) {
                # Add extended ACL entries to FindingDetails
                $ACLConfigExtended += Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $CompliantAcl += "Verify that the extended ACL $ACLName under $LineVty is configured to allow only hosts from the management network to access the device and make finding determination based on STIG check guidance." | Out-String
                $Exception = $True
            }
            ELSEIF ($ACLStandard) {
                # Add standard ACL entries to FindingDetails
                $ACLConfigStandard += ($ACLStandard | Out-String).Trim()
                $CompliantAcl += "Verify that the standard ACL $ACLName under $LineVty is configured to allow only hosts from the management network to access the device and make finding determination based on STIG check guidance." | Out-String
                $Exception = $True
            }
            ELSE {
                $CompliantAcl += "ACL $ACLName under $LineVty is not configured." | Out-String
                $OpenFinding = $True
            }
        }
    }

    IF ($NonCompliantSsh) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below vty lines do not have 'transport input ssh' configured, make finding determination based on STIG check guidance:" | Out-String
        $FindingDetails += "--------------------------------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += ($NonCompliantSsh | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    IF ($CompliantSsh) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below vty lines have 'transport input ssh' configured:" | Out-String
        $FindingDetails += "----------------------------------------------------------" | Out-String
        $FindingDetails += ($CompliantSsh | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    IF ($NonCompliantAcl) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below vty lines do not have an inbound ACL applied, make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "'line vty' without an inbound ACL configured:" | Out-String
        $FindingDetails += "---------------------------------------------" | Out-String
        $FindingDetails += ($NonCompliantAcl | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    IF ($CompliantAcl) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below vty lines have an inbound ACL applied:" | Out-String
        $FindingDetails += "------------------------------------------------" | Out-String
        $FindingDetails += ($CompliantAcl | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    IF ($ACLConfigExtended -OR $ACLConfigStandard) {
        $ACLConfigs = ($ACLConfigStandard + $ACLConfigExtended) | Sort-Object -Unique
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify that the below ACLs are configured to allow only hosts from the management network to access the device and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "------------------------------------------------" | Out-String
        $FindingDetails += ($ACLConfigs | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
        IF ($Exception) {
            $Status = "Not_Reviewed"
        }
        ELSE {
            $Status = "NotAFinding"
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

Function Get-V215813 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215813
        STIG ID    : CISC-ND-000150
        Rule ID    : SV-215813r960840_rule
        CCI ID     : CCI-000044
        Rule Name  : SRG-APP-000065-NDM-000214
        Rule Title : The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
        DiscussMD5 : 65E729AE1725994BC038987712EED5E5
        CheckMD5   : 6EEBD978DD250E8BE4364AAC29116E7E
        FixMD5     : C4ED878650277F33823CCFAD064BEEB2
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
    $OpenFinding = $False
    $LogonAttemptsConf = $ShowRunningConfig | Select-String -Pattern "login block-for"
    IF (!$LogonAttemptsConf) {
        $FindingDetails += "Logon attempts are not limited" | Out-String
        $OpenFinding = $True
    }
    Else {
        #[INT]$LoginAttempts = ($LogonAttemptsConf -Split '(\d+)').Trim()[3]
        [INT]$LoginAttempts = (($LogonAttemptsConf | Out-String).Trim()).Split([char[]]"")[4]
        [INT]$LockOut = (($LogonAttemptsConf | Out-String).Trim()).Split([char[]]"")[2]
        IF ($LoginAttempts -gt "3") {
            $OpenFinding = $True
        }
        IF ($LockOut -lt "900") {
            $OpenFinding = $True
        }
        $FindingDetails += ($LogonAttemptsConf | Out-String).Trim()
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        $Status = "NotAFinding"
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

Function Get-V215814 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215814
        STIG ID    : CISC-ND-000160
        Rule ID    : SV-215814r960843_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-APP-000068-NDM-000215
        Rule Title : The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
        DiscussMD5 : CF61FAB7486D38C6A0974CBBE13DBBB4
        CheckMD5   : 9E07FC09CE6871C88E82F08CEFBB78E2
        FixMD5     : 7CA6B805012223D075B3304C9E2E3249
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
    $BannerStartSTR = ($ShowRunningConfig | Select-String -Pattern "^banner login \^C.*" | Out-String).Trim()
    If ($BannerStartSTR) {
        $BannerEndSTR = "\^C"
        $BannerStartIndex = $ShowRunningConfig.indexof($BannerStartSTR) + 1
        $BannerEndIndex = $BannerStartIndex + ((($ShowRunningConfig | Select-Object -Index ($BannerStartIndex..$ShowRunningConfig.Count) | Select-String $BannerEndSTR)[0]).LineNumber - 1)
        $RTRBanner = ($ShowRunningConfig | Select-Object -Index ($BannerStartIndex..$BannerEndIndex)) -replace "\^C" | Out-String
        $FormattedRTRBanner = (($RTRBanner -replace "\s+", "" -replace "\W" | Out-String).Trim()).Replace("`n", "").ToLower()

        $DoDConsentBanner = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.`r`nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:`r`n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.`r`n-At any time, the USG may inspect and seize data stored on this IS.`r`n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.`r`n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.`r`n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
        $FormattedDoDConsentBanner = (($DoDConsentBanner -replace "\s+", "" -replace "\W" | Out-String).Trim()).Replace("`n", "").ToLower()

        If ($FormattedRTRBanner -eq $FormattedDoDConsentBanner) {
            $Status = "NotAFinding"
            $FindingDetails += "Configured login banner matches Standard Mandatory DoD Notice and Consent Banner as identified in STIG." | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "Configured login banner DOES NOT match Standard Mandatory DoD Notice and Consent Banner as identified in STIG." | Out-String
        }

        $FindingDetails += "" | Out-String
        $FindingDetails += "Configured login banner:" | Out-String
        $FindingDetails += $RTRBanner
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Cisco router is not configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device" | Out-String
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

Function Get-V215815 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215815
        STIG ID    : CISC-ND-000210
        Rule ID    : SV-215815r960864_rule
        CCI ID     : CCI-000166, CCI-000172, CCI-002234
        Rule Name  : SRG-APP-000080-NDM-000220
        Rule Title : The Cisco device must be configured to audit all administrator activity.
        DiscussMD5 : DF73863590F776A7FFB87BC040502047
        CheckMD5   : 7D01FF65BDA22F71F46AEE431C4CDAE4
        FixMD5     : 59EEEB96FC635B01DFB9DE1C4ACA07F3
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings += @()

    IF (!($ShowRunningConfig -contains "logging userinfo")) {
        $OpenFinding = $True
        $Findings += "Global command: logging userinfo"
    }

    IF ($ShowRunningConfig -contains "archive") {
        $archiveConfig = Get-Section $ShowRunningConfig "archive".ToString()

        IF (!($archiveConfig -contains "log config")) {
            $OpenFinding = $True
            $Findings += "log config"
        }
        IF (!($archiveConfig -contains "logging enable")) {
            $OpenFinding = $True
            $Findings += "logging enable"
        }
    }

    IF ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco device must be configured to audit all administrator activity. Configure the router to log administrator activity via these commands." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $FindingDetails += "This device has been configured to audit all administrator activity."
        $Status = "NotAFinding"
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

Function Get-V215817 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215817
        STIG ID    : CISC-ND-000280
        Rule ID    : SV-215817r960894_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-NDM-000226
        Rule Title : The Cisco router must produce audit records containing information to establish when (date and time) the events occurred.
        DiscussMD5 : D3221577E453F1B93CE67F6D72965A55
        CheckMD5   : 163ACA06A8AC649C7E24C5B26512AF45
        FixMD5     : 3DB4870F45D2A3D800FEA4820C3E19D9
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
    $TimeStamp = $ShowRunningConfig | Select-String -Pattern "service timestamps log datetime"
    IF (!$TimeStamp) {
        $FindingDetails += "Date and Time timestamps are not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($TimeStamp | Out-String).Trim()
        $Status = "NotAFinding"
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

Function Get-V215818 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215818
        STIG ID    : CISC-ND-000290
        Rule ID    : SV-215818r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-NDM-000227
        Rule Title : The Cisco router must produce audit records containing information to establish where the events occurred.
        DiscussMD5 : AFF39330BBAA35F46273890D1E49DA4A
        CheckMD5   : 0675C5E1367EBA65007E0C8496E259AC
        FixMD5     : 2153DFD22C560F6F11D3EF769011E54F
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    $IPAccessListSectionNames = $ShowRunningConfig | Select-String -Pattern "^(ip access-list standard|ip access-list extended|ip access-list\s+\S+`$)" | Where-Object {$_ -notlike "*CoPP*"}
    $AclsMissingLogInput = [System.Collections.Generic.List[System.Object]]::new()
    $FoundInterfaceAcls = [System.Collections.Generic.List[System.Object]]::new()
    $StandardAclsOnInterface = [System.Collections.Generic.List[System.Object]]::new()
    $Compliant = $true

    If ($IPAccessListSectionNames) {
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -match "ip access-group*") {
                $InterfaceAclName = ($InterfaceConfig | Where-Object {$_ -like "*ip access-group*"} | Out-String).Trim().Split()[2]

                ForEach ($SectionName in $IPAccessListSectionNames) {
                    $SectionAclName = ($SectionName | Out-String).Trim().Split()[-1]
                    If ($SectionAclName -eq $InterfaceAclName) {
                        If ($SectionName -like "*ip access-list standard*") {
                            $Compliant = $false
                            $NewObj = [PSCustomObject]@{
                                ACL_Name  = ($SectionName | Out-String).Trim() + " [finding]"
                                Interface = ($Interface | Out-String).Trim()
                            }
                            $StandardAclsOnInterface.Add($NewObj)
                        }
                        Else {
                            If ($SectionAclName -notin $FoundInterfaceAcls) {
                                $FoundInterfaceAcls.Add($SectionAclName)

                                $DenyACL = Get-Section $ShowRunningConfig $SectionName | Select-String -Pattern "deny" | Where-Object {$_ -notmatch "remark"}
                                If ($DenyACL) {
                                    $LogInputMissing = $False
                                    $DenyStatements = [System.Collections.Generic.List[System.Object]]::new()
                                    ForEach ($Deny in $DenyACL) {
                                        If ($Deny -notlike "*log-input*") {
                                            $Compliant = $False
                                            $LogInputMissing = $True
                                            $NewObj = [PSCustomObject]@{
                                                Deny = ($Deny | Out-String).Trim() + " [finding]"
                                            }
                                            $DenyStatements.Add($NewObj)
                                        }
                                    }
                                    If ($LogInputMissing) {
                                        $NewObj = [PSCustomObject]@{
                                            ACL_Name = ($SectionName | Out-String).Trim()
                                            Denies   = $DenyStatements
                                        }
                                        $AclsMissingLogInput.Add($NewObj)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "IP Access Lists are not configured" | Out-String
    }

    If ($Compliant -ne $true) {
        $Status = "Open"
        If ($AclsMissingLogInput) {
            $FindingDetails += "The following interface-bound ACL's have deny statements that are missing 'log-input':" | Out-String
            ForEach ($Acl in $AclsMissingLogInput) {
                $FindingDetails += $Acl.ACL_Name | Out-String
                ForEach ($Deny in $Acl.Denies) {
                    $FindingDetails += " $($Deny.Deny)" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        If ($StandardAclsOnInterface) {
            $FindingDetails += "The following standard ACL's are bound to an interface. Standard ACL's are not capable of 'log-input' on deny statements:" | Out-String
            ForEach ($StandardACL in $StandardAclsOnInterface) {
                $FindingDetails += "ACL Name: " + $StandardACL.ACL_Name | Out-String
                $FindingDetails += "Interface: " + $StandardACL.Interface | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "All 'deny' statements are configured to log." | Out-String
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

Function Get-V215819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215819
        STIG ID    : CISC-ND-000330
        Rule ID    : SV-215819r960909_rule
        CCI ID     : CCI-000135
        Rule Name  : SRG-APP-000101-NDM-000231
        Rule Title : The Cisco router must be configured to generate audit records containing the full-text recording of privileged commands.
        DiscussMD5 : FA987022CB17AFB37AA1F4920CF8B471
        CheckMD5   : B15C717457B28658174DB1B3D67B98D2
        FixMD5     : B3B8D388AF4B621F3CECFBFC4B58A5F7
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215820
        STIG ID    : CISC-ND-000380
        Rule ID    : SV-215820r960933_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-APP-000119-NDM-000236
        Rule Title : The Cisco router must be configured to protect audit information from unauthorized modification.
        DiscussMD5 : 4B41337CEF97035D43B8316E7B0647F8
        CheckMD5   : 9E9C5CE62187B0E1952B19940C096BD2
        FixMD5     : 38064D54BF33B529398F995151417345
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
    $LoggingPersistent = $ShowRunningConfig | Select-String -Pattern "^logging persistent"
    IF (!$LoggingPersistent) {
        $FindingDetails += "Logging persistent not found, this requirement is not applicable" | Out-String
        $Status = "Not_Applicable"
    }
    Else {
        $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
        IF (!$FilePrivilege) {
            $FindingDetails += "File privilege configuration was not found" | Out-String
            $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
            $FindingDetails += "Please verify settings on router" | Out-String
        }
        Else {
            $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V215821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215821
        STIG ID    : CISC-ND-000390
        Rule ID    : SV-215821r960936_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-NDM-000237
        Rule Title : The Cisco router must be configured to protect audit information from unauthorized deletion.
        DiscussMD5 : 6114C7D76FD2C2EB038870814F4A6F91
        CheckMD5   : 9E9C5CE62187B0E1952B19940C096BD2
        FixMD5     : 38064D54BF33B529398F995151417345
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
    $LoggingPersistent = $ShowRunningConfig | Select-String -Pattern "^logging persistent"
    IF (!$LoggingPersistent) {
        $FindingDetails += "Logging persistent not found, this requirement is not applicable" | Out-String
        $Status = "Not_Applicable"
    }
    Else {
        $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
        IF (!$FilePrivilege) {
            $FindingDetails += "File privilege configuration was not found" | Out-String
            $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
            $FindingDetails += "Please verify settings on router" | Out-String
        }
        Else {
            $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V215822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215822
        STIG ID    : CISC-ND-000460
        Rule ID    : SV-215822r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-NDM-000244
        Rule Title : The Cisco router must be configured to limit privileges to change the software resident within software libraries.
        DiscussMD5 : 481498A606DD89247A011C1C3394F033
        CheckMD5   : 6E86E753D5FD13CBF9E7992DA422867B
        FixMD5     : FBC1E69B58B84A8E5775D3401AD3C06B
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
    # TODO REMOVE
    #$FindingDetails = @()
    $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
    IF (!$FilePrivilege) {
        $FindingDetails += "File privilege configuration was not found" | Out-String
        $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
        $FindingDetails += "Please verify settings on router" | Out-String
    }
    Else {
        $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V215823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215823
        STIG ID    : CISC-ND-000470
        Rule ID    : SV-215823r1043177_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-NDM-000245
        Rule Title : The Cisco router must be configured to prohibit the use of all unnecessary and nonsecure functions and services.
        DiscussMD5 : 3E6CD5ADF99942F100B05BEF828F3687
        CheckMD5   : A40070A89F3E09EAFE9E90D99F49F7C6
        FixMD5     : EA5EABAD036305B35E758F6746A44630
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
    $OpenFinding = $False
    $DisallowedCommands = @(
        "boot network",
        "ip boot server",
        "ip bootp server",
        "ip dns server",
        "ip identd",
        "ip finger",
        "ip http server",
        "ip rcmd rcp-enable",
        "ip rcmd rsh-enable",
        "service config",
        "service finger",
        "service tcp-small-servers",
        "service udp-small-servers",
        "service pad",
        "service call-home"
    )
    ForEach ($Command in $DisallowedCommands) {
        $CommandCheck = $ShowRunningConfig | Select-String -Pattern "^\s*$Command"
        IF ([Bool]$CommandCheck) {
            $OpenFinding = $True
            $FindingDetails += ([STRING]"$CommandCheck Found").ToUpper() | Out-String
        }
        Else {
            $FindingDetails += "$Command not found" | Out-String
        }
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        $Status = "NotAFinding"
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

Function Get-V215824 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215824
        STIG ID    : CISC-ND-000490
        Rule ID    : SV-215824r1051115_rule
        CCI ID     : CCI-001358, CCI-002111
        Rule Name  : SRG-APP-000148-NDM-000346
        Rule Title : The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.
        DiscussMD5 : 770661E395811E143543EDE334AC2B0C
        CheckMD5   : 5FC37EB1A478AD5E62E5FB332D2902EB
        FixMD5     : DA77018EB229361A85C1B82EED3B9740
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
    $OpenFinding = $False
    $NR = $False
    $AllUsers = $ShowRunningConfig | Select-String -Pattern "^username"
    $Users = @()
    $AAAGroupServer = $ShowRunningConfig | Select-String -Pattern "^aaa group server"
    $AAALoginMethod = $ShowRunningConfig | Select-String -Pattern "^aaa authentication login"

    #This removes pwd from variable
    ForEach ($User in $AllUsers) {
        $PwdHash = (($User | Out-String).Trim()).Split([char[]]"") | Select-Object -Last 1
        $Users += (($User | Out-String).Trim()).Replace("$PwdHash", "<pwd removed>")
    }

    $FindingDetails += "Accounts" | Out-String
    $FindingDetails += ($Users | Out-String).Trim()
    $FindingDetails += "" | Out-String

    IF ($Allusers.Count -gt "1") {
        $OpenFinding = $True
    }
    Else {
        [INT]$PrivLvl = (-Split $AllUsers)[3]
        if (!($PrivLvl -eq "15")) {
            $NR = $True
            $FindingDetails += "Verify that a local account for last resort has been configured with a privilege level that will enable the administrator to troubleshoot connectivity to the authentication server." | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF (!$AAAGroupServer) {
        $OpenFinding = $True
        $FindingDetails += "Authentication Group Server:" | Out-String
        $FindingDetails += "AAA Group Server(s) not configured" | Out-String
    }
    Else {
        #$AAAMethod = (([STRING]$AAAGroupServer).Replace("aaa group server ","")).Split([char[]]"")[0].Trim()
        $AAAAuthSrvrGroupName = (([STRING]$AAAGroupServer).Replace("aaa group server ", "")).Split([char[]]"")[1].Trim()
        $AllowedAuthServers = @("tacacs+", "radius", "$AAAAuthSrvrGroupName")
        IF (!$AAALoginMethod) {
            $OpenFinding = $True
            $FindingDetails += "AAA authentication login method not configured" | Out-String
        }
        Else {
            $FindingDetails += "AAA Login Method:" | Out-String
            ForEach ($LoginMethod in $AAALoginMethod) {
                $AAALoginAuthServer = ($LoginMethod | Out-String).Trim().Replace("aaa authentication login ", "").Split([char[]]"")
                IF ($AAALoginAuthServer[2]) {
                    IF (!($AAALoginAuthServer[2] -in $AllowedAuthServers -AND $AAALoginAuthServer[3] -eq "local")) {
                        $OpenFinding = $True
                    }
                    $FindingDetails += ($LoginMethod | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    $FindingDetails += ($LoginMethod | Out-String).Trim() + " " + "- local is not defined after radius or tacas+ in the authentication order." | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        IF (!$NR) {
            $Status = "NotAFinding"
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

Function Get-V215826 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215826
        STIG ID    : CISC-ND-000550
        Rule ID    : SV-215826r1015288_rule
        CCI ID     : CCI-000205, CCI-004066
        Rule Name  : SRG-APP-000164-NDM-000252
        Rule Title : The Cisco router must be configured to enforce a minimum 15-character password length.
        DiscussMD5 : E86D767C7A84CA263D8A1284AD3C60EC
        CheckMD5   : 5D5D507EF089ECC393F3A276D451AD1F
        FixMD5     : 6796FB099BC3CF5E9B077812FD93CFC8
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
    $SettingName = "min-length"
    $MinimumValue = [int]15

    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String

        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -match $SettingName) {
            $PolicySetting = [int]($PwdPolicySettings -match $SettingName -split "\s+")[1].Trim()
            If ($PolicySetting -ge $MinimumValue) {
                $Status = "NotAFinding"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName) [expected $MinimumValue or greater]" | Out-String
            }
        }
        Else {
            $Status = "Open"
            $FindingDetails += " '$SettingName' is not configured [finding]" | Out-String
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

Function Get-V215827 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215827
        STIG ID    : CISC-ND-000570
        Rule ID    : SV-215827r1015289_rule
        CCI ID     : CCI-000192, CCI-004066
        Rule Name  : SRG-APP-000166-NDM-000254
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one uppercase character be used.
        DiscussMD5 : 36FEAE5F2BDE0023706C61CF0503DA74
        CheckMD5   : C65C7C7F98584EABF89345CF0960BC2E
        FixMD5     : F2B84230055DC8322CBDB119D7404839
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
    $SettingName = "upper-case"
    $MinimumValue = [int]1

    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String

        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -match $SettingName) {
            $PolicySetting = [int]($PwdPolicySettings -match $SettingName -split "\s+")[1].Trim()
            If ($PolicySetting -ge $MinimumValue) {
                $Status = "NotAFinding"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName) [expected $MinimumValue or greater]" | Out-String
            }
        }
        Else {
            $Status = "Open"
            $FindingDetails += " '$SettingName' is not configured [finding]" | Out-String
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

Function Get-V215828 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215828
        STIG ID    : CISC-ND-000580
        Rule ID    : SV-215828r1015290_rule
        CCI ID     : CCI-000193, CCI-004066
        Rule Name  : SRG-APP-000167-NDM-000255
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one lowercase character be used.
        DiscussMD5 : 3064BFCBB08D1423D8F28D13D9EB5B67
        CheckMD5   : F56BA325E488549B978F4C67B1C42C00
        FixMD5     : F530F4C32003CF46621A6EAB9D989DB1
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
    $SettingName = "lower-case"
    $MinimumValue = [int]1

    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String

        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -match $SettingName) {
            $PolicySetting = [int]($PwdPolicySettings -match $SettingName -split "\s+")[1].Trim()
            If ($PolicySetting -ge $MinimumValue) {
                $Status = "NotAFinding"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName) [expected $MinimumValue or greater]" | Out-String
            }
        }
        Else {
            $Status = "Open"
            $FindingDetails += " '$SettingName' is not configured [finding]" | Out-String
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

Function Get-V215829 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215829
        STIG ID    : CISC-ND-000590
        Rule ID    : SV-215829r1015291_rule
        CCI ID     : CCI-000194, CCI-004066
        Rule Name  : SRG-APP-000168-NDM-000256
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one numeric character be used.
        DiscussMD5 : 3064BFCBB08D1423D8F28D13D9EB5B67
        CheckMD5   : B55E81BAEA81A41E898A03FEE407CE97
        FixMD5     : BB5F6E164CCBD09A2F05BBE5BE9A23C7
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
    $SettingName = "numeric-count"
    $MinimumValue = [int]1

    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String

        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -match $SettingName) {
            $PolicySetting = [int]($PwdPolicySettings -match $SettingName -split "\s+")[1].Trim()
            If ($PolicySetting -ge $MinimumValue) {
                $Status = "NotAFinding"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName) [expected $MinimumValue or greater]" | Out-String
            }
        }
        Else {
            $Status = "Open"
            $FindingDetails += " '$SettingName' is not configured [finding]" | Out-String
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

Function Get-V215830 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215830
        STIG ID    : CISC-ND-000600
        Rule ID    : SV-215830r1015292_rule
        CCI ID     : CCI-001619, CCI-004066
        Rule Name  : SRG-APP-000169-NDM-000257
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one special character be used.
        DiscussMD5 : 3064BFCBB08D1423D8F28D13D9EB5B67
        CheckMD5   : D61846543B8BB5976258A0053739D5B0
        FixMD5     : 4F064EB063143734B6395DDE1CDC99FC
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
    $SettingName = "special-case"
    $MinimumValue = [int]1

    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String

        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -match $SettingName) {
            $PolicySetting = [int]($PwdPolicySettings -match $SettingName -split "\s+")[1].Trim()
            If ($PolicySetting -ge $MinimumValue) {
                $Status = "NotAFinding"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName) [expected $MinimumValue or greater]" | Out-String
            }
        }
        Else {
            $Status = "Open"
            $FindingDetails += " '$SettingName' is not configured [finding]" | Out-String
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

Function Get-V215831 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215831
        STIG ID    : CISC-ND-000610
        Rule ID    : SV-215831r1043189_rule
        CCI ID     : CCI-000195, CCI-004066
        Rule Name  : SRG-APP-000170-NDM-000329
        Rule Title : The Cisco router must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.
        DiscussMD5 : 1BD1217C01F3BE8EB813263AE56D4A9F
        CheckMD5   : 62CF48B3793FC08C75C7E59C72220B0F
        FixMD5     : 623FD68E953362E6E5DFF116AF2AE505
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
    $SettingName = "char-changes"
    $MinimumValue = [int]8

    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String

        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -match $SettingName) {
            $PolicySetting = [int]($PwdPolicySettings -match $SettingName -split "\s+")[1].Trim()
            If ($PolicySetting -ge $MinimumValue) {
                $Status = "NotAFinding"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += " $($PwdPolicySettings -match $SettingName) [expected $MinimumValue or greater]" | Out-String
            }
        }
        Else {
            $Status = "Open"
            $FindingDetails += " '$SettingName' is not configured [finding]" | Out-String
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

Function Get-V215832 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215832
        STIG ID    : CISC-ND-000620
        Rule ID    : SV-215832r1015294_rule
        CCI ID     : CCI-000196, CCI-004062, CCI-004910
        Rule Name  : SRG-APP-000171-NDM-000258
        Rule Title : The Cisco router must only store cryptographic representations of passwords.
        DiscussMD5 : 567338A4DCF9B517B41EDD04166B4766
        CheckMD5   : 9BAC61FBBA4E9844590826EE869E9F68
        FixMD5     : 1573982350947D974B22261AFACE2E70
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
    $PWDEncryption = $ShowRunningConfig | Select-String -Pattern "^service password-encryption"
    IF ($PWDEncryption) {
        $FindingDetails += ($PWDEncryption | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "service password-encryption not configured" | Out-String
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

Function Get-V215833 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215833
        STIG ID    : CISC-ND-000720
        Rule ID    : SV-215833r961068_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-APP-000190-NDM-000267
        Rule Title : The Cisco router must be configured to terminate all network connections associated with device management after five minutes of inactivity.
        DiscussMD5 : C55855B1F7DC3A2BCA7DC4A4B7EA8027
        CheckMD5   : 4087E71048E19E385771C782AF5C15D6
        FixMD5     : 292D2E7C97864CACB447EF4DCEC82C88
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
    $OpenFinding = $False
    $NR = $False
    $HttpServer = $ShowRunningConfig | Select-String -Pattern "^no ip http"
    $LineConTimeOut = Get-Section $ShowRunningConfig "line con 0" | Where-Object {$_ -like "exec-timeout*"}
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "^line vty"

    IF ($HttpServer -like "no ip http server" -AND $HttpServer -like "no ip http secure-server") {
        $FindingDetails += "IP HTTP Timeout Settings" | Out-String
        $FindingDetails += ($HttpServer | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "http\https servers are disabled, http\https requirements are not applicable" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $HttpTimeout = $ShowRunningConfig | Select-String -Pattern "^ip http timeout"
        IF ($HttpTimeout) {
            IF ((($HttpTimeout | Out-String).Trim()).Split([char[]]"")[4] -le "600") {
                $FindingDetails += "IP HTTP Timeout Settings" | Out-String
                $FindingDetails += ($HttpTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += "IP HTTP Timeout Settings" | Out-String
                $FindingDetails += ($HttpTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }

        }
        Else {
            $OpenFinding = $True
            $FindingDetails += "IP HTTP Timeout Settings are not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF ($LineConTimeOut) {
        IF (!([INT]$LineConTimeOut.Split([char[]]"")[1] -le "5")) {
            $OpenFinding = $True
        }
        $FindingDetails += "Console Port Timeout Settings" | Out-String
        $FindingDetails += "line con 0" | Out-String
        $FindingDetails += " " + ($LineConTimeOut | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    Else {
        IF (Get-Section $ShowRunningConfig "line con 0") {
            $OpenFinding = $True
            $FindingDetails += "line con 0" | Out-String
            $FindingDetails += (Get-Section $ShowRunningConfig "line con 0" | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "line con 0 exec-timeout is not configured. Default value of 10 is assumed" | Out-String
            $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "Console Port Line Configuration not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF ($LineVtys) {
        $FindingDetails += "Line VTY Timeout Settings"
        $VTYTimeout = Get-Section $ShowRunningConfig $LineVtys[0] | Where-Object {$_ -like "exec-timeout*"}
        IF ($VTYTimeout) {
            IF (!([INT]$VTYTimeout.Split([char[]]"")[1] -le "5")) {
                $OpenFinding = $True
            }
            $FindingDetails += ($LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += " " + ($VTYTimeout | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        Else {
            $OpenFinding = $True
            $FindingDetails += ($LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += (Get-Section $ShowRunningConfig $LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LineVtys[0] | Out-String).Trim() + " " + "exec-timeout is not configured. Default value of 10 is assumed" | Out-String
            $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
            $FindingDetails += "" | Out-String
        }

        $LineVtys | Select-Object -Skip 1 | ForEach-Object {
            $VTYTimeout = Get-Section $ShowRunningConfig $_ | Where-Object {$_ -like "exec-timeout*"}
            IF ($VTYTimeout) {
                IF (!([INT]$VTYTimeout.Split([char[]]"")[1] -le "5")) {
                    $OpenFinding = $True
                }
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += " " + ($VTYTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += (Get-Section $ShowRunningConfig $_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($_ | Out-String).Trim() + " " + "exec-timeout is not configured. Default value of 10 is assumed" | Out-String
                $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $OpenFinding = $true
        $FindingDetails += "Line VTY Timeout Settings not set" | Out-String
        $FindingDetails += ""
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        IF (!$NR) {
            $Status = "NotAFinding"
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

Function Get-V215834 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215834
        STIG ID    : CISC-ND-000880
        Rule ID    : SV-215834r961290_rule
        CCI ID     : CCI-002130
        Rule Name  : SRG-APP-000319-NDM-000283
        Rule Title : The Cisco router must be configured to automatically audit account enabling actions.
        DiscussMD5 : 7F7DEDA73BE5190E575339FCA6BFD3B6
        CheckMD5   : 3DC2A6C63CF49D3E22205E4DD0202BDB
        FixMD5     : A1E6AAA99C056DF493AAC69D5DC441C9
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215836 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215836
        STIG ID    : CISC-ND-000980
        Rule ID    : SV-215836r961392_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-NDM-000293
        Rule Title : The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
        DiscussMD5 : 3796374344336078FA1BEEE6A23D7D08
        CheckMD5   : 8C7F1416E0A9200DBA8678045BF4861B
        FixMD5     : 2AD2DDE416E4CAEEF34A7FC33561E21E
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
    $LoggingBuffer = $ShowRunningConfig | Select-String -Pattern "^logging buffered"
    If ($LoggingBuffer) {
        $LoggingBuffer -match "\d+" | Out-Null
        If ($Matches) {
            $BufferSize = $Matches[0]
            $FindingDetails += "Logging buffer size: $BufferSize" | Out-String
            $Status = "NotAFinding"
        }
        Else {
            $FindingDetails += "Buffer size is not configured:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $LoggingBuffer | Out-String
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "'logging buffered' is not configured" | Out-String
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

Function Get-V215837 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215837
        STIG ID    : CISC-ND-001000
        Rule ID    : SV-215837r991886_rule
        CCI ID     : CCI-001858, CCI-003831
        Rule Name  : SRG-APP-000360-NDM-000295
        Rule Title : The Cisco router must be configured to generate an alert for all audit failure events.
        DiscussMD5 : 5A2FE043544D5FA66D313940CA473FE4
        CheckMD5   : D912606632F4B6129D095F736E5BBF3F
        FixMD5     : 00A46EC582469271C9F665D1F5B707ED
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
    $LoggingTrap = $ShowRunningConfig | Select-String -Pattern "^logging trap"
    IF ($LoggingTrap) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is configured to generate an alert for all audit failure events:" | Out-String
        $FindingDetails += ($LoggingTrap | Out-String).Trim()
        $Status = "NotAFinding"
    }
    ELSE {
        IF ($ShowRunningConfig | Select-String -Pattern "^no logging trap") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to generate an alert for all audit failure events:" | Out-String
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^no logging trap" | Out-String).Trim()
            $Status = "Open"
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is configured to generate an alert for all audit failure events." | Out-String
            IF (Get-CiscoShowTechData -ShowTech $ShowTech -DataType Logging) {
                $ShowLoggingConfig = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Logging
                $FindingDetails += ($ShowLoggingConfig | Select-String -Pattern "\sTrap logging.*" | Out-String).Trim()
            }
            $Status = "NotAFinding"
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

Function Get-V215838 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215838
        STIG ID    : CISC-ND-001030
        Rule ID    : SV-215838r1015295_rule
        CCI ID     : CCI-001889, CCI-001890, CCI-001893, CCI-004922, CCI-004923, CCI-004928
        Rule Name  : SRG-APP-000373-NDM-000298
        Rule Title : The Cisco router must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
        DiscussMD5 : DDCB7B99A9C111819BBFC1DE39E2919A
        CheckMD5   : 7954F4FBCE62EBBD9F576405340E481F
        FixMD5     : D5DA1C14DE233FCC0F18F26848CCD8AE
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
    $NTPServers = $ShowRunningConfig | Select-String -Pattern "^ntp server"
    IF ($NTPServers) {
        IF ($NTPServers.Count -gt "1") {
            # Check if first NTP server exists and has valid IP
            IF ($NTPServers[0] -and ($NTPServers[0] -match "\d+\.\d+\.\d+\.\d+")) {
                $NTPServerPrimary = $Matches[0]
            }
            ELSE {
                $NTPServerPrimary = $null
            }
            # Check if second NTP server exists and has valid IP
            IF ($NTPServers[1] -and ($NTPServers[1] -match "\d+\.\d+\.\d+\.\d+")) {
                $NTPServerBackup = $Matches[0]
            }
            ELSE {
                $NTPServerBackup = $null
            }
            IF ($NTPServerPrimary -AND $NTPServerPrimary -AND ($NTPServerPrimary -ne $NTPServerBackup)) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "The following NTP servers are configured on this device:" | Out-String
                $FindingDetails += ($NTPServers | Out-String).Trim()
                $Status = "NotAFinding"
            }
            ELSE {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Primary and Backup NTP servers are configured with the same IP Address." | Out-String
                $FindingDetails += "Redundant NTP Server is not configured." | Out-String
                $FindingDetails += ($NTPServers | Out-String).Trim()
                $Status = "Open"
            }
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Redundant NTP Server is not configured, this is a finding:" | Out-String
            $FindingDetails += ($NTPServers | Out-String).Trim()
            $Status = "Open"
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no NTP servers configured on this device." | Out-String
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

Function Get-V215841 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215841
        STIG ID    : CISC-ND-001130
        Rule ID    : SV-215841r1107207_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
        DiscussMD5 : 96942660A1069E264F038A35C9A1CBA9
        CheckMD5   : 11B4D9CCBDFEC8EDDEDB00FA54F8363C
        FixMD5     : F8988D511EDE31DB10F8A4FF76928621
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
    $OpenFinding = $False
    $Exception = $False

    # Get snmp-server configuration.
    $SnmpServerConfig = $ShowRunningConfig | Select-String -Pattern "^snmp-server"
    IF ($SnmpServerConfig) {
        IF ($SnmpServerConfig | Select-String -Pattern "^snmp-server group .* v3 (auth|priv) (read|write) .*") {
            $SnmpServerGroups = ($SnmpServerConfig | Select-String -Pattern "^snmp-server group .* v3 (auth|priv) (read|write) .*")
            $FindingDetails += "" | Out-String
            $FindingDetails += "SNMP Server Group Configuration:" | Out-String
            $FindingDetails += "--------------------------------" | Out-String
            ForEach ($SnmpServerGroup in $SnmpServerGroups) {
                $FindingDetails += $SnmpServerGroup | Out-String
            }
        }
        ELSE {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the configuration to verify that this device is able to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)." | Out-String
            $FindingDetails += "snmp-server group is not properly configured." | Out-String
        }
        IF ($SnmpServerConfig | Select-String -Pattern "^snmp-server host .* version 3 auth|priv") {
            $Exception = $True
            $SnmpServerHostsPriv = $SnmpServerConfig | Select-String -Pattern "^snmp-server host .* version 3 priv"
            $FindingDetails += "" | Out-String
            $FindingDetails += "SNMP Server Host Configuration:" | Out-String
            $FindingDetails += "--------------------------------" | Out-String
            IF ($SnmpServerHostsPriv) {
                ForEach ($SnmpServerHost in $SnmpServerHostsPriv) {
                    $SnmpServerUser = ($SnmpServerHost).ToString().Split([char[]]"") | Select-Object -Last 1
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$SnmpServerHost is configured." | Out-String
                    IF ($SnmpServerUser) {
                        $FindingDetails += "Do 'show snmp user' and verify that User Name is $SnmpServerUser and Authentication Protocol is SHA." | Out-String
                    }
                    ELSE {
                        $FindingDetails += "Do 'show snmp user' and verify that Authentication Protocol is SHA." | Out-String
                    }
                }
            }
            $SnmpServerHostsAuth = $SnmpServerConfig | Select-String -Pattern "^snmp-server host .* version 3 auth"
            IF ($SnmpServerHostsAuth) {
                ForEach ($SnmpServerHost in $SnmpServerHostsAuth) {
                    $SnmpServerUser = ($SnmpServerHost).ToString().Split([char[]]"") | Select-Object -Last 1
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$SnmpServerHost is configured." | Out-String
                    IF ($SnmpServerUser) {
                        $FindingDetails += "Do 'show snmp user' and verify that User Name is $SnmpServerUser and Authentication Protocol is SHA." | Out-String
                    }
                    ELSE {
                        $FindingDetails += "Do 'show snmp user' and verify that Authentication Protocol is SHA." | Out-String
                    }
                }
            }
        }
        ELSE {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the configuration to verify that this device is able to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)." | Out-String
            $FindingDetails += "snmp-server host is not properly configured." | Out-String
        }
    }
    ELSE {
        $OpenFinding = $True
        $FindingDetails += "" | Out-String
        $FindingDetails += "Review the configuration to verify that this device is able to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)." | Out-String
        $FindingDetails += "snmp-server configuration is missing." | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
        $Status = "NotAFinding"
        IF ($Exception) {
            $Status = "Not_Reviewed"
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

Function Get-V215842 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215842
        STIG ID    : CISC-ND-001140
        Rule ID    : SV-215842r961506_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
        DiscussMD5 : EC38084E1A006FA7ADEE0533040CE597
        CheckMD5   : BDBF0509B5956836A1AE91BD69DDA347
        FixMD5     : 7BAFC3731CDA4D0B49354009D5FEEF99
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
    $FindingDetails += "Requires information not provided by show tech or show running configuration file" | Out-String
    $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^snmp-server" | Out-String).Trim()
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

Function Get-V215843 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215843
        STIG ID    : CISC-ND-001150
        Rule ID    : SV-215843r1050862_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000347
        Rule Title : The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
        DiscussMD5 : B9CAD587304827035D1B323D3221D8E0
        CheckMD5   : A581B1A7127E7582AA8D7E88AED89644
        FixMD5     : B0756927EA7E1ACC63B6164EB5B3D8DB
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
    $OpenFinding = $False
    $Exception = $False
    $NtpServerKeyList = @()
    $NtpAuthList = @()
    $NtpTrustedList = @()
    $CommonKeys = @()

    # Get NTP configuration.
    $NtpConfig = $ShowRunningConfig | Select-String -Pattern "^ntp"
    IF ($NtpConfig) {
        IF (!($NtpConfig | Select-String -Pattern "^ntp authenticate")) {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based." | Out-String
            $FindingDetails += "'ntp authenticate' is missing." | Out-String
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "'ntp authenticate' is configured." | Out-String
        }
        IF (!($NtpConfig | Select-String -Pattern "^ntp trusted-key")) {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based." | Out-String
            $FindingDetails += "'ntp trusted-key' is missing." | Out-String
        }
        ELSE {
            IF  ($NtpConfig | Select-String -Pattern "^ntp trusted-key \d+`$") {
                $NtpTrustedKeyConfig = $NtpConfig | Select-String -Pattern "^ntp trusted-key \d+`$"
                ForEach ($key in $NtpTrustedKeyConfig) {
                    $NtpTrustedList += ($key).ToString().Split([char[]]"") | Select-Object -Index 2
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$key is configured." | Out-String
                }
                $NtpTrustedList = $NtpTrustedList | Sort-Object | Get-Unique
            }
            IF ($NtpConfig | Select-String -Pattern "^ntp trusted-key .* - .*") {
                $NtpTrustedKeyConfigRange = $NtpConfig | Select-String -Pattern "^ntp trusted-key .* - .*"
                ForEach ($key in $NtpTrustedKeyConfigRange) {
                    $StartKey = ($key).ToString().Split([char[]]"") | Select-Object -Index 2
                    $EndKey = ($key).ToString().Split([char[]]"") | Select-Object -Index 4
                    $NtpTrustedList += $StartKey..$EndKey
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$key is configured." | Out-String
                }
            }
        }
        IF (!($NtpConfig | Select-String -Pattern "^ntp authentication-key .* hmac-sha2-256")) {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based." | Out-String
            $FindingDetails += "'ntp authentication-key <key> hmac-sha2-256' is missing." | Out-String
        }
        ELSE {
            $NtpAuthKeyConfigs = $NtpConfig | Select-String -Pattern "^ntp authentication-key .* hmac-sha2-256"
            ForEach ($NtpAuthKeyConfig in $NtpAuthKeyConfigs) {
                $NtpAuthList += ($NtpAuthKeyConfig).ToString().Split([char[]]"") | Select-Object -Index 2
                $FindingDetails += "" | Out-String
                $FindingDetails += "$NtpAuthKeyConfig is configured." | Out-String
            }
            $NtpAuthList = $NtpAuthList | Sort-Object | Get-Unique
        }
        IF (!($NtpConfig | Select-String -Pattern "^ntp server .* key")) {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based." | Out-String
            $FindingDetails += "'ntp server <IP> key' is missing." | Out-String
        }
        ELSE {
            # Get NTP servers configuration.
            $NtpServers = $ShowRunningConfig | Select-String -Pattern "^ntp server .* key"
            IF ($NtpServers.count -eq 1) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "There is only one NTP server configured. Make finding determination based on STIG check guidance." | Out-String
                $Exception = $True
            }
            ForEach ($NtpServer in $NtpServers) {
                $NtpServerKeyList += ($NtpServer).ToString().Split([char[]]"") | Select-Object -Last 1
                $FindingDetails += "" | Out-String
                $FindingDetails += "$NtpServer is configured." | Out-String
            }
            $NtpServerKeyList = $NtpServerKeyList | Sort-Object | Get-Unique
        }
        IF ($NtpServerKeyList -AND $NtpAuthList -AND $NtpTrustedList) {
            ForEach ($element in $NtpServerKeyList) {
                IF ($NtpAuthList -contains $element) {
                    $CommonKeys += $element
                }
            }
            ForEach ($element in $CommonKeys) {
                IF ($NtpTrustedList -contains $element) {
                    $MatchKey = $True
                }
            }
            IF (!($MatchKey)) {
                $Exception = $True
                $FindingDetails += "" | Out-String
                $FindingDetails += "NTP Keys configured on this device don't match. Make finding determination based on STIG check guidance." | Out-String
            }
        }
    }
    ELSE {
        $OpenFinding = $True
        $FindingDetails += "This device is not configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based." | Out-String
        $FindingDetails += "NTP configuration is missing." | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
        $Status = "NotAFinding"
    }
    IF ($Exception) {
        $Status = "Not_Reviewed"
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

Function Get-V215844 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215844
        STIG ID    : CISC-ND-001200
        Rule ID    : SV-215844r961554_rule
        CCI ID     : CCI-001941, CCI-002890
        Rule Name  : SRG-APP-000411-NDM-000330
        Rule Title : The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
        DiscussMD5 : 515464A1D5B98B44D4F12FA3F0A50083
        CheckMD5   : 930014117BBB480B0D8586C6FA745DF3
        FixMD5     : F3F6BE472877E959CA84874659C796EF
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
    $OpenFinding = $False
    $IPSSHSrvrEncAlgorithm = $ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm mac(?: hmac-sha2-512 | hmac-sha2-256)"
    IF ($IPSSHSrvrEncAlgorithm) {
        $FindingDetails += "SHA-2 algoritm is used for SSH which inherently means that SSHv2 is the protocol." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += ($IPSSHSrvrEncAlgorithm | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    Else {
        $OpenFinding = $True
        $FindingDetails += "SSH Server Algorithm is not configured per STIG check guidelines" | Out-String
        $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh" | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        $Status = "NotAFinding"
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

Function Get-V215845 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215845
        STIG ID    : CISC-ND-001210
        Rule ID    : SV-215845r961557_rule
        CCI ID     : CCI-003123
        Rule Name  : SRG-APP-000412-NDM-000331
        Rule Title : The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
        DiscussMD5 : 451042AAB21D5513C191D553EC3B6ADF
        CheckMD5   : 742F37493052FE4C90FE2B4509BE89AA
        FixMD5     : A1167CC0769548D5C6C661F15CE0832C
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
    $IPSSHSrvrEncAlgorithm = $ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption(?: aes128-ctr| aes192-ctr| aes256-ctr)"
    IF (!$IPSSHSrvrEncAlgorithm) {
        IF ($null -eq ($ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption")) {
            $FindingDetails += "ip ssh server algorithm encryption not configured" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption" | Out-String).Trim()
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += ($IPSSHSrvrEncAlgorithm | Out-String).Trim()
        $Status = "NotAFinding"
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

Function Get-V215848 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215848
        STIG ID    : CISC-ND-001250
        Rule ID    : SV-215848r961812_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-NDM-000319
        Rule Title : The Cisco router must be configured to generate log records when administrator privileges are deleted.
        DiscussMD5 : FA1F339C351D1C903620B12A1C65FF0A
        CheckMD5   : 02FF0523C8101B391FCF4D5A53F1477E
        FixMD5     : 2498DC391EBF03A675DB221FDAEE4DC8
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215849 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215849
        STIG ID    : CISC-ND-001260
        Rule ID    : SV-215849r961824_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-NDM-000320
        Rule Title : The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur.
        DiscussMD5 : FA1F339C351D1C903620B12A1C65FF0A
        CheckMD5   : CA310613A27451A9BE45A5DA51CAB141
        FixMD5     : 1DF014239E7D44157D9587125515B33C
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
    $OpenFinding = $False
    $LoginFailure = $ShowRunningConfig | Select-String -Pattern "login on-failure log"
    $LoginSuccess = $ShowRunningConfig | Select-String -Pattern "login on-success log"
    IF (!$LoginFailure) {
        $LoginFailure = "login on-failure not configured" | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF (!$LoginSuccess) {
        $LoginSuccess = "login on-success not configured" | Out-String
        $OpenFinding = $True
    }
    $FindingDetails += ($LoginFailure | Out-String).Trim()
    $FindingDetails += "" | Out-String
    $FindingDetails += ($LoginSuccess | Out-String).Trim()
    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        $Status = "NotAFinding"
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

Function Get-V215850 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215850
        STIG ID    : CISC-ND-001270
        Rule ID    : SV-215850r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-NDM-000321
        Rule Title : The Cisco router must be configured to generate log records for privileged activities.
        DiscussMD5 : FA1F339C351D1C903620B12A1C65FF0A
        CheckMD5   : 8C49529CCA5C92BEB41332F589375D6D
        FixMD5     : 3FF06C089D905636D15D3774358B22CB
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $Status = "NotAFinding"
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

Function Get-V215855 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215855
        STIG ID    : CISC-ND-001410
        Rule ID    : SV-215855r1069501_rule
        CCI ID     : CCI-000366, CCI-000537
        Rule Name  : SRG-APP-000516-NDM-000340
        Rule Title : The Cisco router must be configured to back up the configuration when changes occur.
        DiscussMD5 : 6EE4BBF0BC1248E5EB03F0E6278D282E
        CheckMD5   : 95020C29ABF9FCBCEFC68DCF41FEDBE7
        FixMD5     : 3D6391F5E75FFC2EB85529279DD68224
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
    # TODO REMOVE
    #$FindingDetails = @()
    $EventManager = $ShowRunningConfig | Select-String -Pattern "^event manager applet"
    IF ($EventManager) {
        ForEach ($BackupConfig in $EventManager) {
            $FindingDetails += ($BackupConfig | Out-String).Trim()
            $FindingDetails += (Get-Section $ShowRunningConfig $BackupConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "Cisco router is not configured to conduct backups of the configuration when changes occur" | Out-String
        $Status = "Open"
    } #<--------------------------------------------------------- Might be able to dermine full status in the future, however I would need configuration files that are properly configured to test against.
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

Function Get-V215856 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215856
        STIG ID    : CISC-ND-001440
        Rule ID    : SV-215856r991889_rule
        CCI ID     : CCI-001159, CCI-004909
        Rule Name  : SRG-APP-000516-NDM-000344
        Rule Title : The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
        DiscussMD5 : 90C82E3DF14F4AA185857EC1A544EB50
        CheckMD5   : 30A15CA834EBB9BB746589B425D3EEEC
        FixMD5     : 05BBB5294BF7D7AA2291FED2BB06021C
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
    $OpenFinding = $False
    $Trustpoint = $ShowRunningConfig | Select-String -Pattern "^crypto pki trustpoint"
    IF ($Trustpoint) {
        ForEach ($Point in $Trustpoint) {
            $Enrollment = Get-Section $ShowRunningConfig $Point.ToString() | Select-String -Pattern "enrollment"
            IF ($Enrollment) {
                If ($Enrollment -like "*url*") {
                    $FindingDetails += ($Point | Out-String).Trim() + " - ensure url is from a trusted CA. " | Out-String
                    $FindingDetails += ($Point | Out-String).Trim()
                    $FindingDetails += " " + ($Enrollment | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    $FindingDetails += ($Point | Out-String).Trim() + " is not configured for url enrollment" | Out-String
                    $FindingDetails += ($Point | Out-String).Trim()
                    $FindingDetails += " " + ($Enrollment | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += "There is no enrollment configuration configured for: " + ($Point | Out-String).Trim()
                $FindingDetails += ($Point | Out-String).Trim()
                $FindingDetails += (Get-Section $ShowRunningConfig $Point.ToString() | Out-String).Trim()
            }
        }
    }
    Else {
        $FindingDetails += "PKI trust point have not been configured" | Out-String
    }
    IF ($OpenFinding) {
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

Function Get-V220139 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220139
        STIG ID    : CISC-ND-001450
        Rule ID    : SV-220139r961863_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000516-NDM-000350
        Rule Title : The Cisco router must be configured to send log data to at least two syslog servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).
        DiscussMD5 : 2B60B499490110C0A7C4C1920395BB82
        CheckMD5   : 1B706946007EACAC4CDE4EEC9EEAC465
        FixMD5     : 46F1C7DF06307FF389D8E34AF97A8DE7
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
    $OpenFinding = $False
    $LoggingHost = $ShowRunningConfig | Select-String -Pattern "^logging host"
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $RouterIPs = @()
    ForEach ($Interface in $Interfaces) {
        $IP = (((Get-Section $ShowRunningConfig $Interface | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
        IF ($IP -match "\d+\.\d+\.\d+\.\d+") {
            $RouterIPs += $IP
        }
    }
    IF ($LoggingHost) {
        foreach ($SysLogServer in $LoggingHost) {
            $SysLogServer = (($SysLogServer | Out-String).Trim()).Replace("logging host ", "")
            IF ($SysLogServer -in $RouterIPs) {
                $OpenFinding = $True
                $FindingDetails += "The router is not configured to off-load log records onto a different system." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += ($LoggingHost | Out-String).Trim()
    }
    Else {
        $FindingDetails += "The router is not configured to send log data to the syslog server, this is a finding." | Out-String
        $OpenFinding = $True
    }

    If ($LoggingHost -and ($LoggingHost | Measure-Object).Count -lt 2) {
        $OpenFinding = $True
        $FindingDetails += "" | Out-String
        $FindingDetails += "A minimum of two syslog servers are required." | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        $Status = "NotAFinding"
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

Function Get-V220140 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220140
        STIG ID    : CISC-ND-001470
        Rule ID    : SV-220140r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-NDM-000351
        Rule Title : The Cisco router must be running an IOS release that is currently supported by Cisco Systems.
        DiscussMD5 : 48C9EDC8AEA8EE82D3771483542AB7DB
        CheckMD5   : 3BC8574C55E3EA3DF7B92C575B7B12CB
        FixMD5     : 6B4D73D26C5614740F02021AADF6ED58
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
    $FindingDetails += "Check with vendor for support status of the device" | Out-String
    $FindingDetails += "Device Info:" | Out-String
    $FindingDetails += ($DeviceInfo | Out-String).Trim()
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDixxY0OlX3Col8
# 84Nh+SFH/LG07By4C3iu96zaVLfJ4KCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCC6FVldh7I8Bza/bgWL8D17e1P0twAwLTmDGN8eGIPbdzANBgkqhkiG9w0BAQEF
# AASCAQBdUYB/veM4XeNGLMLJmOwq/iAjKJpx8zx4Ct+XnwTO5e60Gd0704S6yGN0
# O7xYnD9Jc+D3oIoGx3rzeMRHVw0v2Ufb94j8OAjP6kKvlaJ4s+aGt6IhkAwy+e4T
# XJT/oQDw3iEyHx/gO0YuqVu+A/1RLsPkJ7bxOnM2FrgQXm8jEeJnQXdMgjgXmAQT
# kVuv2jhvH40mY9kZt7jOk9AePozlDooXyIvyjWkg68OumPlZtv2kel6S+O5FBmwE
# ua+kR3IuphFzAl+mGqloe94e7FygnWQtsrWO+g4UGrMxRtfTXh2SWp5k4+MjkFSQ
# aiSIXEKv2yQDtLGyU33tHG+uGUNloYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTAxMlowLwYJKoZIhvcNAQkEMSIEIKvQX+pLmEcaZckyupfb/vs0rFLS
# +0/6ifxpC5ZPzy7GMA0GCSqGSIb3DQEBAQUABIICAHxtbw8XwXcqFv+Z0GUR0USv
# ZlzBegbXRq8BCHB3UrmA4By4kozxJRDE1IzXU25DZMRLeZh4rsqzlnlMvEylJaHO
# un+h1pfe3YO8oOkRuDzlOfGVw0fI0mNF1keEXLGycEKTjkDXm1sf3M+Ox2wQl0fK
# EvrSmElBLxjmt6e0G3wUNyOnNnwlOeiVlWIe0vTa5TbjqL7ww1eZ/6RB8JdXVHfB
# X3wjtoxcHe00EfFpCPLxmg4uvHTi9JPQqy3HzsSfBVJJjsaK8T5bZVIVJ70LbfHg
# 0fVGImNiidK1fzKOlARCQQbePI35SmuMqIUHBRpFN9Ho80LZxKCY81p9dCZ27sOE
# 5EqRG48BI095vfGQInnWvMZ3tQRSbz4Mo4JB89ZCKmY6Jd5FXQaa+7H2t6MVLWgt
# KRU7k27FS0y8Ys/Ya7/l7tb6ejxI78gxTpbuof9+H6dmIeuYB8jVUXPgHLK4USWY
# yOXVdrNNaVPG3D1bMIJxXjMPoM0+DaO3aUpJ06R/k0KM/cTpQMUDzCwepNZbIpz0
# ekEpPkZf6nKjMV8GkKPTqk9Kvvhc6tfF08wmG5YOLPx5SoDthNpKwKoU23KqDrp4
# uSA7l5B8yhfDu4VIJGrq68FXlT5zZ/1XWGjbzTmi5Rc7NKN4scSKEcuupvwD5+i3
# o6FWVnBHC5DQzgyvnjVz
# SIG # End signature block
