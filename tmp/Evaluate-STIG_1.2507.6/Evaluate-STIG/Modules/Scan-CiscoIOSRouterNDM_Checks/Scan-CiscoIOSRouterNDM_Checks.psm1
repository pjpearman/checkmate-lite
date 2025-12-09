##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS Router NDM
# Version:  V3R5
# Class:    UNCLASSIFIED
# Updated:  10/7/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V215662 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215662
        STIG ID    : CISC-ND-000010
        Rule ID    : SV-215662r1050869_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-NDM-000200
        Rule Title : The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.
        DiscussMD5 : F1519029437488F84FA9ED3FCE4716F8
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

Function Get-V215663 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215663
        STIG ID    : CISC-ND-000090
        Rule ID    : SV-215663r960777_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings += @()

    IF ($ShowRunningConfig -contains "archive") {
        $archiveConfig = Get-Section $ShowRunningConfig "archive".ToString()

        if (!($archiveConfig -contains "log config")) {
            $OpenFinding = $True
            $Findings += "log config"
        }
        if (!($archiveConfig -contains "logging enable")) {
            $OpenFinding = $True
            $Findings += "logging enable"
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to automatically audit account creation. Configure the router to log account creation via these commands under 'archive'." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
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

Function Get-V215664 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215664
        STIG ID    : CISC-ND-000100
        Rule ID    : SV-215664r960780_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings += @()

    IF ($ShowRunningConfig -contains "archive") {
        $archiveConfig = Get-Section $ShowRunningConfig "archive".ToString()

        if (!($archiveConfig -contains "log config")) {
            $OpenFinding = $True
            $Findings += "log config"
        }
        if (!($archiveConfig -contains "logging enable")) {
            $OpenFinding = $True
            $Findings += "logging enable"
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to automatically audit account modification. Configure the router to log account modification via these commands under 'archive'." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
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

Function Get-V215665 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215665
        STIG ID    : CISC-ND-000110
        Rule ID    : SV-215665r960783_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings += @()

    IF ($ShowRunningConfig -contains "archive") {
        $archiveConfig = Get-Section $ShowRunningConfig "archive".ToString()

        if (!($archiveConfig -contains "log config")) {
            $OpenFinding = $True
            $Findings += "log config"
        }
        if (!($archiveConfig -contains "logging enable")) {
            $OpenFinding = $True
            $Findings += "logging enable"
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to automatically audit account disabling actions. Configure the router to log account disabling via these commands under 'archive'." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
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

Function Get-V215666 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215666
        STIG ID    : CISC-ND-000120
        Rule ID    : SV-215666r960786_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings += @()

    IF ($ShowRunningConfig -contains "archive") {
        $archiveConfig = Get-Section $ShowRunningConfig "archive".ToString()

        if (!($archiveConfig -contains "log config")) {
            $OpenFinding = $True
            $Findings += "log config"
        }
        if (!($archiveConfig -contains "logging enable")) {
            $OpenFinding = $True
            $Findings += "logging enable"
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to automatically audit account removal actions. Configure the router to log account removal via these commands under 'archive'." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
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

Function Get-V215667 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215667
        STIG ID    : CISC-ND-000140
        Rule ID    : SV-215667r991819_rule
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

Function Get-V215668 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215668
        STIG ID    : CISC-ND-000150
        Rule ID    : SV-215668r960840_rule
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
    # Verify if logging block-for is enabled.
    IF (!($ShowRunningConfig | Select-String -Pattern "^login block-for")) {
        $Status = "Open"
        $FindingDetails += "This device is not configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Login block equal to 3 attempts and 15 minutes lock out.
        IF ($ShowRunningConfig | Select-String -Pattern "^login block-for 900 attempts 3") {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured to enforce the limit of three consecutive invalid logon attempts, and to lock out the user account from accessing the device for 15 minutes" | Out-String
            $FindingDetails += "" | Out-String
        }
        # Login block not equal to 3 attempts and 15 minutes lock out.
        ELSE {
            $Status = "Open"
            $FindingDetails += "This device is not configured to enforce the limit of three consecutive invalid logon attempts, and to lock out the user account from accessing the device for 15 minutes." | Out-String
            $FindingDetails += "The below configuration is present:" | Out-String
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^login block-for").ToString() | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V215669 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215669
        STIG ID    : CISC-ND-000160
        Rule ID    : SV-215669r960843_rule
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
    $Status = "Not_Reviewed"
    $ConfigBanner = @()
    $StigBanner = @(
    'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.'
    'By using this IS (which includes any device attached to this IS), you consent to the following conditions:'
    '-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.'
    '-At any time, the USG may inspect and seize data stored on this IS.'
    '-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.'
    '-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.'
    '-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.')

    IF ($ShowRunningConfig -like "banner login ^C*") {
        $running = $False
        $runningLine = ""
        ForEach ($line in $ShowRunningConfig) {
            IF ($running) {
                IF ($line -like "^C*") {
                    $running = $False
                }
                ELSEIF ($line.EndsWith(".")) {
                    $ConfigBanner += $runningLine + $line + " "
                    $runningLine = ""
                }
                ELSEIF ($line.EndsWith(":")) {
                    $ConfigBanner += $runningLine + $line + " "
                    $runningLine = ""
                }
                ELSE {
                    $runningLine += $line + " "
                }
            }
            ELSEIF ($line -like "banner login ^C*") {
                $running = $True
            }
        }
        IF ($ConfigBanner -AND $StigBanner) {
            $ConfigBannerString =  ([string]$ConfigBanner -replace '\s+', ' ' -replace '- ', '-' -replace '^ ', '').Trim()
            $StigBannerString = ([string]$StigBanner).Trim()

            IF ($ConfigBannerString -ceq $StigBannerString) {
                $Status = "NotAFinding"
            }
            ELSE {
                $Status = "Not_Reviewed"
                $FindingDetails += "" | Out-String
                $FindingDetails += "This device must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device." | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        $FindingDetails += "" | Out-String
        $FindingDetails += "---------------------------------------- Login Banner Configured ----------------------------------------" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($line in $ConfigBanner){
            $FindingDetails += $line.ToString() | Out-String
            $FindingDetails += "" | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $Status = "Open"
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device. No banner is detected. Configure this device to display the Standard Mandatory DoD Notice and Consent Banner before granting access as shown below." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "---------------------------------------- Compliant Banner ----------------------------------------" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($line in $StigBanner){
            $FindingDetails += $line
        }
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

Function Get-V215670 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215670
        STIG ID    : CISC-ND-000210
        Rule ID    : SV-215670r984088_rule
        CCI ID     : CCI-000166, CCI-000172, CCI-002234
        Rule Name  : SRG-APP-000080-NDM-000345
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

Function Get-V215672 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215672
        STIG ID    : CISC-ND-000280
        Rule ID    : SV-215672r960894_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-NDM-000226
        Rule Title : The Cisco router must produce audit records containing information to establish when (date and time) the events occurred.
        DiscussMD5 : D3221577E453F1B93CE67F6D72965A55
        CheckMD5   : B96EF9F8A79F1AC9A8E5BB4C821442DA
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
    # Check if service timestamps is configured.
    $TimestampsLogConfig = $ShowRunningConfig | Select-String -Pattern "^service timestamps log datetime"
    IF ($TimestampsLogConfig) {
        $Status = "NotAFinding"
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is configured to produce audit records containing information to establish when (date and time) the events occurred:" | Out-String
        $FindingDetails += $TimestampsLogConfig | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $Status = "Open"
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device must be configured to produce audit records containing information to establish when (date and time) the events occurred." | Out-String
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

Function Get-V215673 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215673
        STIG ID    : CISC-ND-000290
        Rule ID    : SV-215673r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-NDM-000227
        Rule Title : The Cisco router must produce audit records containing information to establish where the events occurred.
        DiscussMD5 : AFF39330BBAA35F46273890D1E49DA4A
        CheckMD5   : 87DA5398989C1121B6097DC340EDA056
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
    $OpenFinding = $False
    $ACLNames = @()

    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip access-group *")) {
            # Add interface without an inbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interface without an ACL configured:" | Out-String
            $FindingDetails += "------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $ACLNames = $InterfaceConfig | Select-String -Pattern "ip access-group .*"
            ForEach ($ACLName in $ACLNames) {
                $ACLName = $ACLName.ToString().Split([char[]]"") | Select-Object -Index 2
                $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
                IF (!$ACLExtended) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Extended ACL $ACLName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                    ForEach ($ACE in $ACLConfig) {
                        IF (($ACE | Select-String -Pattern "deny") -AND ($ACE | Select-String -Pattern ".* log-input")) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "ACE $ACE part of ACL $ACLName under interface $Interface is configured with log-input." | Out-String
                        }
                        ELSEIF ($ACE | Select-String -Pattern "deny") {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Verify that the ACE $ACE part of ACL $ACLName under interface $Interface is configured with log-input and make finding determination based on STIG check guidance." | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
            }
        }
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
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

Function Get-V215674 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215674
        STIG ID    : CISC-ND-000330
        Rule ID    : SV-215674r960909_rule
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
    # Get archive configuration.
    $Archive = $ShowRunningConfig | Select-String -Pattern "^archive"
    IF ($Archive) {
        $ArchiveConfig = Get-Section $ShowRunningConfig $Archive.ToString()
        # Check if log config and logging enable are configured.
        IF (!($ArchiveConfig | Select-String -Pattern "log config") -OR !($ArchiveConfig | Select-String -Pattern "logging enable")) {
            $Status = "Open"
            $FindingDetails += "This device is not configured to generate audit records containing the full-text recording of privileged commands." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured to generate audit records containing the full-text recording of privileged commands." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V215675 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215675
        STIG ID    : CISC-ND-000380
        Rule ID    : SV-215675r960933_rule
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
    # Verify if persistent logging is enabled.
    IF (!($ShowRunningConfig | Select-String -Pattern "^logging persistent url")) {
        $Status = "NotAFinding"
        $FindingDetails += "This device is not configured for persistent logging." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # File privilege not equal to 15.
        IF ($ShowRunningConfig | Select-String -Pattern "^file privilege") {
            $Status = "Open"
            $FilePrivilege = ($ShowRunningConfig | Select-String -Pattern "^file privilege").ToString().Split([char[]]"") | Select-Object -Last 1
            $FindingDetails += "This device is configured for persistent logging and file privilege $FilePrivilege" | Out-String
            $FindingDetails += "" | Out-String
        }
        # File privilege equal to 15.
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured for persistent logging and file privilege 15." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V215676 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215676
        STIG ID    : CISC-ND-000390
        Rule ID    : SV-215676r960936_rule
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
    # Verify if persistent logging is enabled.
    IF (!($ShowRunningConfig | Select-String -Pattern "^logging persistent url")) {
        $Status = "NotAFinding"
        $FindingDetails += "This device is not configured for persistent logging." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # File privilege not equal to 15.
        IF ($ShowRunningConfig | Select-String -Pattern "^file privilege") {
            $Status = "Open"
            $FilePrivilege = ($ShowRunningConfig | Select-String -Pattern "^file privilege").ToString().Split([char[]]"") | Select-Object -Last 1
            $FindingDetails += "This device is configured for persistent logging and file privilege $FilePrivilege" | Out-String
            $FindingDetails += "" | Out-String
        }
        # File privilege equal to 15.
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured for persistent logging and file privilege 15." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V215677 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215677
        STIG ID    : CISC-ND-000460
        Rule ID    : SV-215677r960960_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"

    IF ($ShowRunningConfig -like "file privilege*") {
        $Priv = $ShowRunningConfig | Select-String -Pattern "^file privilege"
        $level = ($Priv -split " ")[2]
        if ($level -ne "15") {
            $Status = "Open"
            $FindingDetails += "The Cisco router must be configured to limit privileges to change the software resident within software libraries. Configure the router to only allow administrators with privilege level '15' access to the file system." | Out-String
            $FindingDetails += "Note: The default privilege level required for access to the file system is '15'; hence, the command file privilege '15' will not be shown in the configuration." | Out-String
        }
    }
    else {
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

Function Get-V215678 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215678
        STIG ID    : CISC-ND-000470
        Rule ID    : SV-215678r1043177_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings = @()

    IF ($ShowRunningConfig -contains "boot network") {
        $OpenFinding = $True
        $Findings += "boot network"
    }
    IF ($ShowRunningConfig -contains "ip boot server") {
        $OpenFinding = $True
        $Findings += "ip boot server"
    }
    IF ($ShowRunningConfig -contains "ip bootp server") {
        $OpenFinding = $True
        $Findings += "ip bootp server"
    }
    IF ($ShowRunningConfig -contains "ip dns server") {
        $OpenFinding = $True
        $Findings += "ip dns server"
    }
    IF ($ShowRunningConfig -contains "ip identd") {
        $OpenFinding = $True
        $Findings += "ip identd"
    }
    IF ($ShowRunningConfig -contains "ip finger") {
        $OpenFinding = $True
        $Findings += "ip finger"
    }
    IF ($ShowRunningConfig -contains "ip http server") {
        $OpenFinding = $True
        $Findings += "ip http server"
    }
    IF ($ShowRunningConfig -contains "ip rcmd rcp-enable") {
        $OpenFinding = $True
        $Findings += "ip rcmd rcp-enable"
    }
    IF ($ShowRunningConfig -contains "ip rcmd rsh-enable") {
        $OpenFinding = $True
        $Findings += "ip rcmd rsh-enable"
    }
    IF ($ShowRunningConfig -contains "service config") {
        $OpenFinding = $True
        $Findings += "service config"
    }
    IF ($ShowRunningConfig -contains "service finger") {
        $OpenFinding = $True
        $Findings += "service finger"
    }
    IF ($ShowRunningConfig -contains "service tcp-small-servers") {
        $OpenFinding = $True
        $Findings += "service tcp-small-servers"
    }
    IF ($ShowRunningConfig -contains "service udp-small-servers") {
        $OpenFinding = $True
        $Findings += "service udp-small-servers"
    }
    IF ($ShowRunningConfig -contains "service pad") {
        $OpenFinding = $True
        $Findings += "service pad"
    }
    IF ($ShowRunningConfig -contains "service call-home") {
        $OpenFinding = $True
        $Findings += "service call-home"
    }

    if ($OpenFinding) {
        $FindingDetails += "The Cisco router must be configured to prohibit the use of all unnecessary and nonsecure functions and services. The following configurations have been detected and must be removed per this requirement." | Out-String
        $FindingDetails += "---------------------------------------- Invalid Configurations ----------------------------------------" | Out-String
        ForEach ($finding in $Findings) {
            $FindingDetails += $finding | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    else {
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

Function Get-V215679 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215679
        STIG ID    : CISC-ND-000490
        Rule ID    : SV-215679r1051115_rule
        CCI ID     : CCI-001358, CCI-002111
        Rule Name  : SRG-APP-000148-NDM-000346
        Rule Title : The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.
        DiscussMD5 : FDCD143C4A64A74BCF259F2DAC72CDC1
        CheckMD5   : 1CA7085A5EC87E3FF273D02DC77727A4
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False

    IF (!($ShowRunningConfig -like "username * privilege * secret *")) {
        $FindingDetails += "Configure a local account to be used as the account of last resort in the event the authentication server is unavailable." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    If (!($ShowRunningConfig -like "aaa authentication login default group tacacs+ local")) {
        $FindingDetails += "Configure the authentication order to use the local account if the authentication server is not reachable." | Out-String
        $FindingDetails += "Required configuration: 'aaa authentication login default group tacacs+ local'" | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
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

Function Get-V215681 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215681
        STIG ID    : CISC-ND-000550
        Rule ID    : SV-215681r991820_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-APP-000164-NDM-000252
        Rule Title : The Cisco router must be configured to enforce a minimum 15-character password length.
        DiscussMD5 : 0CC444F915EE49514C33FC41A40592B8
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False

    IF ($ShowRunningConfig -like "aaa common-criteria policy *") {
        if ($ShowRunningConfig -like "*min-length 15") {
            $Status = "NotAFinding"
        }
        else {
            $OpenFinding = $True
        }
    }
    else {
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to enforce a minimum 15-character password length. Configure the Cisco router to enforce a minimum 15-character password length with the commands: 'aaa common-criteria policy PASSWORD_POLICY' and 'min-length 15'."
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

Function Get-V215682 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215682
        STIG ID    : CISC-ND-000570
        Rule ID    : SV-215682r991823_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-APP-000166-NDM-000254
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one uppercase character be used.
        DiscussMD5 : 36FEAE5F2BDE0023706C61CF0503DA74
        CheckMD5   : 910BCD1ADA2D23EAF4E829AF0994A662
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
    # Get aaa common-criteria policy configuration.
    $AaaPolicy = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF ($AaaPolicy) {
        $AaaPolicyConfig = Get-Section $ShowRunningConfig $AaaPolicy.ToString()
        # Check if uppercase is configured.
        IF (!($AaaPolicyConfig | Select-String -Pattern "upper-case")) {
            $Status = "Open"
            $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one uppercase character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured to enforce password complexity by requiring that at least one uppercase character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    ELSE {
        $Status = "Open"
        $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one uppercase character be used." | Out-String
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

Function Get-V215683 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215683
        STIG ID    : CISC-ND-000580
        Rule ID    : SV-215683r991826_rule
        CCI ID     : CCI-004066
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
    # Get aaa common-criteria policy configuration.
    $AaaPolicy = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF ($AaaPolicy) {
        $AaaPolicyConfig = Get-Section $ShowRunningConfig $AaaPolicy.ToString()
        # Check if lowercase is configured.
        IF (!($AaaPolicyConfig | Select-String -Pattern "lower-case")) {
            $Status = "Open"
            $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one lowercase character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured to enforce password complexity by requiring that at least one lowercase character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    ELSE {
        $Status = "Open"
        $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one lowercase character be used." | Out-String
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

Function Get-V215684 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215684
        STIG ID    : CISC-ND-000590
        Rule ID    : SV-215684r991827_rule
        CCI ID     : CCI-004066
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
    # Get aaa common-criteria policy configuration.
    $AaaPolicy = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF ($AaaPolicy) {
        $AaaPolicyConfig = Get-Section $ShowRunningConfig $AaaPolicy.ToString()
        # Check if numeric count is configured.
        IF (!($AaaPolicyConfig | Select-String -Pattern "numeric-count")) {
            $Status = "Open"
            $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one numeric character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured to enforce password complexity by requiring that at least one numeric character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    ELSE {
        $Status = "Open"
        $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one numeric character be used." | Out-String
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

Function Get-V215685 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215685
        STIG ID    : CISC-ND-000600
        Rule ID    : SV-215685r991828_rule
        CCI ID     : CCI-004066
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
    # Get aaa common-criteria policy configuration.
    $AaaPolicy = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF ($AaaPolicy) {
        $AaaPolicyConfig = Get-Section $ShowRunningConfig $AaaPolicy.ToString()
        # Check if special case is configured.
        IF (!($AaaPolicyConfig | Select-String -Pattern "special-case")) {
            $Status = "Open"
            $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one special character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured to enforce password complexity by requiring that at least one special character be used." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    ELSE {
        $Status = "Open"
        $FindingDetails += "This device is not configured to enforce password complexity by requiring that at least one special character be used." | Out-String
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

Function Get-V215686 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215686
        STIG ID    : CISC-ND-000610
        Rule ID    : SV-215686r1043189_rule
        CCI ID     : CCI-004066
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
    # Get aaa common-criteria policy configuration.
    $AaaPolicy = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF ($AaaPolicy) {
        $AaaPolicyConfig = Get-Section $ShowRunningConfig $AaaPolicy.ToString()
        # Check if char-changes is configured.
        IF ($AaaPolicyConfig | Select-String -Pattern "char-changes") {
            $Characters = ($AaaPolicyConfig | Select-String -Pattern "char-changes").ToString().Split([char[]]"") | Select-Object -Last 1
            IF ([int]$Characters -gt 7) {
                $Status = "NotAFinding"
                $FindingDetails += "This device is configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password." | Out-String
                $FindingDetails += "" | Out-String
            }
            ELSE {
                $Status = "Open"
                $FindingDetails += "This device is not configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password." | Out-String
                $FindingDetails += ($AaaPolicyConfig | Select-String -Pattern "char-changes").ToString() | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        ELSE {
            $Status = "Open"
            $FindingDetails += "This device is not configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    ELSE {
        $Status = "Open"
        $FindingDetails += "This device is not configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password." | Out-String
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

Function Get-V215687 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215687
        STIG ID    : CISC-ND-000620
        Rule ID    : SV-215687r991830_rule
        CCI ID     : CCI-004062, CCI-004910
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"

    IF ($ShowRunningConfig -contains "service password-encryption") {
        $Status = "NotAFinding"
    }
    else {
        $FindingDetails += "The Cisco router must only store cryptographic representations of passwords. The configuration: 'service password-encryption' must be enabled to meet this requirement." | Out-String
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

Function Get-V215688 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215688
        STIG ID    : CISC-ND-000720
        Rule ID    : SV-215688r961068_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-APP-000190-NDM-000267
        Rule Title : The Cisco router must be configured to terminate all network connections associated with device management after five minutes of inactivity.
        DiscussMD5 : C55855B1F7DC3A2BCA7DC4A4B7EA8027
        CheckMD5   : 4087E71048E19E385771C782AF5C15D6
        FixMD5     : F862AAE6A6091706AEDA3A79FF91DC71
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
    $Findings = @()
    $MgtLines = $ShowRunningConfig | Select-String -Pattern "^line (vty|con)"
    $HttpSecureServer = $ShowRunningConfig | Select-String -Pattern "^ip http secure-server"
    $NoHttpSecureServer = $ShowRunningConfig | Select-String -Pattern "^no ip http secure-server"
    $HttpTimePolicy = $ShowRunningConfig | Select-String -Pattern "^ip http timeout-policy idle 300"

    IF ($MgtLines) {
        ForEach ($line in $MgtLines) {
            $MgtLinesConfig = Get-Section $ShowRunningConfig $line.ToString()
            $ExecTimeout = $MgtLinesConfig | Select-String -Pattern "exec-timeout"
            $NoExecTimeout = $MgtLinesConfig | Select-String -Pattern "no exec-timeout"
            IF ($NoExecTimeout) {
                $Findings += "" | Out-String
                $Findings += "'no exec-timeout' is configured under $line" | Out-String
            }
            ELSEIF ($ExecTimeout) {
                $Timeout = [int](($ExecTimeout -split " ")[1])
                $SecondaryTimeout = [int](($ExecTimeout -split " ")[2])
                IF ($Timeout -gt 5) {
                    $Findings += "" | Out-String
                    $Findings += "Uncompliant configuration:"
                    $Findings += $line
                    $Findings += ($ExecTimeout.ToString() | Out-String).Trim()
                    $OpenFinding = $True
                }
                ELSEIF (($timeout -eq 5) -AND ($SecondaryTimeout -gt 0)) {
                    $Findings += "" | Out-String
                    $Findings += "Uncompliant configuration:"
                    $Findings += $line
                    $Findings += ($ExecTimeout.ToString() | Out-String).Trim()
                    $OpenFinding = $True
                }
                ELSE {
                    $Findings += "" | Out-String
                    $Findings += "Compliant configuration:"
                    $Findings += $line
                    $Findings += ($ExecTimeout.ToString() | Out-String).Trim()
                }
            }
            ELSE {
                $Findings += "" | Out-String
                $Findings += "exec-timeout is not configured under $line. Timeout for EXEC on Cisco devices defaults to '10' minutes." | Out-String
                $OpenFinding = $True
            }
        }
    }

    IF ($NoHttpSecureServer) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is configured with 'no ip http secure-server'." | Out-String
        $FindingDetails += "" | Out-String
        IF ($Findings) {
            $FindingDetails += $Findings | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    ELSEIF ($HttpSecureServer -AND $HttpTimePolicy) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is configured to terminate all network connections associated with device management after five minutes of inactivity, verify the below configuration and make finding determination based on STIG check guidance:" | Out-String
        $FindingDetails += "---------------------------------------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += ($HttpSecureServer.ToString() | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($HttpTimePolicy.ToString() | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += $Findings | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device must be configured to terminate all network connections associated with device management after five minutes of inactivity. Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        IF ($HttpSecureServer) {
            $FindingDetails += "The below configuration is present on this device:" | Out-String
            $FindingDetails += "--------------------------------------------------" | Out-String
            $FindingDetails += ($HttpSecureServer.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "Missing 'ip http secure-server'." | Out-String
            $FindingDetails += "" | Out-String
        }
        IF ($HttpTimePolicy) {
            $FindingDetails += "The below configuration is present on this device:" | Out-String
            $FindingDetails += "--------------------------------------------------" | Out-String
            $FindingDetails += ($HttpTimePolicy.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "Missing 'ip http timeout-policy'." | Out-String
            $FindingDetails += "" | Out-String
        }
        IF ($Findings) {
            $FindingDetails += $Findings | Out-String
            $FindingDetails += "" | Out-String
        }
        $OpenFinding = $True
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
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

Function Get-V215689 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215689
        STIG ID    : CISC-ND-000880
        Rule ID    : SV-215689r961290_rule
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
    # Get archive configuration.
    $Archive = $ShowRunningConfig | Select-String -Pattern "^archive"
    IF ($Archive) {
        $ArchiveConfig = Get-Section $ShowRunningConfig $Archive.ToString()
        # Check if log config and logging enable are configured.
        IF (!($ArchiveConfig | Select-String -Pattern "log config") -OR !($ArchiveConfig | Select-String -Pattern "logging enable")) {
            $Status = "Open"
            $FindingDetails += "This device is not configured to automatically audit account enabling actions." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $Status = "NotAFinding"
            $FindingDetails += "This device is configured to automatically audit account enabling actions." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V215691 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215691
        STIG ID    : CISC-ND-000980
        Rule ID    : SV-215691r961392_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"

    IF ($ShowRunningConfig -like "logging buffered * informational") {
        $Status = "NotAFinding"
    }
    else {
        $FindingDetails += "The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements. Verify that the Cisco router is configured with a logging buffer size. and is configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V215692 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215692
        STIG ID    : CISC-ND-001000
        Rule ID    : SV-215692r991831_rule
        CCI ID     : CCI-001858, CCI-003831
        Rule Name  : SRG-APP-000360-NDM-000295
        Rule Title : The Cisco router must be configured to generate an alert for all audit failure events.
        DiscussMD5 : 5A2FE043544D5FA66D313940CA473FE4
        CheckMD5   : C85A2D8FED67EE380B8E6D5498738D5E
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
    # Get show logging from show-tech.
    $ShowLogging = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Logging
    # Check if logging trap is configured.
    IF ($ShowLogging | Select-String -Pattern "Trap logging: disabled") {
        $Status = "Open"
        $FindingDetails += "This device must be configured to generate an alert for all audit failure events. Trap logging is disabled." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $Status = "NotAFinding"
        $FindingDetails += "This device is configured to generate an alert for all audit failure events." | Out-String
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

Function Get-V215693 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215693
        STIG ID    : CISC-ND-001030
        Rule ID    : SV-215693r991832_rule
        CCI ID     : CCI-001889, CCI-001890, CCI-004922, CCI-004923, CCI-004928
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
    # Get NTP servers configuration.
    $NtpServers = $ShowRunningConfig | Select-String -Pattern "^ntp server"
    # Get number of NTP servers configured.
    $NumberOfServers = ($NtpServers | Measure-Object -Line).Lines

    IF ($NumberOfServers -gt 1) {
        $Status = "NotAFinding"
        $FindingDetails += "There are $NumberOfServers NTP Servers configured." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $Status = "Open"
        IF ($NumberOfServers -eq 1) {
            $FindingDetails += "There is $NumberOfServers NTP Server configured. This device must be configured to synchronize its clock with redundant authoritative time sources." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "There aren't NTP Servers configured. This device must be configured to synchronize its clock with redundant authoritative time sources." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V215696 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215696
        STIG ID    : CISC-ND-001130
        Rule ID    : SV-215696r961506_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
        DiscussMD5 : D496EF6E2854AA9218CFE0EDD0C58874
        CheckMD5   : 48DA28B3D339CEDC2C46CE5A4E8C9859
        FixMD5     : 9CEB8F1836298C5725B12099833A43D2
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
    $MatchString = @()
    $SnmpViews = @()

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
        IF ($SnmpServerConfig | Select-String -Pattern "^snmp-server view .*") {
            $SnmpServerViews = $SnmpServerConfig | Select-String -Pattern "^snmp-server view .*"
            $FindingDetails += "" | Out-String
            $FindingDetails += "SNMP Server View Configuration:" | Out-String
            $FindingDetails += "--------------------------------" | Out-String
            ForEach ($SnmpServerView in $SnmpServerViews) {
                $MatchString = $SnmpServerView.ToString().Split([char[]]"") | Select-Object -First 3 | Join-String -Separator " "
                IF ($SnmpViews -notcontains $MatchString) {
                    $SnmpViews += $MatchString
                }
            }
            ForEach ($SnmpServerView in $SnmpViews) {
                $SnmpServerViewName = ($SnmpServerView).ToString().Split([char[]]"") | Select-Object -Index 2
                IF ($SnmpServerGroups) {
                    ForEach ($SnmpServerGroup in $SnmpServerGroups) {
                        IF ($SnmpServerGroup | Select-String -Pattern "snmp-server group .* v3 (auth|priv) (read|write) .*") {
                            $SnmpServerGroupRead = ($SnmpServerGroup).ToString().Split([char[]]"") | Select-Object -Index 6
                            $SnmpServerGroupWrite = ($SnmpServerGroup).ToString().Split([char[]]"") | Select-Object -Last 1
                            $SnmpServerGroup = ($SnmpServerGroup).ToString().Split([char[]]"") | Select-Object -Index 2
                            IF (($SnmpServerViewName -eq $SnmpServerGroupRead) -or ($SnmpServerViewName -eq $SnmpServerGroupWrite)) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "snmp-server view $SnmpServerViewName is configured matching a read/write view for group $SnmpServerGroup`:" | Out-String
                                $FindingDetails += $SnmpServerView
                                $FindingDetails += "" | Out-String
                            }
                            ELSE {
                                $OpenFinding = $True
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "snmp-server view $SnmpServerViewName does not match a read/write view for group $SnmpServerGroup." | Out-String
                            }
                        }
                    }
                }
                ELSE {
                    $OpenFinding = $True
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "snmp-server view $SnmpServerView is configured but it doesn't match any SNMP Server Group." | Out-String
                }
            }
        }
        ELSE {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the configuration to verify that this device is able to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)." | Out-String
            $FindingDetails += "snmp-server view read or write is not properly configured." | Out-String
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

Function Get-V215697 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215697
        STIG ID    : CISC-ND-001140
        Rule ID    : SV-215697r961506_rule
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
    $OpenFinding = $False
    $Exception = $False
    $MatchString = @()
    $SnmpViews = @()

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
        IF ($SnmpServerConfig | Select-String -Pattern "^snmp-server view .*") {
            $SnmpServerViews = $SnmpServerConfig | Select-String -Pattern "^snmp-server view .*"
            $FindingDetails += "" | Out-String
            $FindingDetails += "SNMP Server View Configuration:" | Out-String
            $FindingDetails += "--------------------------------" | Out-String
            ForEach ($SnmpServerView in $SnmpServerViews) {
                $MatchString = $SnmpServerView.ToString().Split([char[]]"") | Select-Object -First 3 | Join-String -Separator " "
                IF ($SnmpViews -notcontains $MatchString) {
                    $SnmpViews += $MatchString
                }
            }
            ForEach ($SnmpServerView in $SnmpViews) {
                $SnmpServerViewName = ($SnmpServerView).ToString().Split([char[]]"") | Select-Object -Index 2
                IF ($SnmpServerGroups) {
                    ForEach ($SnmpServerGroup in $SnmpServerGroups) {
                        IF ($SnmpServerGroup | Select-String -Pattern "snmp-server group .* v3 (auth|priv) (read|write) .*") {
                            $SnmpServerGroupRead = ($SnmpServerGroup).ToString().Split([char[]]"") | Select-Object -Index 6
                            $SnmpServerGroupWrite = ($SnmpServerGroup).ToString().Split([char[]]"") | Select-Object -Last 1
                            $SnmpServerGroup = ($SnmpServerGroup).ToString().Split([char[]]"") | Select-Object -Index 2
                            IF (($SnmpServerViewName -eq $SnmpServerGroupRead) -or ($SnmpServerViewName -eq $SnmpServerGroupWrite)) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "snmp-server view $SnmpServerViewName is configured matching a read/write view for group $SnmpServerGroup`:" | Out-String
                                $FindingDetails += $SnmpServerView
                                $FindingDetails += "" | Out-String
                            }
                            ELSE {
                                $OpenFinding = $True
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "snmp-server view $SnmpServerViewName does not match a read/write view for group $SnmpServerGroup." | Out-String
                            }
                        }
                    }
                }
                ELSE {
                    $OpenFinding = $True
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "snmp-server view $SnmpServerView is configured but it doesn't match any SNMP Server Group." | Out-String
                }
            }
        }
        ELSE {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the configuration to verify that this device is able to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)." | Out-String
            $FindingDetails += "snmp-server view read or write is not properly configured." | Out-String
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

Function Get-V215698 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215698
        STIG ID    : CISC-ND-001150
        Rule ID    : SV-215698r1107152_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000347
        Rule Title : The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
        DiscussMD5 : B9CAD587304827035D1B323D3221D8E0
        CheckMD5   : A581B1A7127E7582AA8D7E88AED89644
        FixMD5     : 747DA3CC5BA394914C933859E19D96B7
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
        IF (!($NtpConfig | Select-String -Pattern "^ntp authentication-key \d+ hmac-sha2-256")) {
            $OpenFinding = $True
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based." | Out-String
            $FindingDetails += "'ntp authentication-key <key> hmac-sha2-256' is missing." | Out-String
        }
        ELSE {
            $NtpAuthKeyConfigs = $NtpConfig | Select-String -Pattern "^ntp authentication-key \d+ hmac-sha2-256"
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

Function Get-V215699 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215699
        STIG ID    : CISC-ND-001200
        Rule ID    : SV-215699r961554_rule
        CCI ID     : CCI-001941, CCI-002890
        Rule Name  : SRG-APP-000411-NDM-000330
        Rule Title : The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
        DiscussMD5 : 515464A1D5B98B44D4F12FA3F0A50083
        CheckMD5   : 930014117BBB480B0D8586C6FA745DF3
        FixMD5     : E1A1BD3B6C3BE6C06638AA6B049B8E63
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

    # Get ip ssh configuration.
    $IpSshConfig = $ShowRunningConfig | Select-String -Pattern "^ip ssh"
    IF ($IpSshConfig) {
        IF (($IpSshConfig | Select-String -Pattern "^ip ssh version 2") -AND ($IpSshConfig | Select-String -Pattern "^ip ssh server algorithm mac hmac-sha2-256")) {
            $FindingDetails += "'ip ssh version 2' and 'ip ssh server algorithm mac hmac-sha2-256' are configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $OpenFinding = $True
            $FindingDetails += "This device is not configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions." | Out-String
            IF (!($IpSshConfig | Select-String -Pattern "^ip ssh version 2")) {
                $FindingDetails += "'ip ssh version 2' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
            IF (!($IpSshConfig | Select-String -Pattern "^ip ssh server algorithm mac hmac-sha2-256")) {
                $FindingDetails += "'ip ssh server algorithm mac hmac-sha2-256' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    ELSE {
        $OpenFinding = $True
        $FindingDetails += "This device is not cconfigured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions." | Out-String
        $FindingDetails += "ip ssh configuration is missing." | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
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

Function Get-V215700 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215700
        STIG ID    : CISC-ND-001210
        Rule ID    : SV-215700r961557_rule
        CCI ID     : CCI-003123
        Rule Name  : SRG-APP-000412-NDM-000331
        Rule Title : The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
        DiscussMD5 : 451042AAB21D5513C191D553EC3B6ADF
        CheckMD5   : 3572762719C622B89FA0D3D3F4F695C7
        FixMD5     : 2623F99CE01E718372307D2D45C5AA5E
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

    # Get ip ssh configuration.
    $IpSshConfig = $ShowRunningConfig | Select-String -Pattern "^ip ssh"
    IF ($IpSshConfig) {
        IF (($IpSshConfig | Select-String -Pattern "^ip ssh version 2") -AND ($IpSshConfig | Select-String -Pattern "^ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr")) {
            $FindingDetails += "'ip ssh version 2' and 'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr' are configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $OpenFinding = $True
            $FindingDetails += "This device is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions." | Out-String
            IF (!($IpSshConfig | Select-String -Pattern "^ip ssh version 2")) {
                $FindingDetails += "'ip ssh version 2' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
            IF (!($IpSshConfig | Select-String -Pattern "^ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr")) {
                $FindingDetails += "'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    ELSE {
        $OpenFinding = $True
        $FindingDetails += "This device is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions." | Out-String
        $FindingDetails += "ip ssh configuration is missing." | Out-String
        $FindingDetails += "" | Out-String
    }

    # Get https configuration.
    $HttpsConfig = $ShowRunningConfig | Select-String -Pattern "^ip http secure"
    IF ($HttpsConfig) {
        IF (($HttpsConfig | Select-String -Pattern "^ip http secure-server") -AND ($HttpsConfig | Select-String -Pattern "^ip http secure-ciphersuite aes-128-cbc-sha") -AND ($HttpsConfig | Select-String -Pattern "^ip http secure-client-auth") -AND ($HttpsConfig | Select-String -Pattern "^ip http secure-trustpoint")) {
            $FindingDetails += "ip http secure configuration is correct." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $OpenFinding = $True
            $FindingDetails += "This device is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions." | Out-String
            IF (!($HttpsConfig | Select-String -Pattern "^ip http secure-server")) {
                $FindingDetails += "'ip http secure-server' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
            IF (!($HttpsConfig | Select-String -Pattern "^ip http secure-ciphersuite aes-128-cbc-sha")) {
                $FindingDetails += "'ip http secure-ciphersuite aes-128-cbc-sha' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
            IF (!($HttpsConfig | Select-String -Pattern "^ip http secure-client-auth")) {
                $FindingDetails += "'ip http secure-client-auth' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
            IF (!($HttpsConfig | Select-String -Pattern "^ip http secure-trustpoint")) {
                $FindingDetails += "'ip http secure-trustpoint' is not properly configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    ELSE {
        $OpenFinding = $True
        $FindingDetails += "This device is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions." | Out-String
        $FindingDetails += "ip http secure configuration is missing." | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
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

Function Get-V215701 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215701
        STIG ID    : CISC-ND-001220
        Rule ID    : SV-215701r961620_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-NDM-000315
        Rule Title : The Cisco router must be configured to protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.
        DiscussMD5 : 8280ADB8113403B9D70BBDB808296D42
        CheckMD5   : 49E2AF582A7FF75042FF0566B2A3AC33
        FixMD5     : F2BDA8BD3F1C786096A1FEAD814766C2
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

    $ClassMapConfig = @()
    $ClassMaps = @()
    $ACLs = @()

    # Verify CoPP is enabled
    IF ($ShowRunningConfig | Select-String -Pattern "^control-plane") {
        $CoPPConfig = Get-Section $ShowRunningConfig "control-plane"
        IF ($CoPPConfig | Select-String -Pattern "service-policy input") {
            $PolicyMap = ($CoPPConfig | Select-String -Pattern "service-policy input").ToString().Split([char[]]"")[-1]
            # Add CoPP policy-map to FindingDetails
            $PolicyMapConfig = Get-Section $ShowRunningConfig "policy-map $PolicyMap"
            $ClassMaps = ($PolicyMapConfig | Select-String -Pattern "^class *")
            $FindingDetails += "" | Out-String
            IF ($PolicyMapConfig) {
                $FindingDetails += "Review the policy-map configuration to verify if traffic is being policed appropriately for each classification and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ("policy-map $PolicyMap" | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($PolicyMapConfig | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
                IF ($ClassMaps) {
                    ForEach ($ClassMap in $ClassMaps) {
                        $ClassMapName = $ClassMap.ToString().Split([char[]]"")[-1]
                        $ClassMapAnyConfig = Get-Section $ShowRunningConfig "class-map match-any $ClassMapName"
                        $ClassMapAllConfig = Get-Section $ShowRunningConfig "class-map match-all $ClassMapName"
                        # Get access-lists referenced by class-maps
                        IF ($ClassMapAnyConfig | Select-String -Pattern "match access-group name") {
                            $ACLs += ($ClassMapAnyConfig | Select-String -Pattern "match access-group name").ToString().Split([char[]]"")[-1]
                        }
                        ELSEIF ($ClassMapAllConfig | Select-String -Pattern "match access-group name") {
                            $ACLs += ($ClassMapAllConfig | Select-String -Pattern "match access-group name").ToString().Split([char[]]"")[-1]
                        }
                        # Add class-maps to FindingDetails
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the following class-map to verify if traffic types have been classified based on importance levels and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += ("class-map $ClassMapName"  | Out-String).Trim()
                        IF ($ClassMapAnyConfig) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += ($ClassMapAnyConfig | Out-String).Trim()
                        }
                        ELSEIF ($ClassMapAllConfig) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += ($ClassMapAllConfig | Out-String).Trim()
                        }
                        ELSE {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += ("This class-map is not properly configured. Make finding determination based on STIG check guidance." | Out-String).Trim()
                            $OpenFinding = $True
                        }
                        $FindingDetails += "" | Out-String
                    }
                    # Add class-maps access-lists to FindingDetails
                    IF ($ACLs) {
                        ForEach ($ACL in $ACLs) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Review the access-list configuration referenced by the class-map to determine if traffic is being classified appropriately and make finding determination based on STIG check guidance." | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            IF (Get-Section $ShowRunningConfig "ip access-list extended $ACL") {
                                $ACLConfig = Get-Section $ShowRunningConfig "ip access-list extended $ACL"
                                $FindingDetails += ("ip access-list extended $ACL" | Out-String).Trim()
                            }
                            ELSEIF (Get-Section $ShowRunningConfig "ipv6 access-list $ACL") {
                                $ACLConfig = Get-Section $ShowRunningConfig "ipv6 access-list $ACL"
                                $FindingDetails += ("ipv6 access-list $ACL" | Out-String).Trim()
                            }
                            ELSE {
                                $FindingDetails += "Access list $ACL is not configured. Make finding determination based on STIG check guidance." | Out-String
                            }
                            IF ($ACLConfig) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += ($ACLConfig | Out-String).Trim()
                            }
                            $FindingDetails += "" | Out-String
                        }
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "This device does not have access-lists configured under class-maps to protect against known types of denial-of-service (DoS) attacks." | Out-String
                    }
                }
                ELSE {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "This device does not have class-maps configured under policy-map $PolicyMap to protect against known types of denial-of-service (DoS) attacks." | Out-String
                    $OpenFinding = $True
                }
            }
            ELSE {
                $FindingDetails += ("Control plane policy map $PolicyMap is not properly configured. Make finding determination based on STIG check guidance." | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device does not have a policy-map configured under control-plane to protect against known types of denial-of-service (DoS) attacks." | Out-String
            $OpenFinding = $True
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is not configured for Control Plane Protection to protect against known types of denial-of-service (DoS) attacks." | Out-String
        $OpenFinding = $True
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

Function Get-V215703 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215703
        STIG ID    : CISC-ND-001250
        Rule ID    : SV-215703r961812_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings += @()

    IF ($ShowRunningConfig -contains "archive") {
        $archiveConfig = Get-Section $ShowRunningConfig "archive".ToString()

        if (!($archiveConfig -contains "log config")) {
            $OpenFinding = $True
            $Findings += "log config"
        }
        if (!($archiveConfig -contains "logging enable")) {
            $OpenFinding = $True
            $Findings += "logging enable"
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to generate log records when administrator privileges are deleted. Configure the Cisco router to generate log records when administrator privileges are deleted via these commands under 'archive'." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
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

Function Get-V215704 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215704
        STIG ID    : CISC-ND-001260
        Rule ID    : SV-215704r961824_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $Findings = @()

    IF ($ShowRunningConfig -notcontains "login on-failure log") {
        $OpenFinding = $True
        $Findings += "login on-failure log"
    }
    IF ($ShowRunningConfig -notcontains "login on-success log") {
        $OpenFinding = $True
        $Findings += "login on-success log"
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur. Configure the Cisco router to generate audit records when successful/unsuccessful logon attempts occur with the commands below." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
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

Function Get-V215705 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215705
        STIG ID    : CISC-ND-001270
        Rule ID    : SV-215705r961827_rule
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False
    $Findings += @()

    IF ($ShowRunningConfig -contains "archive") {
        $archiveConfig = Get-Section $ShowRunningConfig "archive".ToString()

        if (!($archiveConfig -contains "log config")) {
            $OpenFinding = $True
            $Findings += "log config"
        }
        if (!($archiveConfig -contains "logging enable")) {
            $OpenFinding = $True
            $Findings += "logging enable"
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
        $FindingDetails += "The Cisco router must be configured to generate log records for privileged activities. Configure the Cisco router to generate log records for privileged activities via these commands under 'archive'." | Out-String
        $FindingDetails += "-------------------- Missing configurations --------------------" | Out-String
        ForEach ($f in $Findings) {
            $FindingDetails += $f.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
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

Function Get-V215709 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215709
        STIG ID    : CISC-ND-001370
        Rule ID    : SV-215709r961863_rule
        CCI ID     : CCI-000370
        Rule Name  : SRG-APP-000516-NDM-000336
        Rule Title : The Cisco router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access.
        DiscussMD5 : 499C4BC76E102C66C756732859C51091
        CheckMD5   : 4ADD8DF67AD10F4C3A20B498750F2003
        FixMD5     : C2254D73923E659FC2F2E3A9603675B3
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
    $radiusHosts = $ShowRunningConfig | Select-String -Pattern "^radius-server host .* key .*"
    $lineConnections = $ShowRunningConfig | Select-String -Pattern "^line (con|vty)"
    $NoHttpSecureServer = $ShowRunningConfig | Select-String -Pattern "^no ip http secure-server"

    IF ($NoHttpSecureServer) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device is configured with 'no ip http secure-server'." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    ELSE {
        IF ($radiusHosts.count -lt 2 -AND $radiusHosts.count -gt 0) {
            $Findings += "The Cisco router must be configured to use at least two authentication servers. Review the configuration and verify at least two radius-server hosts are configured." | Out-String
            $Findings += "Radius server host configurations detected:" | Out-String
            $Findings += $radiusHosts | Out-String
            $Findings += "" | Out-String
            $OpenFinding = $True
        }

        IF (!($ShowRunningConfig -like "ip http authentication aaa login-authentication *")) {
            $Findings += "Http authentication configuration improperly configured. Review global authentication configurations and verify/enforce proper authentication." | Out-String
            $Findings += "Example http authentication: ip http authentication aaa login-authentication LOGIN_AUTHENTICATION" | Out-String
            $Findings += "" | Out-String
            $OpenFinding = $True
        }

        IF (!($ShowRunningConfig -like "aaa authentication * local")) {
            $Findings += "Authentication order configured incorrectly. Configure the authentication order to use the authentication servers as primary source for authentication." | Out-String
            $Findings += "Example configuration:" | Out-String
            $Findings += "aaa authentication CONSOLE local" | Out-String
            $Findings += "aaa authentication login LOGIN_AUTHENTICATION group radius local" | Out-String
            $Findings += "" | Out-String
            $OpenFinding = $True
        }
        ELSEIF (!($ShowRunningConfig -like "aaa authentication login * group radius local")) {
            $Findings += "Authentication order configured incorrectly. Configure the authentication order to use the authentication servers as primary source for authentication." | Out-String
            $Findings += "Example configuration:" | Out-String
            $Findings += "aaa authentication CONSOLE local" | Out-String
            $Findings += "aaa authentication login LOGIN_AUTHENTICATION group radius local" | Out-String
            $Findings += "" | Out-String
            $OpenFinding = $True
        }

        ForEach ($line in $lineConnections){
            $LineConfig = Get-Section $ShowRunningConfig $line.ToString()
            if (!($LineConfig -like "login authentication *")) {
                $Findings += "All network connections associated with device management must use the authentication servers for the purpose of login authentication." | Out-String
                $Findings += "No login authentication configuration found for connection: $line" | Out-String
                $Findings += "-------------------- $line Configuration --------------------" | Out-String
                $Findings += $LineConfig | Out-String
                $Findings += "" | Out-String
                $OpenFinding = $True
            }
        }

        IF ($OpenFinding) {
            $Status = "Open"
            $FindingDetails += "The Cisco router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access." | Out-String
            $FindingDetails += "One or more required configurations are missing. Please review the results below." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------------------------------- Results ----------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
            ForEach ($finding in $Findings) {
                $FindingDetails += $finding
            }
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access." | Out-String
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

Function Get-V215710 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215710
        STIG ID    : CISC-ND-001410
        Rule ID    : SV-215710r1069534_rule
        CCI ID     : CCI-000366, CCI-000537
        Rule Name  : SRG-APP-000516-NDM-000340
        Rule Title : The Cisco router must be configured to back up the configuration when changes occur.
        DiscussMD5 : 6EE4BBF0BC1248E5EB03F0E6278D282E
        CheckMD5   : 95020C29ABF9FCBCEFC68DCF41FEDBE7
        FixMD5     : 327BC10EC94C44664D4F7812ACE78649
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
    $backup = @('event manager applet BACKUP_CONFIG',
    'event syslog pattern "%SYS-5-CONFIG_I"',
    'action 1 info type routername',
    'action 2 cli command "enable"',
    'action 3 cli command "copy run scp" pattern "remote host"',
    'action 4 cli command "x.x.x.x" pattern "filename"',
    'action 5 cli command "$_info_routername-config"',
    'action 6 syslog priority informational msg "Configuration backup was executed"')

    IF ($ShowRunningConfig -like "event manager applet *") {
        $eventManager = $ShowRunningConfig | Select-String -Pattern "^event manager applet"
        $eventManagerConfig = Get-Section $ShowRunningConfig $eventManager.ToString()
        $cnt = 0
        $running = $False

        ForEach ($line in $eventManagerConfig) {
            if ($line -like 'event syslog pattern "%*"') {
                $cnt += 1
                $running = $True
            }
            elseif ($running) {
                if (($line -like "action * info type routername") -and ($cnt -eq 1)) {
                    $cnt += 1
                }
                elseif ($line -like 'action * cli command "enable"' -and $cnt -eq 2) {
                    $cnt += 1
                }
                elseif ($line -like 'action * cli command "copy run scp" pattern "remote host"' -and $cnt -eq 3) {
                    $cnt += 1
                }
                elseif ($line -like 'action * cli command "x.x.x.x" pattern "filename"' -and $cnt -eq 4) {
                    $cnt += 1
                }
                elseif ($line -like 'action * cli command "$_info_routername-config"' -and $cnt -eq 5) {
                    $cnt += 1
                }
                elseif ($line -like 'action * syslog priority informational msg "*"' -and $cnt -eq 6) {
                    $cnt += 1
                }
                elseif ($cnt -eq 7) {
                    $running = $False
                    $OpenFinding = $False
                    break
                }
            }
        }

        if ($cnt -ne 7) {
            $OpenFinding = $True
        }
    }
    Else {
        $OpenFinding = $True
    }

    if ($OpenFinding){
        $FindingDetails += "The Cisco router must be configured to back up the configuration when changes occur." | Out-String
        $FindingDetails += "Backup configuration has either been detected as incorrectly configured or is absent. See details below and verify or configure correct backup procedures." | Out-String
        $FindingDetails += "-------------------- Detected Configurations --------------------" | Out-String
        $FindingDetails += $eventManager | Out-String
        ForEach ($line in $eventManagerConfig) {
            $FindingDetails += $line.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "-------------------- Required Configurations Example --------------------" | Out-String
        ForEach ($line in $backup) {
            $FindingDetails += $line | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    else {
        $FindingDetails += "Backup procedure detected." | Out-String
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

Function Get-V215711 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215711
        STIG ID    : CISC-ND-001440
        Rule ID    : SV-215711r991834_rule
        CCI ID     : CCI-001159, CCI-004909
        Rule Name  : SRG-APP-000516-NDM-000344
        Rule Title : The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
        DiscussMD5 : 9C58869D9EF19C95CCBDB63FF5DF7345
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
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Status = "Not_Reviewed"
    $OpenFinding = $False

    IF ($ShowRunningConfig -like "crypto pki trustpoint *") {
        if ($ShowRunningConfig -like "*enrollment url *") {
            $Status = "NotAFinding"
        }
        else {
            $OpenFinding = $True
        }
    }
    else {
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Not_Reviewed"
        $FindingDetails += "The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider. Configure the router via the commands 'crypto pki trustpoint *' and 'enrollment url *' to obtain its public key certificates from an appropriate certificate policy through an approved service provider." | Out-String
        $FindingDetails += "Note: This requirement is not applicable if the router does not have any public key certificates." | Out-String
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

Function Get-V220136 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220136
        STIG ID    : CISC-ND-001450
        Rule ID    : SV-220136r961863_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000516-NDM-000350
        Rule Title : The Cisco router must be configured to send log data to at least two syslog servers for the purpose of forwarding alerts to the administrators and the ISSO.
        DiscussMD5 : 2B60B499490110C0A7C4C1920395BB82
        CheckMD5   : 1B706946007EACAC4CDE4EEC9EEAC465
        FixMD5     : 3D524978B5C106205E088234187B0A44
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
    # Get syslog servers configuration.
    $SyslogServers = $ShowRunningConfig | Select-String -Pattern "^logging host"
    # Get number of syslog servers configured.
    $NumberOfServers = ($SyslogServers | Measure-Object -Line).Lines

    IF ($NumberOfServers -gt 1) {
        $Status = "NotAFinding"
        $FindingDetails += "There are $NumberOfServers Syslog Servers configured." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $Status = "Open"
        IF ($NumberOfServers -eq 1) {
            $FindingDetails += "There is $NumberOfServers Syslog Servers configured. This device must be configured to send log data to at least two Syslog Servers for the purpose of forwarding alerts to the administrators and the ISSO." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "There aren't Syslog Server configured. This device must be configured to send log data to at least two Syslog Servers for the purpose of forwarding alerts to the administrators and the ISSO." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V220137 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220137
        STIG ID    : CISC-ND-001470
        Rule ID    : SV-220137r961863_rule
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
    # Get show version
    $ShowVersion = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version

    # Get device SW version
    IF ($ShowVersion) {
        $SWVersion = (($ShowVersion | Select-String -Pattern "^ROM:").ToString().Split([char[]]"") | Select-Object -Index 4) -replace ".$"
        # Add SW version details to FindingDetails
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify if release: Version $SWVersion is still supported by Cisco Systems and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "All releases supported by Cisco Systems can be found on the following URL: https://www.cisco.com/c/en/us/support/all-products.html" | Out-String
        $FindingDetails += "" | Out-String
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

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBFMwDgBmLW737Y
# FVwZY/589uwTmWKzi0HlDcyngGxwKaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCCSyBRgGhCS4bAtLe7QxhVFwTHCJOb8YPRHenyOLmAgnDANBgkqhkiG9w0BAQEF
# AASCAQASz5SseClcXqiLaqheos3p45u/jACzk3OLi39iA3gCa7AAHQpz3vB8rHhG
# lp5wQbfvjcL4nsUuT6ONs051RV5mgXye8ev/3feF8TFhSP8J9pM47ZsX8+nmPu1t
# eH88prQH0b+iZ9WGUBVuV7dgEPeqlj2Z7XDgGF+UR9WinWfsbmoSkSISnv3UNcRV
# qtcqlrKYPwcKYkxhxDtN/DhZfiTaho03B66SdoFcf59aETIqY+1yPsLBVq0t2Kmt
# POQo9HgBO6A6fP3fVoaOhqdBEwEE2Yk5oCwq1Ja+hQQXlAXMCjZmIzWzeLG1QyPm
# uNgAZK/NuNMDEkVuF688MMjQXAhxoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTAxMVowLwYJKoZIhvcNAQkEMSIEILTaDzo+PYzKC1ir1hM3kEn1gk1g
# 5yWADgEaF0aHDLXBMA0GCSqGSIb3DQEBAQUABIICAHT2dkykHoPfT9rH8TfG3KY0
# skJL8H7Hc81PKh8bioGS508oGLREZcGyRA2oioWK91ggkSvhaS0HhNuIPnQnrCmU
# jURcotScks1EhooWfQ6jojqMHv7RWpXEkfc/VHbsjncAQTi4Eg45M22+CWyq4OTv
# RKBvVl6vv8PoP0TO7LPsWmatuef8esVUYcTK1+OrqUkXW+4o2Qeguk7eXARJBXog
# bUO3ZRl76jOCLq1vP5U5iJ5hYmElYU+m9ceGTsViZasAMCNf8v+11YGTAIcIMHuq
# MH0XDMRyHpq8IGac9PPbb/6cMI2muH/16X4FghshNLa42zlHa7+3T9QBeWdtlahb
# YEQcbqN0Jhd79NR1jvv+I2jVGLG/7TxP7mGdEhv+7zllTCC8jeGl91AEpldI1Abm
# fXV5DXG+lH5TlA1W1mgaQ7NhYlo4D2p7d1oR9eh3GXDiKFDprknz3FdTYrtRdkJB
# bt8981xBvyAUWuZvKWgdIPpeu9E4+e+tqxsXb5X1LEP2Q03Bjp/F97dAZLr6fQv+
# YACOUtTX+yieiqg4smIs7BrSbgdtJVLnm1Yp86vlCFPDNLNQzdF130osCTBn4AI/
# MSG2Ui0NcefGETZGHiR1UdaVHn4tUzQy+DM7AwEyBgPxX8oM/CkWtoMtqkfe/PNx
# VhIIp03EGq3yt4Qy5Jj0
# SIG # End signature block
