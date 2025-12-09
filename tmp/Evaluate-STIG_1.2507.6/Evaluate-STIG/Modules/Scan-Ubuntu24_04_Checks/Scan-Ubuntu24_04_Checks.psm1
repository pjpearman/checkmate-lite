##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Canonical Ubuntu 24.04 LTS
# Version:  V1R2
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Daniel Frye
##########################################################################
$ErrorActionPreference = "Stop"

#requires -version 7.1

Function CheckPermissions {
    Param(
        [Parameter (Mandatory = $true)]
        [string]$FindPath,

        [Parameter (Mandatory = $false)]
        [ValidateSet("File", "Directory")]
        [string]$Type,

        [Parameter (Mandatory = $true)]
        [int]$MinPerms,

        [Parameter (Mandatory = $false)]
        [switch]$Recurse
    )

    $ValidPerms = $(find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")

    if ($Type -eq "File"){
        $ValidPerms = $(find $FindPath -maxdepth 1 -not -path '*/.*' -not -type l -type f -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
    }
    elseif ($Type -eq "Directory"){
        $ValidPerms = $(find $FindPath -maxdepth 0 -not -path '*/.*' -not -type l -type d -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
    }

    if ($Recurse){
        if ($Type -eq "File"){
            $ValidPerms = $(find $FindPath -xdev -not -path '*/.*' -not -type l -type f -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
        elseif ($Type -eq "Directory"){
            $ValidPerms = $(find $FindPath -xdev -not -path '*/.*' -not -type l -type d -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
        else{
            $ValidPerms = $(find $FindPath -xdev -not -path '*/.*' -not -type l -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
    }

    if ($ValidPerms -eq "" -or $null -eq $ValidPerms){
        Return $True
    }
    else{
        Return $ValidPerms
    }
}

Function FormatFinding {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        $finding
    )

    # insert separator line between $FindingMessage and $finding
    $BarLine = '------------------------------------------------------------------------'
    $FormattedFinding = $BarLine | Out-String

    # building a string to properly format new lines bewtween findings and each bar line when argument is an array
    $joiner = '' | Out-String | Out-String
    $joiner += $BarLine | Out-String

    # if $finding is an array, '-join' will combine the items in the array together into a String with the bar and new line seperators
    # if $finding is not an array, this will simple set $combined_finding to the value of $finding
    $combined_finding = $finding -join $joiner

    # insert findings
    $FormattedFinding += $combined_finding | Out-String

    return $FormattedFinding
}

Function Get-V270645 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270645
        STIG ID    : UBTU-24-100010
        Rule ID    : SV-270645r1068357_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must not have the "systemd-timesyncd" package installed.
        DiscussMD5 : E9B43BE149F6F88FBDDA95464231D017
        CheckMD5   : B57111E96032D973EC33AC88C81C0DD0
        FixMD5     : F74F258978F1BD86547E0CA272263365
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
    $finding = $(dpkg -l | grep -s systemd-timesyncd)

    if (($finding | awk '{print $2}') -eq "systemd-timesyncd") {
        $Status = "Open"
        $FindingMessage = "Ubuntu 24.04 LTS has the 'systemd-timesyncd' package installed."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "Ubuntu 24.04 LTS does not have the 'systemd-timesyncd' package installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270646 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270646
        STIG ID    : UBTU-24-100020
        Rule ID    : SV-270646r1068358_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must not have the "ntp" package installed.
        DiscussMD5 : E9B43BE149F6F88FBDDA95464231D017
        CheckMD5   : 0F75C319E8E52EA2F7A3416F5CCF052E
        FixMD5     : 08E2CACB3B4FD4DE2E0F8215E251FA91
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
    $finding = $(dpkg -l | grep -s ntp)

    if (($finding | awk '{print $2}') -eq "ntp") {
        $Status = "Open"
        $FindingMessage = "Ubuntu 24.04 LTS has the 'ntp' package installed."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "Ubuntu 24.04 LTS does not have the 'ntp' package installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270647 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270647
        STIG ID    : UBTU-24-100030
        Rule ID    : SV-270647r1066430_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-OS-000074-GPOS-00042
        Rule Title : Ubuntu 24.04 LTS must not have the telnet package installed.
        DiscussMD5 : F8C9B138D97A89226BFE2D5DB3677348
        CheckMD5   : E143AE4865352BF1F706ECC135381E0E
        FixMD5     : F62D3124166A09F35C791FC423513424
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
    $finding = $(dpkg -l | grep -s telnetd)

    if (($finding | awk '{print $2}') -eq "telnetd") {
        $Status = "Open"
        $FindingMessage = "Ubuntu 22.04 LTS has the 'telnetd' package installed."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "Ubuntu 22.04 LTS does not have the 'telnetd' package installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270648 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270648
        STIG ID    : UBTU-24-100040
        Rule ID    : SV-270648r1066433_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : Ubuntu 24.04 LTS must not have the rsh-server package installed.
        DiscussMD5 : 0BE30828767E22FE73AC64F8728FED8C
        CheckMD5   : 8DDC444B55853DE2591AE3896BFF525B
        FixMD5     : 897E52C94CFCD246D0C593F66CFCD18A
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
    $finding = $(dpkg -l | grep -s rsh-server)

    if (($finding | awk '{print $2}') -eq "rsh-server") {
        $Status = "Open"
        $FindingMessage = "Ubuntu 22.04 LTS has the 'rsh-server' package installed."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "Ubuntu 22.04 LTS does not have the 'rsh-server' package installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270649 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270649
        STIG ID    : UBTU-24-100100
        Rule ID    : SV-270649r1067136_rule
        CCI ID     : CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : Ubuntu 24.04 LTS must use a file integrity tool to verify correct operation of all security functions.
        DiscussMD5 : D6179A650A723C87D9C34FF77244E790
        CheckMD5   : 6C80672CCC5CFE8230EAE44BE1D73CB2
        FixMD5     : EF377A339CC3E096D700DA948938E150
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
    $finding = $(dpkg -l | grep -s aide)

    if (($finding | awk '{print $2}') -eq "aide") {
        $Status = "NotAFinding"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions."
    }
    else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed. Ask the System Administrator how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270650 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270650
        STIG ID    : UBTU-24-100110
        Rule ID    : SV-270650r1066439_rule
        CCI ID     : CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : Ubuntu 24.04 LTS must configure AIDE to preform file integrity checking on the file system.
        DiscussMD5 : D6179A650A723C87D9C34FF77244E790
        CheckMD5   : 071A1214DDF60B2977FE580AC3914CCF
        FixMD5     : F4BC51321C053D9A04BA9924DE43F4C9
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
    $finding = $(dpkg -l | grep -s aide)

    if (($finding | awk '{print $2}') -eq "aide") {
        $finding = $(aide -c /etc/aide/aide.conf --check)

        if ($finding -eq "Couldn't open file /var/lib/aide/aide.db for reading"){
            $Status = "Open"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed but has not been initialized."
        }
        else{
            $Status = "NotAFinding"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions."
        }
    }
    else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed. Ask the System Administrator how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270652 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270652
        STIG ID    : UBTU-24-100130
        Rule ID    : SV-270652r1067138_rule
        CCI ID     : CCI-001744, CCI-002702
        Rule Name  : SRG-OS-000447-GPOS-00201
        Rule Title : Ubuntu 24.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator (SA) when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
        DiscussMD5 : F62C031E9297F235D2D7AECC4AECCADF
        CheckMD5   : 911EFF01EAF94651AC4D30491C4024D4
        FixMD5     : 994FAB30FAF190FA092F5DAB4CE38146
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
    $finding = $(grep -s -i ^[[:blank:]]*SILENTREPORTS /etc/default/aide)

    if ($finding){
        if ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]).ToLower() -eq "no") {
            $Status = "NotAFinding"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) notifies the system administrator when anomalies in the operation of any security functions are discovered."
        }
        else {
            $Status = "Open"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) does not notify the system administrator when anomalies in the operation of any security functions are discovered."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) does not notify the system administrator when anomalies in the operation of any security functions are discovered."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270653 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270653
        STIG ID    : UBTU-24-100200
        Rule ID    : SV-270653r1067141_rule
        CCI ID     : CCI-001665
        Rule Name  : SRG-OS-000269-GPOS-00103
        Rule Title : Ubuntu 24.04 LTS must be configured to preserve log records from failure events.
        DiscussMD5 : 91819B56744A0B92292AD2DE6CAE3E8C
        CheckMD5   : D76DF0AC1DF58526DD8586A198F59B15
        FixMD5     : 5D625E66731AE828EA1BFBCF176E4EA4
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
    $finding = $(dpkg -l | grep -s rsyslog)
    $finding_2 = ""
    $finding_3 = ""

    if (($finding | awk '{print $2}') -eq "rsyslog") {
        $FindingMessage = "The log service is installed properly"
        $finding_2 = $(systemctl is-enabled rsyslog)
        if ($finding_2 -eq "enabled") {
            $FindingMessage += "`r`n"
            $FindingMessage += "The log service is enabled."
            $finding_3 = $(systemctl is-active rsyslog)
            if ($finding_3 -eq "active") {
                $Status = "NotAFinding"
                $FindingMessage += "`r`n"
                $FindingMessage += "The log service is properly running and active on the system."
            }
            else {
                $Status = "Open"
                $FindingMessage += "`r`n"
                $FindingMessage += "The log service is not properly running and active on the system."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage += "`r`n"
            $FindingMessage += "The log service is not enabled."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The rsyslog package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270654 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270654
        STIG ID    : UBTU-24-100300
        Rule ID    : SV-270654r1067143_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-OS-000297-GPOS-00115
        Rule Title : Ubuntu 24.04 LTS must have an application firewall installed in order to control remote access methods.
        DiscussMD5 : 8F32443935E173FBE702CFCFDF319926
        CheckMD5   : B49220CDEC04499E6B85C46F634641E6
        FixMD5     : 3EA67F2035520FB93C4C096D141AE2B4
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
    $finding = $(dpkg -l | grep -s ufw)

    if (($finding | awk '{print $2}') -eq "ufw") {
        $Status = "NotAFinding"
        $FindingMessage = "The Uncomplicated Firewall is installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Uncomplicated Firewall is not installed."
        $FindingMessage += "`r`n"
        $FindingMessage += "The 'ufw' package is not installed.  Is another application firewall is installed?"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270655 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270655
        STIG ID    : UBTU-24-100310
        Rule ID    : SV-270655r1067145_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-OS-000297-GPOS-00115
        Rule Title : Ubuntu 24.04 LTS must enable and run the Uncomplicated Firewall (ufw).
        DiscussMD5 : 79DB4F7D674CCB12C8CCA31F7E4621D8
        CheckMD5   : F4CFB689450F7A558458759A4202FBE0
        FixMD5     : 1D8A811CC5C3BDE932D93B5AAF555A3B
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
    $finding = $(ufw status)

    if ($finding -match "Status: active") {
        $Status = "NotAFinding"
        $FindingMessage = "The Uncomplicated Firewall is enabled."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Uncomplicated Firewall is inactive."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270656 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270656
        STIG ID    : UBTU-24-100400
        Rule ID    : SV-270656r1067148_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000154, CCI-000158, CCI-000169, CCI-000172, CCI-001875, CCI-001876, CCI-001877, CCI-001878, CCI-001879, CCI-001880, CCI-001881, CCI-001882, CCI-001914, CCI-003938
        Rule Name  : SRG-OS-000365-GPOS-00152
        Rule Title : Ubuntu 24.04 LTS must have the "auditd" package installed.
        DiscussMD5 : D766A39338D2320DAA45F66912955D24
        CheckMD5   : 4695F57BF1F97A047CD64CE11C664205
        FixMD5     : D34B16F777E61076AC24AAE51F50531D
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
    $finding = $(dpkg -l | grep -s auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the 'auditd' package installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'auditd' package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270657 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270657
        STIG ID    : UBTU-24-100410
        Rule ID    : SV-270657r1066460_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000154, CCI-000158, CCI-000169, CCI-000172, CCI-001875, CCI-001876, CCI-001877, CCI-001878, CCI-001879, CCI-001880, CCI-001881, CCI-001882, CCI-001914, CCI-003938
        Rule Name  : SRG-OS-000365-GPOS-00152
        Rule Title : Ubuntu 24.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time.
        DiscussMD5 : D766A39338D2320DAA45F66912955D24
        CheckMD5   : AED97ABC9B4A93C5478A83CB4B899809
        FixMD5     : D128CB529413EDE7407C97AB55868104
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
    $finding = $(dpkg -l auditd)
    $finding_2 = ""
    $finding_3 = ""

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding_2 = $(systemctl is-enabled auditd.service)
        if ($finding_2 -eq "enabled") {
            $finding_3 = $(systemctl is-active auditd.service)
            if ($finding_3 -eq "active") {
                $Status = "NotAFinding"
                $FindingMessage = "The audit service is configured to produce audit records."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The audit service is not active."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit service is not enabled."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270658 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270658
        STIG ID    : UBTU-24-100450
        Rule ID    : SV-270658r1067151_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : Ubuntu 24.04 LTS audit event multiplexor must be configured to offload audit logs onto a different system or storage media from the system being audited.
        DiscussMD5 : F4EFC0921D72594CF68294CED987F684
        CheckMD5   : F7407709B5A9F7619642829F7EA98D77
        FixMD5     : 72E7B598F3943223F9D0AC182B3454CC
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
    $finding = $(dpkg -l | grep -s audispd-plugins)

    if (($finding | awk '{print $2}') -eq "audispd-plugins") {
        $finding = $(grep -s -i active /etc/audisp/plugins.d/au-remote.conf)

        if ($finding -eq "active = yes") {
            $finding_2 = $(grep -s -i ^[[:blank:]]*remote_server /etc/audit/audisp-remote.conf)

            if ($finding_2){
                $status = "Not_Reviewed"
                $FindingMessage = "The audit logs are offloaded to a different system or storage media.  IP Address must be validated."
            }
            else{
                $Status = "Open"
                $FindingMessage = "The audisp-remote plugin is not configured to send audit logs to a different system."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The records are not being offloaded to a remote server."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Status is 'not installed', verify that another method to off-load audit logs has been implemented."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270659 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270659
        STIG ID    : UBTU-24-100500
        Rule ID    : SV-270659r1066466_rule
        CCI ID     : CCI-001764, CCI-001774, CCI-002165
        Rule Name  : SRG-OS-000312-GPOS-00124
        Rule Title : Ubuntu 24.04 LTS must have AppArmor installed.
        DiscussMD5 : 13A0ADFC0F7A99544899C4355F8082D0
        CheckMD5   : A73CB518747B24B3E7B0B03BBB69DA8D
        FixMD5     : FF47BA126F8A36B6DF031B6A5542BB2E
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
    $finding = $(dpkg -l | grep -s apparmor)

    if (($finding | awk '{print $2}') -eq "apparmor") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the 'apparmor' package installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'apparmor' package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270660 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270660
        STIG ID    : UBTU-24-100510
        Rule ID    : SV-270660r1066469_rule
        CCI ID     : CCI-001764, CCI-001774, CCI-002235
        Rule Name  : SRG-OS-000368-GPOS-00154
        Rule Title : Ubuntu 24.04 LTS must be configured to use AppArmor.
        DiscussMD5 : 4181DB2CE14066C9B29B39CF5A4B6759
        CheckMD5   : 97B4B781A7E278DD86A50C41F2814021
        FixMD5     : 37529844891AFF55D7728668ACEB83B4
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
    $finding = $(dpkg -l | grep -s -i apparmor)
    $finding_2 = ""
    $finding_3 = ""

    if (($finding | awk '{print $2}') -match "apparmor") {
        $finding_2 = $(systemctl is-active apparmor.service)
        if ($finding_2 -eq "active") {
            $finding_3 = $(systemctl is-enabled apparmor.service)
            if ($finding_3 -eq "enabled") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system prevents program execution in accordance with local policies."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not prevent program execution in accordance with local policies."
                $FindingMessage += "`r`n"
                $FindingMessage += "Apparmor.service is not enabled."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not prevent program execution in accordance with local policies."
            $FindingMessage += "`r`n"
            $FindingMessage += "Apparmor.service is not active."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent program execution in accordance with local policies."
        $FindingMessage += "`r`n"
        $FindingMessage += "AppArmor is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270661 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270661
        STIG ID    : UBTU-24-100600
        Rule ID    : SV-270661r1067175_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00225
        Rule Title : Ubuntu 24.04 LTS must have the "libpam-pwquality" package installed.
        DiscussMD5 : 4AF4C1E3A5017E0922F67CCAEF89849A
        CheckMD5   : D73C73FF0500FE9D1EAC97D6F348BFBF
        FixMD5     : 4F0051104C8FCD9D8E7E22E8E4F82CAD
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
    $finding = $(dpkg -l | grep -s libpam-pwquality)

    if (($finding | awk '{print $2}') -match "libpam-pwquality") {
        $Status = "NotAFinding"
        $FindingMessage = "Ubuntu 24.04 LTS has the 'libpam-pwquality' package installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Ubuntu 24.04 LTS does not have the 'libpam-pwquality' package installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270662 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270662
        STIG ID    : UBTU-24-100650
        Rule ID    : SV-270662r1067156_rule
        CCI ID     : CCI-000765, CCI-000766, CCI-004046, CCI-004047
        Rule Name  : SRG-OS-000705-GPOS-00150
        Rule Title : Ubuntu 24.04 LTS must have the "SSSD" package installed.
        DiscussMD5 : 61B6A5ADAFFA700D1013ED028622AB64
        CheckMD5   : 4FB5CF6A4B30CAF8F2D631C334D60CBC
        FixMD5     : 639A4EB5449C99C9D7C3FAF61B1DDC53
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
    $finding = $(dpkg -l | grep -s sssd)
    $finding_2 = $(dpkg -l | grep -s libpam-sss)
    $finding_3 = $(dpkg -l | grep -s libnss-sss)

    if ((($finding | awk '{print $2}') -match "^sssd$") -and (($finding_2 | awk '{print $2}') -match "^libpam-sss") -and (($finding_3 | awk '{print $2}') -match "^libnss-sss")){
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the 'sssd', 'libpam-sss', and 'libnss-sss' packages installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'sssd', 'libpam-sss', or 'libnss-sss' packages installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270663 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270663
        STIG ID    : UBTU-24-100660
        Rule ID    : SV-270663r1066478_rule
        CCI ID     : CCI-000765, CCI-000766, CCI-004046, CCI-004047
        Rule Name  : SRG-OS-000705-GPOS-00150
        Rule Title : Ubuntu 24.04 LTS must use the "SSSD" package for multifactor authentication services.
        DiscussMD5 : 61B6A5ADAFFA700D1013ED028622AB64
        CheckMD5   : 5B8AFDF7FD85840FB10954B927B04065
        FixMD5     : E19C24353CA48CAC34B427AF4FF60152
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
    $finding = $(dpkg -l | grep -s sssd)
    $finding_2 = ""

    if (($finding | awk '{print $2}').contains("sssd")) {
        $finding_2 = $(systemctl is-active sssd)
        if ($finding_2 -eq "active") {
            $finding_3 = $(systemctl is-enabled sssd)
            if ($finding_3 -eq "enabled") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system uses the 'SSSD' package for multifactor authentication services."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not use the 'SSSD' package for multifactor authentication services."
                $FindingMessage += "`r`n"
                $FindingMessage += "sssd.service is not enabled."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not use the 'SSSD' package for multifactor authentication services."
            $FindingMessage += "`r`n"
            $FindingMessage += "sssd.service is not active."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The sssd package is not installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270664 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270664
        STIG ID    : UBTU-24-100700
        Rule ID    : SV-270664r1068359_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must have the "chrony" package installed.
        DiscussMD5 : E9B43BE149F6F88FBDDA95464231D017
        CheckMD5   : ACBDD41CC4F60B4233D3356DF16DE69D
        FixMD5     : 21F571A27F7467EE747142799F5C58AE
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
    $finding = $(dpkg -l | grep -s chrony)

    if (($finding | awk '{print $2}') -eq "chrony") {
        $Status = "NotAFinding"
        $FindingMessage = "Ubuntu 24.04 LTS has the 'chrony' package installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Ubuntu 24.04 LTS does not have the 'chrony' package installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270665 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270665
        STIG ID    : UBTU-24-100800
        Rule ID    : SV-270665r1067133_rule
        CCI ID     : CCI-002418, CCI-002420, CCI-002422
        Rule Name  : SRG-OS-000423-GPOS-00187
        Rule Title : Ubuntu 24.04 LTS must have SSH installed.
        DiscussMD5 : 7CE7587484A0E3FC6C9BDEB296764BEC
        CheckMD5   : 2C17A6DF9E9BA8B14DAD7F980D4ED3CB
        FixMD5     : 8B9DCC09BB2F0B64948758E676B5A455
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
    $finding = $(dpkg -l | grep -s openssh)

    if (($finding | awk '{print $2}').contains("openssh-server")) {
        $Status = "NotAFinding"
        $FindingMessage = "The ssh package is installed and the 'sshd.service' is loaded and active."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The ssh package is not installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270666 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270666
        STIG ID    : UBTU-24-100810
        Rule ID    : SV-270666r1066487_rule
        CCI ID     : CCI-002418, CCI-002420, CCI-002422
        Rule Name  : SRG-OS-000423-GPOS-00187
        Rule Title : Ubuntu 24.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.
        DiscussMD5 : 7CE7587484A0E3FC6C9BDEB296764BEC
        CheckMD5   : A6A45C37942570902AEAA94F7E7C0FF9
        FixMD5     : F203C378ADC3374E098750A549612612
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
    $finding = $(dpkg -l | grep -s openssh)
    $finding_2 = ""

    if (($finding | awk '{print $2}').contains("openssh-server")) {
        $finding_2 = $(systemctl is-active ssh)
        if ($finding_2 -eq "active") {
            $finding_3 = $(systemctl is-enabled ssh)
            if ($finding_3 -eq "enabled") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system protects the confidentiality and integrity of transmitted information."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not protect the confidentiality and integrity of transmitted information."
                $FindingMessage += "`r`n"
                $FindingMessage += "ssh.service is not enabled."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not protect the confidentiality and integrity of transmitted information."
            $FindingMessage += "`r`n"
            $FindingMessage += "ssh.service is not active."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The ssh package is not installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270667 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270667
        STIG ID    : UBTU-24-100820
        Rule ID    : SV-270667r1067107_rule
        CCI ID     : CCI-000068, CCI-002421, CCI-003123
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : Ubuntu 24.04 LTS must configure the SSH daemon to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
        DiscussMD5 : 876BDB20B54E1D108D70CA727C67B7B5
        CheckMD5   : C8ED3914035F2CD4D8C72721785B4CB3
        FixMD5     : CD59F3620E6723450E0843099523ABA8
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
    $finding = $(grep -s -i ^[[:blank:]]*ciphers /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $correct_message_count = 0

    $Ciphers = @("aes256-gcm@openssh.com","aes128-gcm@openssh.com","aes256-ctr","aes128-ctr")

    if ($finding){
        $finding | ForEach-Object {
            $cipher_count = 0
            Foreach ($Cipher in $Ciphers){
                if ($_ -match $Cipher){
                    $cipher_count++
                }
            }

            if ($cipher_count -eq $Ciphers.count){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system configures the SSH daemon to only use FIPS-approved ciphers."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system configures the SSH daemon but does not use FIPS-approved ciphers."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system configures the SSH daemon but does not use FIPS-approved ciphers."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270668 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270668
        STIG ID    : UBTU-24-100830
        Rule ID    : SV-270668r1067110_rule
        CCI ID     : CCI-001453, CCI-002421, CCI-002890
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
        DiscussMD5 : F4A660D075C4ADC96B1CDF8F5E0B3152
        CheckMD5   : 9D8C2CA573F6454C63C5932399CDA2C0
        FixMD5     : EB82AB379C67F24FCAB5F531C54239AA
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
    $finding = $(grep -s -i ^[[:blank:]]*macs /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $correct_message_count = 0

    $Macs = @("hmac-sha2-512","hmac-sha2-512-etm@openssh.com","hmac-sha2-256","hmac-sha2-256-etm@openssh.com")

    if ($finding){
        $finding | ForEach-Object {
            $mac_count = 0
            Foreach ($Mac in $Macs){
                if ($_ -match $Mac){
                    $mac_count++
                }
            }

            if ($mac_count -eq $Macs.count){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system configures the SSH daemon to only use Message Authentication Codes (MACs) that employ FIPS approved ciphers."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system configures the SSH daemon but does not use Message Authentication Codes (MACs) that employ FIPS approved ciphers."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system configures the SSH daemon but does not use Message Authentication Codes (MACs) that employ FIPS approved ciphers."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270669 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270669
        STIG ID    : UBTU-24-100840
        Rule ID    : SV-270669r1067112_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : Ubuntu 24.04 LTS SSH server must be configured to use only FIPS 140-3 validated key exchange algorithms.
        DiscussMD5 : 21A3EA07F8F337CE08FFE4E82DD4BBBD
        CheckMD5   : 9DE44BD6A1CF82D12CEA7A472699849D
        FixMD5     : DDA097076A02F5DB1F817E7093289BA7
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
    $finding = $(grep -s -i ^[[:blank:]]*kexalgorithms /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $correct_message_count = 0

    $Kexalgorithms = @("ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256")

    if ($Finding){
        $finding | ForEach-Object {
            $kexalgorithm_count = 0
            Foreach ($Kexalgorithm in $Kexalgorithms){
                if ($_ -match $Kexalgorithm){
                    $kexalgorithm_count++
                }
            }

            if ($kexalgorithm_count -eq $Kexalgorithms.count){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH server is configured to use only FIPS-validated key exchange algorithms."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The SSH server is not configured to use only FIPS-validated key exchange algorithms."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The SSH server is not configured to use only FIPS-validated key exchange algorithms."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270670 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270670
        STIG ID    : UBTU-24-100850
        Rule ID    : SV-270670r1067115_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Ubuntu 24.04 LTS must configure the SSH client to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
        DiscussMD5 : 7C83B55EB6B1006DE4D2DA43B0318C72
        CheckMD5   : 744CC72EF5722053B12E0585D34A29B6
        FixMD5     : FEBC769BC4397926AE938E740851EF54
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
    $finding = $(grep -s -i ^[[:blank:]]*ciphers /etc/ssh/ssh_config /etc/ssh/ssh_config.d/*)
    $correct_message_count = 0

    $Ciphers = @("aes256-gcm@openssh.com","aes128-gcm@openssh.com","aes256-ctr","aes128-ctr")

    if ($finding){
        $finding | ForEach-Object {
            $cipher_count = 0
            Foreach ($Cipher in $Ciphers){
                if ($_ -match $Cipher){
                    $cipher_count++
                }
            }

            if ($cipher_count -eq $Ciphers.count){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system configures the SSH client to only use FIPS-approved ciphers."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system configures the SSH client but does not use FIPS-approved ciphers."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system configures the SSH client but does not use FIPS-approved ciphers."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270671 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270671
        STIG ID    : UBTU-24-100860
        Rule ID    : SV-270671r1067118_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Ubuntu 24.04 LTS SSH client must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms.
        DiscussMD5 : D26CCD429D5F3D3F1E10B5FC88409961
        CheckMD5   : C0781B6BA64E50136223B9682CBF32B3
        FixMD5     : 0D5A87210CFE713734EA8C91F89E0EB5
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
    $finding = $(grep -s -i ^[[:blank:]]*macs /etc/ssh/ssh_config /etc/ssh/ssh_config.d/*)
    $correct_message_count = 0

    $Macs = @("hmac-sha2-512","hmac-sha2-512-etm@openssh.com","hmac-sha2-256","hmac-sha2-256-etm@openssh.com")

    if ($finding){
        $finding | ForEach-Object {
            $mac_count = 0
            Foreach ($Mac in $Macs){
                if ($_ -match $Mac){
                    $mac_count++
                }
            }

            if ($mac_count -eq $Macs.count){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system configures the SSH client to only use Message Authentication Codes (MACs) that employ FIPS approved ciphers."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system configures the SSH client but does not use Message Authentication Codes (MACs) that employ FIPS approved ciphers."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system configures the SSH client but does not use Message Authentication Codes (MACs) that employ FIPS approved ciphers."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270672 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270672
        STIG ID    : UBTU-24-100900
        Rule ID    : SV-270672r1067161_rule
        CCI ID     : CCI-001953
        Rule Name  : SRG-OS-000376-GPOS-00161
        Rule Title : Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials.
        DiscussMD5 : 2C9ECD5A3E383A7D3778F1FB8AF704B2
        CheckMD5   : 4883EEA629C63DF4995B5C20A8656C4E
        FixMD5     : D28D000E605A9CCE72EDC63C7A185719
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
    $finding = $(dpkg -l | grep -s opensc-pkcs11)

    if (($finding | awk '{print $2}') -match "opensc-pkcs11") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system accepts Personal Identity Verification (PIV) credentials."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not accept Personal Identity Verification (PIV) credentials."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270673 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270673
        STIG ID    : UBTU-24-100910
        Rule ID    : SV-270673r1067164_rule
        CCI ID     : CCI-001953
        Rule Name  : SRG-OS-000376-GPOS-00161
        Rule Title : Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials managed through the Privileged Access Management (PAM) framework.
        DiscussMD5 : 2C9ECD5A3E383A7D3778F1FB8AF704B2
        CheckMD5   : B90530DD78BC9AD0736F766107F21D3D
        FixMD5     : 9ACC8F19701ABA4D110A949A7BCCE98E
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
    $finding = $(dpkg -l | grep -s libpam-pkcs11)

    if (($finding | awk '{print $2}') -match "libpam-pkcs11") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the packages required for multifactor authentication installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the packages required for multifactor authentication installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270674 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270674
        STIG ID    : UBTU-24-101000
        Rule ID    : SV-270674r1067167_rule
        CCI ID     : CCI-000057, CCI-000060
        Rule Name  : SRG-OS-000031-GPOS-00012
        Rule Title : Ubuntu 24.04 LTS must allow users to directly initiate a session lock for all connection types.
        DiscussMD5 : 61C55D041C2C5B4F3DBA7844EF3346A1
        CheckMD5   : A5CD2B408D5673EEDD6081D3F210F1E4
        FixMD5     : 95DEE5C23F074D11A2C5C9F84D9EB13B
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
    $finding = $(dpkg -l | grep -s vlock)

    if (($finding | awk '{print $2}') -eq "vlock") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the 'vlock' package installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'vlock' package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270675 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270675
        STIG ID    : UBTU-24-102000
        Rule ID    : SV-270675r1066514_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Ubuntu 24.04 LTS when booted must require authentication upon booting into single-user and maintenance modes.
        DiscussMD5 : FB54911A0FFF71E4BC06F36B0F136841
        CheckMD5   : 071A6D0CDD76325C12BE217152DC795C
        FixMD5     : 84EE501A950080BB94247AEC63D5F4C4
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
    $finding = $(grep -I -s -iw ^[[:blank:]]*password_pbkdf2 /boot/grub/grub.cfg)

    If ($finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The root password entry does begin with 'password_pbkdf2'"
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The root password entry does not begin with 'password_pbkdf2'"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270676 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270676
        STIG ID    : UBTU-24-102010
        Rule ID    : SV-270676r1068360_rule
        CCI ID     : CCI-001464
        Rule Name  : SRG-OS-000254-GPOS-00095
        Rule Title : Ubuntu 24.04 LTS must initiate session audits at system startup.
        DiscussMD5 : 7B96DED03C72CEF7D7FFEEEA490EA6E0
        CheckMD5   : 6945D9DEA8133285B7D7F9905F5F6C9D
        FixMD5     : 297912500F34EBBCA0BC8C18FEEBCD25
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
    $finding = $(grep -s -i ^[[:blank:]]*linux[[:blank:]] /boot/grub/grub.cfg)
    $correct_message_count = 0

    $finding | ForEach-Object {
        If ($_ -match "audit=1") {
            $correct_message_count++
        }
    }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "All linux lines contain 'audit=1'"
    }
    else {
        $Status = "Open"
        $FindingMessage = "A linux line does not contain 'audit=1'"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270677 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270677
        STIG ID    : UBTU-24-200000
        Rule ID    : SV-270677r1101774_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-OS-000027-GPOS-00008
        Rule Title : Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types.
        DiscussMD5 : 8CDA433E2DCB75CC4D263EDA80B93301
        CheckMD5   : C11DA88C59005D8477F2244EE5E6E9E7
        FixMD5     : 39A82E45FA69C17936E31E9BCCB20916
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
    $finding = $(grep -I -s -r -v "^\s*#" /etc/security/limits.conf /etc/security/limits.d/*.conf | grep -I -s -i maxlogins)

    if ($finding){
        if ((($finding | awk '{$2=$2};1').split(":")[1]).split(" ")[-1] -le 10) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system limits the number of concurrent sessions to '10' for all accounts and/or account types."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not limit the number of concurrent sessions to '10' for all accounts and/or account types."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not limit the number of concurrent sessions to '10' for all accounts and/or account types."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270678 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270678
        STIG ID    : UBTU-24-200020
        Rule ID    : SV-270678r1101791_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : Ubuntu 24.04 LTS must initiate a graphical session lock after 10 minutes of inactivity.
        DiscussMD5 : 02A567D7681A83CC35E179997BDE6B29
        CheckMD5   : 51E3B3669746BCD9DBA0193F9D6C85CB
        FixMD5     : 359E3ADAA33D6A17723F7FA0BB4B99D3
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."

    if ($finding.Contains("gdm3")) {
        $finding = $(gsettings get org.gnome.desktop.screensaver lock-enabled)
        $finding ??= "Check text: No results found."
        $finding_2 = $(gsettings get org.gnome.desktop.screensaver lock-delay)
        $finding_3 = $(gsettings get org.gnome.desktop.session idle-delay)

        $lockenabled = $False
        $lockdelay = $False
        $idledelay = $False

        if ($finding -eq "true") {
            $lockenabled = $True
            $FindingMessage = "The Ubuntu operating system has a graphical user interface session lock enabled."
        }
        else {
            $FindingMessage = "The Ubuntu operating system does not have a graphical user interface session lock enabled."
        }
        $FindingMessage += "`r`n"
        if ($finding_2){
            if ([int](($finding_2 | awk '{$2=$2};1').split(" ")[1]) -le 0) {
                $lockdelay = $True
                $FindingMessage += "The Ubuntu operating system has a graphical user interface session lock delay."
            }
            else {
                $FindingMessage += "The Ubuntu operating system does not have a graphical user interface session lock delay."
            }
        }
        else{
            $FindingMessage += "The Ubuntu operating system does not have a graphical user interface session lock delay."
        }
        $FindingMessage += "`r`n"
        if ($finding_3){
            if ([int](($finding_3 | awk '{$2=$2};1').split(" ")[1]) -gt 600) {
                $idledelay = $True
                $FindingMessage += "The Ubuntu operating system has a graphical user interface session idle delay."
            }
            else {
                $FindingMessage += "The Ubuntu operating system does not have a graphical user interface session idle delay."
            }
        }
        else{
            $FindingMessage += "The Ubuntu operating system does not have a graphical user interface session idle delay."
        }

        if ($lockenabled -and $lockdelay -and $idledelay){
            $Status = "NotAFinding"
        }
        else{
            $Status = "Open"
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270679 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270679
        STIG ID    : UBTU-24-200040
        Rule ID    : SV-270679r1107295_rule
        CCI ID     : CCI-000056
        Rule Name  : SRG-OS-000028-GPOS-00009
        Rule Title : Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user interface automount function.
        DiscussMD5 : D9B132544ED138C8A0A16A1EC43E4335
        CheckMD5   : 215DA7FD2A54B61444836CE117A4A3E4
        FixMD5     : 21DE7A17E0185DDC7A6341B2B079552D
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."

    if ($finding.Contains("gdm3")) {
        $systemdb = $(grep -I -s system-db /etc/dconf/profile/user)
        $finding = $systemdb
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $setting = "automount-open"

        $systemdb | ForEach-Object {
            $finding = $(grep -I -s -iR $setting /etc/dconf/db/$($_.split(":")[1]).d/locks/)
            if (!($Finding)) { $Finding = "Check text did not return results for $($_.split(":")[1])." }

            If ($finding.split(":")[1]) {
                If (($finding.split(":")[1]) -eq "/org/gnome/desktop/media-handling/$setting") {
                    $found = $True
                }
            }

            $FindingDetails += $(FormatFinding $finding) | Out-String
        }

        If ($found) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system disables the ability of the user to override the graphical user interface automount setting."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not disable the ability of the user to override the graphical user interface automount setting."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }

    $FindingDetails = , $FindingMessage + $FindingDetails | Out-String
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

Function Get-V270680 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270680
        STIG ID    : UBTU-24-200060
        Rule ID    : SV-270680r1066529_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-OS-000279-GPOS-00109
        Rule Title : Ubuntu 24.04 LTS must automatically terminate a user session after inactivity timeouts have expired.
        DiscussMD5 : D69E0609223316C87B1B8AEF4374A3C4
        CheckMD5   : 2367EE37DC1F78EF6C33A3E41073818F
        FixMD5     : 4FEAEF26A63BD321A880BC18FF40B472
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
    $finding = $(grep -s -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*)
    $finding ??= "Check text: No results found."

    if (((($finding.ToUpper()).split(":")[1]).startswith("TMOUT")) -and (($finding | awk '{$2=$2};1').replace(" ", "").Split("=")[1] -ne 0)) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system initiates a session logout after greater than a 15-minute period of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not initiate a session logout."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270681 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270681
        STIG ID    : UBTU-24-200090
        Rule ID    : SV-270681r1066532_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000032-GPOS-00013
        Rule Title : Ubuntu 24.04 LTS must monitor remote access methods.
        DiscussMD5 : 42DB7B5A6C97E0F7B8C5936EBF150319
        CheckMD5   : 1989C46AEBC14DDA7FA83AF0D220D290
        FixMD5     : 9F0BD25AE84ABBEFDF285A5B4AF347AA
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
    $finding = $(grep -s -E -r '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*)

    if ($finding) {
        $better_finding_1 = $(grep -s -E -r '^(auth\.\*,authpriv\.\*)' /etc/rsyslog.* | awk '{$2=$2};1')
        if (!($better_finding_1)) { $better_finding_1 = "Check text: No results found." }
        else{
            $better_finding_1_path = ($better_finding_1).split(":")[0]
        }
        $better_finding_2 = $(grep -s -E -r '^daemon\.*' /etc/rsyslog.* | awk '{$2=$2};1')
        if (!($better_finding_2)) { $better_finding_2 = "Check text: No results found." }
        else {
            $better_finding_2_path = ($better_finding_2).split(":")[0]
        }
    }
    else {
        $Finding = "Check text: No results found."
    }

    if (($better_finding_1 -match "^$($better_finding_1_path):auth.*,authpriv.*\s+/var/log/secure$") -and ($better_finding_2 -match "^$($better_finding_2_path):daemon.*\s+/var/log/messages$")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system monitors all remote access methods."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not monitor all remote access methods."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270683 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270683
        STIG ID    : UBTU-24-200260
        Rule ID    : SV-270683r1066538_rule
        CCI ID     : CCI-003627, CCI-003628
        Rule Name  : SRG-OS-000118-GPOS-00060
        Rule Title : Ubuntu 24.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
        DiscussMD5 : 763A942F7F5988EF1D4107018EC53D82
        CheckMD5   : 18C470262884E47E9952B18479F23552
        FixMD5     : 324926185A041B5FADBD3920E9EC5C3F
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
    $finding = $(grep -s -i ^[[:blank:]]*INACTIVE /etc/default/useradd)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 35) {
        $Status = "NotAFinding"
        $FindingMessage = "The account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The account identifiers (individuals, groups, roles, and devices) are not disabled after 35 days of inactivity."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270684 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270684
        STIG ID    : UBTU-24-200280
        Rule ID    : SV-270684r1066541_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
        DiscussMD5 : 343143FFF8B4DBCBA83BA20F5E4901DF
        CheckMD5   : 47DA127AD417BAD1EE839E80DB35F61D
        FixMD5     : A1C451C4F62EED9EE7B966027ADFD943
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s passwd)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/passwd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270685 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270685
        STIG ID    : UBTU-24-200290
        Rule ID    : SV-270685r1066544_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
        DiscussMD5 : 343143FFF8B4DBCBA83BA20F5E4901DF
        CheckMD5   : 7977240A1276C6D3B816B5342AFC4F7B
        FixMD5     : 188AFF095FF128F78147D5FE756E7D9C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s group)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/group[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270686 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270686
        STIG ID    : UBTU-24-200300
        Rule ID    : SV-270686r1066547_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
        DiscussMD5 : 343143FFF8B4DBCBA83BA20F5E4901DF
        CheckMD5   : 582A8B1A800DF382F790AB4CD39BBFDA
        FixMD5     : D5D528D393FA820787200214E8412721
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s shadow)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/shadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270687 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270687
        STIG ID    : UBTU-24-200310
        Rule ID    : SV-270687r1066550_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
        DiscussMD5 : 343143FFF8B4DBCBA83BA20F5E4901DF
        CheckMD5   : D1BF508D7C68D97B3CB81A49C3A0CF52
        FixMD5     : D5F4C229DF7B51549CAB528C8021E209
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s gshadow)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/gshadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270688 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270688
        STIG ID    : UBTU-24-200320
        Rule ID    : SV-270688r1066553_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.
        DiscussMD5 : F879220E4643EF36114FAF866FC6A6A8
        CheckMD5   : 01884CDC3AA5382EE372E3E68060AB73
        FixMD5     : 60B7AF2A2265940EA1577591E109EC9D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s opasswd)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/security\/opasswd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270689 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270689
        STIG ID    : UBTU-24-200580
        Rule ID    : SV-270689r1066556_rule
        CCI ID     : CCI-002233, CCI-002234, CCI-004188
        Rule Name  : SRG-OS-000326-GPOS-00126
        Rule Title : Ubuntu 24.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.
        DiscussMD5 : 02CCD66987B3478E5E2F145C5E7BC9B0
        CheckMD5   : F04F120B2907225721C490A39D67BE58
        FixMD5     : 439D28B642800A0508F872384CFE9541
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w execve)
        $finding ??= "Check text: No results found."

        $not_commented = 0
        $line = 0
        ($finding | grep -s -i " execve ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " execve ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if ((($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b32[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+uid!=euid[\s]+)(?:-F[\s]+euid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+uid!=euid[\s]+)(?:-F[\s]+euid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and
                (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b32[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+gid!=egid[\s]+)(?:-F[\s]+egid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+gid!=egid[\s]+)(?:-F[\s]+egid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$')) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'execve' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'execve' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'execve' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270690 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270690
        STIG ID    : UBTU-24-200610
        Rule ID    : SV-270690r1067126_rule
        CCI ID     : CCI-000044, CCI-002238
        Rule Name  : SRG-OS-000021-GPOS-00005
        Rule Title : Ubuntu 24.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.
        DiscussMD5 : 97535DE64FF5CF25F542274BC33565A9
        CheckMD5   : BFDD1B8CD4C85CE3E984F9E5256F87C1
        FixMD5     : 87FDEE3D90C7B2F9C451BDE0EF30F66A
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
    $finding = $(grep -s -i faillock /etc/pam.d/common-auth)
    $silent = $false
    $deny = $false
    $audit = $false
    $fail_interval = $false
    $unlock_time = $false

    if ($finding){
        $finding_2 = $(egrep -s -i 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf | grep -v "^#")
        $finding_2 ??= "Check text: No results found."

        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "silent"){
            if ((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "silent").StartsWith("silent")){
                $silent = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "audit"){
            if ((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "audit").StartsWith("audit")){
                $audit = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "deny="){
            if (((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "deny=").StartsWith("deny")) -and ([int]((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "deny=").split("=")[1]) -le 3)){
                $deny = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "fail_interval="){
            if (((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "fail_interval=").StartsWith("fail_interval")) -and ([int]((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "fail_interval=").split("=")[1]) -le 900)){
                $fail_interval = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "unlock_time="){
            if (((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "unlock_time=").StartsWith("unlock_time")) -and ([int]((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "unlock_time=").split("=")[1]) -eq 0)){
                $unlock_time = $true
            }
        }

        if ($silent -and $deny -and $audit -and $fail_interval -and $unlock_time){
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system utilizes the 'pam_faillock' module and is configured with the correct options."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system utilizes the 'pam_faillock' module but is not configured with the correct options."
        }

    }
    else{
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not utilize the 'pam_faillock' module."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270691 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270691
        STIG ID    : UBTU-24-200640
        Rule ID    : SV-270691r1066562_rule
        CCI ID     : CCI-000048, CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting access to via an SSH logon.
        DiscussMD5 : C2BAF2A0190754B1B5468F9E5ED4A083
        CheckMD5   : D084744855B4AB21ED8B99F1C9CA9EAB
        FixMD5     : A9C2F16CE231A86A8B9FFE25E3B0A2C8
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
    $finding = $(grep -s -i ^[[:blank:]]*banner /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding_2 = ""

    if ($finding){
        $correct_message_count = 0
        $finding | Foreach-Object {
            $banner_path = ($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1]
            $finding_2 = $(cat $banner_path)

            if ((($finding_2 | awk '{$2=$2};1').replace("\n", "") | tr -d '[:space:]"') -eq "YouareaccessingaU.S.Government(USG)InformationSystem(IS)thatisprovidedforUSG-authorizeduseonly.ByusingthisIS(whichincludesanydeviceattachedtothisIS),youconsenttothefollowingconditions:-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct(PM),lawenforcement(LE),andcounterintelligence(CI)investigations.-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.-ThisISincludessecuritymeasures(e.g.,authenticationandaccesscontrols)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.") {
                $correct_message_count++
            }
        }
        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270692 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270692
        STIG ID    : UBTU-24-200650
        Rule ID    : SV-270692r1066565_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : Ubuntu 24.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
        DiscussMD5 : B755CA03E863B1D89A183E9311CC0F5B
        CheckMD5   : ABB3373082CDBE78BF946A15DB09A919
        FixMD5     : 617BB90364E0F42AD3FFDD59ED7963F9
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."
    $finding_2 = ""

    if ($finding.Contains("gdm3")) {
        $finding_2 = $(grep -s -i ^[[:blank:]]*banner-message-enable /etc/gdm3/greeter.dconf-defaults)
        if ($finding_2 = "banner-message-enable=true") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system displays banner text before granting local access to the system via a graphical user logon."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not display banner text before granting local access to the system via a graphical user logon."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270693 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270693
        STIG ID    : UBTU-24-200660
        Rule ID    : SV-270693r1066568_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
        DiscussMD5 : B755CA03E863B1D89A183E9311CC0F5B
        CheckMD5   : BBBB2608E0252BA8DB2D35D7006445A6
        FixMD5     : CE5B5309762BA1E75CE7884BAF69108F
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."
    $finding_2 = ""

    if ($finding.Contains("gdm3")) {
        $finding_2 = $(grep -s -i ^[[:blank:]]*banner-message-text /etc/gdm3/greeter.dconf-defaults)
        $finding_2 ??= "Check text: No results found."

        if ((($finding_2 | awk '{$2=$2};1').replace("\n", "").replace('"',"'") | tr -d '[:space:]"') -eq "banner-message-text='YouareaccessingaU.S.Government\(USG\)InformationSystem\(IS\)thatisprovidedforUSG-authorizeduseonly.ByusingthisIS\(whichincludesanydeviceattachedtothisIS\),youconsenttothefollowingconditions:-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct\(PM\),lawenforcement\(LE\),andcounterintelligence\(CI\)investigations.-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.-ThisISincludessecuritymeasures\(e.g.,authenticationandaccesscontrols\)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.'") {
            $Status = "NotAFinding"
            $FindingMessage += "The operating system displays the exact approved Standard Mandatory DoD Notice and Consent Banner text."
        }
        else {
            $Status = "Open"
            $FindingMessage += "The operating system does not display the exact approved Standard Mandatory DoD Notice and Consent Banner text."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270695 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270695
        STIG ID    : UBTU-24-300001
        Rule ID    : SV-270695r1066574_rule
        CCI ID     : CCI-003992
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : Ubuntu 24.04 LTS Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu 24.04 LTS components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
        DiscussMD5 : B3778E7342BE017EFEEBA7D20E9F295B
        CheckMD5   : 4C307DB2D71B9008A669E2F54A1F6729
        FixMD5     : 58DEA4C63DE1BEBA2B8668CFAFAD636A
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
    $finding = $(grep -s -i ^[[:blank:]]*AllowUnauthenticated /etc/apt/apt.conf.d/*)
    $finding ??= "Check text: No results found."
    $incorrect_message_count = 0

    $finding | ForEach-Object { if ($_.Contains('APT::Get::AllowUnauthenticated "true"')) {
            $incorrect_message_count++
        } }
    if ($incorrect_message_count -gt 0) {
        $Status = "Open"
        $FindingMessage = "At least one of the files returned from the command with 'AllowUnauthenticated' set to 'true'"
        $FindingMessage += "`r`n"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'AllowUnauthenticated' variable is not set at all or set to 'false'"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270696 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270696
        STIG ID    : UBTU-24-300006
        Rule ID    : SV-270696r1107306_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS library files must have mode 0755 or less permissive.
        DiscussMD5 : EE56CADC84DD3CEF4241A4FC20706BA3
        CheckMD5   : 190EE303AE5767FD21596A9DB73C1414
        FixMD5     : 48954B210C7A7E346AF0520687E708DF
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
    $command = @'
#!/bin/sh

find /lib /lib64 /usr/lib /usr/lib64 -xdev -perm /022 -type f -exec stat -c "%n %a" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $finding | ForEach-Object {
        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library files in '/lib', '/lib64', '/usr/lib', and '/usr/lib64' have mode '0755' or less permissive."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library files in '/lib', '/lib64', '/usr/lib', and '/usr/lib64' do not have mode '0755' or less permissive."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) do not have their permissions set to 755 or more."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270697 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270697
        STIG ID    : UBTU-24-300007
        Rule ID    : SV-270697r1107308_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS library files must be owned by root.
        DiscussMD5 : EE56CADC84DD3CEF4241A4FC20706BA3
        CheckMD5   : 20B2AF2066D4A374E5DA53CB7D33AC7E
        FixMD5     : 684B73E2126EE0396FB9727179DEA139
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 /usr/lib64 -xdev ! -user root -type f -exec stat -c "%n %U" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are not owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270698 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270698
        STIG ID    : UBTU-24-300008
        Rule ID    : SV-270698r1101751_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS library directories must be owned by root.
        DiscussMD5 : EE56CADC84DD3CEF4241A4FC20706BA3
        CheckMD5   : 2F0FE2A07F9ABD654351E883D3763CEA
        FixMD5     : E3108A8139BD5C5A76D7A4E4FEBF4610
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 /usr/lib64 -xdev ! -user root -type d -exec stat -c "%n %U" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are not owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270699 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270699
        STIG ID    : UBTU-24-300009
        Rule ID    : SV-270699r1107310_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS library files must be group-owned by root or a system account.
        DiscussMD5 : EE56CADC84DD3CEF4241A4FC20706BA3
        CheckMD5   : AE3BAFDF39CE9DBD47FD86370E092DAE
        FixMD5     : F1632F6CA4CD50640702A105E50AFB3B
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 /usr/lib64 -xdev ! -group root -type f -exec stat -c "%n %G" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide library files contained in the directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are not group-owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide library files contained in the directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are group-owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270700 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270700
        STIG ID    : UBTU-24-300010
        Rule ID    : SV-270700r1066589_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS library directories must be group-owned by root.
        DiscussMD5 : EE56CADC84DD3CEF4241A4FC20706BA3
        CheckMD5   : C50E0BDC3C9683C33530D66FE54F7CCB
        FixMD5     : 91675EDAA86B4E9544917DBB737630B2
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 -xdev ! -group root -type d -exec stat -c "%n %G" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide library directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are not group-owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide library directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' are group-owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270701 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270701
        STIG ID    : UBTU-24-300011
        Rule ID    : SV-270701r1066592_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS must have system commands set to a mode of 0755 or less permissive.
        DiscussMD5 : 945DEB655E2C8F02E60BBA9B57453BEA
        CheckMD5   : 69BBB13FB5177603A8A21C7003570FA6
        FixMD5     : E130FE7F21DE9452E4DC92D005DBEEA1
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
    $command = @'
#!/bin/sh

find /lib /lib64 /usr/lib -xdev -perm /022 -type f -exec stat -c "%n %a" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $finding | ForEach-Object {
        if (($_ | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' have mode '0755' or less permissive."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64', '/usr/lib', and '/usr/lib64' do not have mode '0755' or less permissive."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) do not have their permissions set to 755 or more."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270702 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270702
        STIG ID    : UBTU-24-300012
        Rule ID    : SV-270702r1066595_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS must have system commands owned by root or a system account.
        DiscussMD5 : 945DEB655E2C8F02E60BBA9B57453BEA
        CheckMD5   : 5AB32ADBA675B6AB5AEDBEBCAEBFE19A
        FixMD5     : 210985B82BCDE3E9DFD1C0FC13F6D90A
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev ! -user root -type f -exec stat -c "%n %U" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270703 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270703
        STIG ID    : UBTU-24-300013
        Rule ID    : SV-270703r1066598_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Ubuntu 24.04 LTS must have system commands group-owned by root or a system account.
        DiscussMD5 : 945DEB655E2C8F02E60BBA9B57453BEA
        CheckMD5   : FF15703140329CEBBD6C956F6745E0E3
        FixMD5     : 123C5154B80A8D2D7893806785D2E687
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev ! -group root -type f -exec stat -c "%n %G" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not group-owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are group-owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270704 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270704
        STIG ID    : UBTU-24-300014
        Rule ID    : SV-270704r1066601_rule
        CCI ID     : CCI-004061
        Rule Name  : SRG-OS-000710-GPOS-00160
        Rule Title : Ubuntu 24.04 LTS must prevent the use of dictionary words for passwords.
        DiscussMD5 : 6E73C54903676AAC76FE7578E85FBBE9
        CheckMD5   : 7E67C1BA95FD1191CA8E7B1B69A7044E
        FixMD5     : 39D7353DB3F2DA97F2C82FAB490C7424
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
    $finding = $(grep -s -i ^[[:blank:]]*dictcheck /etc/security/pwquality.conf)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system uses the cracklib library to prevent the use of dictionary words."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not use the cracklib library to prevent the use of dictionary words."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270705 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270705
        STIG ID    : UBTU-24-300016
        Rule ID    : SV-270705r1066604_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00225
        Rule Title : Ubuntu 24.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
        DiscussMD5 : 4AF4C1E3A5017E0922F67CCAEF89849A
        CheckMD5   : D85C6680766651869BA265CBC6BD415A
        FixMD5     : 11F89C81579655F6089BA439417990FC
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
    $finding = $(dpkg -l libpam-pwquality)
    $finding_2 = ""
    $finding_3 = ""

    if ($finding -match "libpam-pwquality") {
        $finding_2 = $(grep -s -i enforcing /etc/security/pwquality.conf)
        $finding_2 ??= "Check text: No results found."

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "enforcing=1") {
            $finding_3 = $(cat /etc/pam.d/common-password | grep -s requisite | grep -s pam_pwquality)
            $finding_3 ??= "Check text: No results found."

            if ((($finding_3 | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "retry" }).split("=")[1] -in 1..3) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system has the libpam-pwquality package installed and is configured correctly."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system has the libpam-pwquality package installed and enforced but is not configured correctly."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system has the libpam-pwquality package installed but is not being enforced."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the libpam-pwquality package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270706 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270706
        STIG ID    : UBTU-24-300017
        Rule ID    : SV-270706r1068361_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00226
        Rule Title : Ubuntu 24.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.
        DiscussMD5 : 37BC02AC5DCCE6AF3A064B94C99B1A7E
        CheckMD5   : DE83DEFDC8D8666810E99FF620F38065
        FixMD5     : 0FB270C1D99548B5B955E210A70D888D
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
    $finding = $(grep -i -s pam_faildelay /etc/pam.d/common-auth | grep -v "^#")

    if (($finding | awk '{$2=$2};1') -match "auth required pam_faildelay.so delay=") {
        if ([int]($finding.split("=")[1]) -ge 4000000) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system enforces a delay of at least 4 seconds between logon prompts."
        }
        else {
            $Status = "Open"
            $FindingMessage += "`r`n"
            $FindingMessage += "the Ubuntu operating system enforces a delay of less than 4 seconds between logon prompts following a failed logon attempt."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce a delay between logon prompts following a failed logon attempt."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270707 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270707
        STIG ID    : UBTU-24-300021
        Rule ID    : SV-270707r1101786_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.
        DiscussMD5 : 9250217E6AC4A35A4738F2A328AD51E7
        CheckMD5   : CE408C1E058EAA5FAAFF395BB2ABAB54
        FixMD5     : 462E4AE4CAA16025829703514DE55B51
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
    $finding = $(grep -I -s -iR !authenticate /etc/sudoers /etc/sudoers.d/)
    $commented = 0

    If ($finding) {
        $finding | ForEach-Object {
            If ($_.StartsWith("#")) {
                $commented++
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires users to reauthenticate for privilege escalation."
    }

    if ($finding.count -ne $commented) {
        $Status = "Open"
        $FindingMessage = "The operating system does not require users to reauthenticate for privilege escalation."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires users to reauthenticate for privilege escalation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270708 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270708
        STIG ID    : UBTU-24-300022
        Rule ID    : SV-270708r1066613_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.
        DiscussMD5 : 87A706DE32538425BCB6A069DA89D63F
        CheckMD5   : 99618D26BAD26DC66AEB9EE5ECB2651D
        FixMD5     : 026731B354C0571783D7C893A9ED4F3D
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
    $finding = $(dpkg -l | grep -s openssh)

    if (!($finding | awk '{print $2}').contains("openssh-server")) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The ssh package is not installed to validate check per Check Text."
    }
    else {
        $finding = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH ^[[:blank:]]*x11forwarding)
        $finding ??= "Check text: No results found."
        $correct_message_count = 0

        $finding | ForEach-Object {
            if (((($_.split(":")[1] | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "no"){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "X11Forwarding is disabled."
        }
        else {
            $Status = "Open"
            $FindingMessage = "X11Forwarding is not disabled."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270709 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270709
        STIG ID    : UBTU-24-300023
        Rule ID    : SV-270709r1066616_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.
        DiscussMD5 : 42EF94ABF769BB918502DBBDEEBE36AA
        CheckMD5   : 18E00FDD0DEE3796EF668A2796B5F53D
        FixMD5     : 3A687B626CC535CD665683B3EF685D44
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
    $finding = $(dpkg -l | grep -s openssh)

    if (!($finding | awk '{print $2}').contains("openssh-server")) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The ssh package is not installed to validate check per Check Text."
    }
    else {
        $finding = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH ^[[:blank:]]*x11uselocalhost)
        $finding ??= "Check text: No results found."
        $correct_message_count = 0

        $finding | ForEach-Object {
            if (((($_ | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "yes"){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH daemon prevents remote hosts from connecting to the proxy display."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The SSH daemon does not prevent remote hosts from connecting to the proxy display."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270710 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270710
        STIG ID    : UBTU-24-300024
        Rule ID    : SV-270710r1066619_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must display the date and time of the last successful account logon upon logon.
        DiscussMD5 : 2581E9F2E9188407ED2680DE35E92ADC
        CheckMD5   : 0BD98FB8C547B7112AFAB8267BC3CEFF
        FixMD5     : 56FCAE82E80021DEE9B923C4CA9FD7DC
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
    $finding = $(grep -i -s pam_lastlog /etc/pam.d/login | grep -v "#")

    if ($finding) {
        if ($finding -notmatch "silent" -and $finding -match "required") {
            $Status = "NotAFinding"
            $FindingMessage = "Users are provided with feedback on when account accesses last occurred."
        }
        else {
            $Status = "Open"
            $FindingMessage = "Users are not provided with feedback on when account accesses last occurred."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "Users are not provided with feedback on when account accesses last occurred."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270711 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270711
        STIG ID    : UBTU-24-300025
        Rule ID    : SV-270711r1101772_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
        DiscussMD5 : 61C10053D406013548766BA3039950D9
        CheckMD5   : 4570B79DC33BCA45597DAFAF9A4AFB0D
        FixMD5     : 68A8CCBC86BC59E864239A8D99B9DEA0
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."

    if ($finding.Contains("gdm3")) {
        $finding = $(gsettings get org.gnome.settings-daemon.plugins.media-keys logout)

        if ($finding) {
            if ($finding -eq "['']") {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
            $FindingMessage += "The 'logout' key is missing."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270712 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270712
        STIG ID    : UBTU-24-300026
        Rule ID    : SV-270712r1068363_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.
        DiscussMD5 : B088CF73E7DF2FDD87FC791E99F74F73
        CheckMD5   : EC6729842B0119916850CA28A1D116CC
        FixMD5     : 251E44FDB92AE2770209980BF1E7F641
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
    $finding = $(systemctl status ctrl-alt-del.target)

    If ($finding -match "Unit ctrl-alt-del.target is masked") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed."
        $FindingMessage += "`r'`n"
        $FindingMessage += "The 'ctrl-alt-del.target' is active."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270713 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270713
        STIG ID    : UBTU-24-300027
        Rule ID    : SV-270713r1066628_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords.
        DiscussMD5 : 178C558CD4D9B6C646CC32A3B2BCD188
        CheckMD5   : BA187F3EFC24B9453BB30EC4713EF741
        FixMD5     : EEBCB041C7386989DB5A766FB2AAF96D
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
    $finding = $(awk -F: '!$2 {print $1}' /etc/shadow)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The '/etc/shadow' file contains account(s) with blank passwords."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/shadow' file does not contain account(s) with blank passwords."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270714 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270714
        STIG ID    : UBTU-24-300028
        Rule ID    : SV-270714r1067119_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must not allow accounts configured in Pluggable Authentication Modules (PAM) with blank or null passwords.
        DiscussMD5 : 178C558CD4D9B6C646CC32A3B2BCD188
        CheckMD5   : 8ABC5E057F9BEFD8F24762E8E32CC584
        FixMD5     : 397F7FEF5D51EBC810F6B39D3D1EDB89
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
    $finding = $(grep -s nullok /etc/pam.d/common_password)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "Null passwords can be used."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "Null passwords cannot be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270715 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270715
        STIG ID    : UBTU-24-300029
        Rule ID    : SV-270715r1066634_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must generate audit records for all events that affect the systemd journal files.
        DiscussMD5 : 969B89C2FAB3C54DBA579DC839788502
        CheckMD5   : A57657611CDC39B3834276990D43767B
        FixMD5     : 2C9B41E17469D5FFB5A4899B8739F5DC
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s journal)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/journal[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system audits all events that affect '/var/log/journal'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system audits all events that affect '/var/log/journal'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270716 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270716
        STIG ID    : UBTU-24-300030
        Rule ID    : SV-270716r1066637_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00228
        Rule Title : Ubuntu 24.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.
        DiscussMD5 : C6C79138B0EDB9B72967285655877C24
        CheckMD5   : 539A767EDF94ADC17028755923485DB6
        FixMD5     : 6E5632C0DBAB58C09DD394869097D7BF
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
    $finding = $(grep -s -i ^[[:blank:]]*umask /etc/login.defs)
    $finding ??= "Check text: No results found."

    if ((($finding | awk '{$2=$2};1').split(" ")[1] -eq "077")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
        if ((($finding | awk '{$2=$2};1').split(" ")[1] -eq "000")) {
            $SeverityOverride = "CAT_I"
            $Justification = "The 'UMASK' variable is set to '000, therefore this is a finding with the severity raised to a CAT I."
            $FindingMessage += "`r`n"
            $FindingMessage += $Justification
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270717 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270717
        STIG ID    : UBTU-24-300031
        Rule ID    : SV-270717r1067177_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH.
        DiscussMD5 : A9484A74FB0EC17D34E20B328944F429
        CheckMD5   : E663F17F679ABCCB9DE692A1523E9CF3
        FixMD5     : 0522F71F33743ACE141DA6664BE60875
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
    $finding = $(dpkg -l | grep -s openssh)

    if (!($finding | awk '{print $2}').contains("openssh-server")) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The ssh package is not installed to validate check per Check Text."
    }
    else {
        $finding = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iEH ^[[:blank:]]*'(permit(.*?)(passwords|environment))')
        $PE_correct_message = $false
        $PU_correct_message = $false

        if ($finding) {
            $PermitEmpty = $($finding | Select-String -Pattern "PermitEmptyPasswords" -Raw)
            $PermitUser = $($finding | Select-String -Pattern "PermitUserEnvironment" -Raw)

            $correct_message_count = 0
            if ($PermitEmpty) {
                $PermitEmpty | ForEach-Object { if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1].ToLower() -eq "no") {
                    $correct_message_count++
                } }
                if ($correct_message_count -eq $PermitEmpty.count) {
                        $PE_correct_message = $true
                }
            }
            $correct_message_count = 0
            if ($PermitUser) {
                $PermitUser | ForEach-Object { if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1].ToLower() -eq "no") {
                    $correct_message_count++
                } }
                if ($correct_message_count -eq $PermitUser.count) {
                    $PU_correct_message = $true
                }
            }

            if (($PE_correct_message) -and ($PU_correct_message)) {
                $Status = "NotAFinding"
                $FindingMessage = "Unattended or automatic login via ssh is disabled."
            }
            else {
                $Status = "Open"
                $FindingMessage = "Unattended or automatic login via ssh is not disabled."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "Unattended or automatic login via ssh is not disabled."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270718 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270718
        STIG ID    : UBTU-24-300039
        Rule ID    : SV-270718r1067128_rule
        CCI ID     : CCI-001958, CCI-003959
        Rule Name  : SRG-OS-000690-GPOS-00140
        Rule Title : Ubuntu 24.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.
        DiscussMD5 : 3F69A8243FBA2EF1F14FEAD805F1DAA4
        CheckMD5   : 419CFF7858450B510B177A61C8947AB0
        FixMD5     : 16FB7DFB0D4F4A5C7C9D1B735150823B
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
    $finding = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -i usb-storage | grep -s -i "/bin/false")
    $installusbs = $false

    if ($finding){
        If (((($Finding.ToLower()).split(":")[1]).startswith("install")) -and (((($Finding | awk '{$2=$2};1').ToLower()).split(":")[1]) -eq "install usb-storage /bin/false")){
            $installusbs = $true
            $FindingMessage = "The Ubuntu operating system disables ability to load the USB storage kernel module and disables the ability to use USB mass storage device."
        }
        else{
            $FindingMessage = "The Ubuntu operating system does not disable the ability to load the USB storage kernel module and disables the ability to use USB mass storage device."
        }
    }
    else{
        $Finding = "Check text: No results found."
    }

    $FindingMessage += "`r`n"

    $finding_2 = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -ih usb-storage | grep -s -i "blacklist ")
    $blacklistusbs = $false

    if ($Finding_2){
        If (((($Finding_2 | awk '{$2=$2};1').ToLower()).split(":"))[1] -match "blacklist usb-storage"){
            $blacklistusbs = $True
            $FindingMessage += "The Ubuntu operating system disables USB mass storage."
        }
        else{
            $FindingMessage += "The Ubuntu operating system does not disable USB mass storage."
        }
    }
    else{
        $Finding_2 = "Check text: No results found."
    }

    if ($installusbs -and $blacklistusbs){
        $Status = "NotAFinding"
    }
    else{
        $Status = "Open"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270720 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270720
        STIG ID    : UBTU-24-400000
        Rule ID    : SV-270720r1066649_rule
        CCI ID     : CCI-000764, CCI-000804
        Rule Name  : SRG-OS-000104-GPOS-00051
        Rule Title : Ubuntu 24.04 LTS must uniquely identify interactive users.
        DiscussMD5 : EFB690A038309DB3C3A5A289672D9FF4
        CheckMD5   : 3A67304314A94F1C24D6BD9F866531BA
        FixMD5     : 00F89260B0EE246E7628E599E2FE5377
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
    $finding = $(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd)

    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The Ubuntu operating system may contains duplicate User IDs (UIDs) for interactive users."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system contains no duplicate User IDs (UIDs) for interactive users."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270721 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270721
        STIG ID    : UBTU-24-400020
        Rule ID    : SV-270721r1066652_rule
        CCI ID     : CCI-000765, CCI-000766
        Rule Name  : SRG-OS-000105-GPOS-00052
        Rule Title : Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.
        DiscussMD5 : 1B68DE1CEE98B2F986C1007CC4D13F3B
        CheckMD5   : FA463B611C98D01D1CAC20A7EFF0FD14
        FixMD5     : 25FFCAF312369F8297E8D1D039635DC6
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
    $finding = $(dpkg -l | grep -s libpam-pkcs11)

    if (($finding | awk '{print $2}') -match "libpam-pkcs11") {
        $finding = $(grep -s -i pam_pkcs11.so /etc/pam.d/common-auth | grep -v "#")
        if ($finding){
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system implements smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270722 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270722
        STIG ID    : UBTU-24-400030
        Rule ID    : SV-270722r1067130_rule
        CCI ID     : CCI-000765, CCI-000766
        Rule Name  : SRG-OS-000105-GPOS-00052
        Rule Title : Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts over SSH.
        DiscussMD5 : 1B68DE1CEE98B2F986C1007CC4D13F3B
        CheckMD5   : C596BAD1B7639F5CDC4FD0A118A0E2FE
        FixMD5     : B0429934C46C3EE04F900A1418CE8F94
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
    $finding = $(dpkg -l | grep -s libpam-pkcs11)

    if (($finding | awk '{print $2}') -match "libpam-pkcs11") {
        $finding = $(dpkg -l | grep -s openssh)

        if (($finding | awk '{print $2}').contains("openssh-server")) {
            $Status = "Not_Reviewed"
            $FindingMessage = "The ssh package is not installed to validate check per Check Text."
        }
        else {
            $finding_2 = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH ^[[:blank:]]*pubkeyauthentication)
            $finding_2 ??= "Check text: No results found."
            $correct_message_count = 0

            $finding_2 | ForEach-Object { if ((($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes"){
                $correct_message_count++
            } }
            if ($correct_message_count -eq $finding_2.count) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system has the packages required for multifactor authentication installed and public key authentication is configured."
            }
            else{
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system has the packages required for multifactor authentication installed, but public key authentication is not configured."
            }
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the packages required for multifactor authentication installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270723 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270723
        STIG ID    : UBTU-24-400060
        Rule ID    : SV-270723r1066658_rule
        CCI ID     : CCI-001954
        Rule Name  : SRG-OS-000377-GPOS-00162
        Rule Title : Ubuntu 24.04 LTS must electronically verify Personal Identity Verification (PIV) credentials.
        DiscussMD5 : 2C9ECD5A3E383A7D3778F1FB8AF704B2
        CheckMD5   : 6B1031D3B3FCB7BDC5CDC59E07BF8053
        FixMD5     : 57B543065CD3F6BB4A4746FEA43F5C69
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
    $finding = $(grep -s use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep -s cert_policy | grep -s ocsp_on)
    $finding ??= "Check text: No results found."

    if ((($Finding.Trim().ToLower()).StartsWith("cert_policy")) -and (($finding.ToLower()).contains("ocsp_on"))) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system implements certificate status checking for multifactor authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not implement certificate status checking for multifactor authentication."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270724 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270724
        STIG ID    : UBTU-24-400110
        Rule ID    : SV-270724r1066661_rule
        CCI ID     : CCI-004045
        Rule Name  : SRG-OS-000109-GPOS-00056
        Rule Title : Ubuntu 24.04 LTS must prevent direct login to the root account.
        DiscussMD5 : 4E9DE03F514B72FDCC0F5C3164E40AC3
        CheckMD5   : 0024F318AF9DEE661E4D5946C6666464
        FixMD5     : 5FC692BDF03B540742904DACB8E17175
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
    $finding = $(passwd -S root)

    if (($finding | awk '{print $2}') -eq "L") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system prevents direct logins to the root account."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not prevent direct logins to the root account."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270725 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270725
        STIG ID    : UBTU-24-400220
        Rule ID    : SV-270725r1101789_rule
        CCI ID     : CCI-004062
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : Ubuntu 24.04 LTS must store only encrypted representations of passwords.
        DiscussMD5 : C6168053D628B3449EEE454F08ADAE9A
        CheckMD5   : 703D60DAB7CA45E210FB3580E1174323
        FixMD5     : 7F9F0C73289C5FB01A8F707377AAD212
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
    $finding = $(grep -s -i pam_unix.so /etc/pam.d/common-password)
    $finding ??= "Check text: No results found."

    if (($finding.ToLower().StartsWith("password")) -and ($finding.ToLower() -match "sha512") -and [int](((($finding | awk '{$2=$2};1').split(" ")) | Where-Object {$_ -match "rounds"}).split("=")[1]) -ge 100000) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system stores only encrypted representations of passwords."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not store only encrypted representations of passwords."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270726 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270726
        STIG ID    : UBTU-24-400260
        Rule ID    : SV-270726r1066667_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one uppercase character be used.
        DiscussMD5 : 1906B1F167DD07676D72F578F5D26C45
        CheckMD5   : E9F284205C6BC479B3BCFB50BB8D3F18
        FixMD5     : 8E1C95BBB34252030B8820A7658E7D7E
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
    $finding = $(grep -s -i ^[[:blank:]]*ucredit /etc/security/pwquality.conf)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one upper-case character be used."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one upper-case character be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270727 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270727
        STIG ID    : UBTU-24-400270
        Rule ID    : SV-270727r1066670_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000070-GPOS-00038
        Rule Title : Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one lowercase character be used.
        DiscussMD5 : B266E8F10D0F0F4B0108B5A4F72DDF7F
        CheckMD5   : 97FB73655AF107285A4EE468DF8DAEDA
        FixMD5     : 7155EA167B1389EEDBE1257314460889
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
    $finding = $(grep -s -i ^[[:blank:]]*lcredit /etc/security/pwquality.conf)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one lower-case character be used."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one lower-case character be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270728 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270728
        STIG ID    : UBTU-24-400280
        Rule ID    : SV-270728r1066673_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000071-GPOS-00039
        Rule Title : Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one numeric character be used.
        DiscussMD5 : 91666C0FEF653C3450D455C7DC328DDC
        CheckMD5   : 301AB0ED17C54CE1A1784D815C9E8441
        FixMD5     : C1ADC6E7288E9EB93D36B21325810C8E
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
    $finding = $(grep -s -i ^[[:blank:]]*dcredit /etc/security/pwquality.conf)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one numeric character be used."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one numeric character be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270729 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270729
        STIG ID    : UBTU-24-400290
        Rule ID    : SV-270729r1066676_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : Ubuntu 24.04 LTS must require the change of at least eight characters when passwords are changed.
        DiscussMD5 : DE8198C7E616B24859BA1DB3E9A1003F
        CheckMD5   : E9BE2030C51653741A543B32C0738511
        FixMD5     : F03C91EA7E0DDDF0B7A52DB78E83A909
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
    $finding = $(grep -s -i ^[[:blank:]]*difok /etc/security/pwquality.conf)
    $finding ??= "Check text: No results found."

    if ([int](($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]).replace('"','') -ge 8) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system requires the change of at least 8 characters when passwords are changed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not require the change of at least 8 characters when passwords are changed.."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270730 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270730
        STIG ID    : UBTU-24-400300
        Rule ID    : SV-270730r1066679_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000075-GPOS-00043
        Rule Title : Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.
        DiscussMD5 : 2E6757EF467805CE924AEA21469664BB
        CheckMD5   : 126E2896567C1567482CCD36EE23ED05
        FixMD5     : 7E3F5A8A4773000574DB53EEC5261B3C
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
    $finding = $(grep -s -i ^[[:blank:]]*pass_min_days /etc/login.defs)
    $finding ??= "Check text: No results found."

    if ([int](($finding | awk '{$2=$2};1').Split(" ")[1]).replace('"','') -ge 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces a 24 hours/1 day minimum password lifetime for new user accounts."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce a 24 hours/1 day minimum password lifetime for new user accounts."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270731 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270731
        STIG ID    : UBTU-24-400310
        Rule ID    : SV-270731r1066682_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000076-GPOS-00044
        Rule Title : Ubuntu 24.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
        DiscussMD5 : 5AAE45DA4B08704C730EAE3757F5735E
        CheckMD5   : EB747BD5A95DBE69F72442D1E52A8769
        FixMD5     : D18FD33ABC400DB641021239F8C38F03
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
    $finding = $(grep -s -i ^[[:blank:]]*pass_max_days /etc/login.defs)
    $finding ??= "Check text: No results found."

    if ([int](($finding | awk '{$2=$2};1').Split(" ")[1]).replace('"','') -ge 60) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces a 60-day maximum password lifetime for new user accounts."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce a 60-day maximum password lifetime for new user accounts."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270732 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270732
        STIG ID    : UBTU-24-400320
        Rule ID    : SV-270732r1066685_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000078-GPOS-00046
        Rule Title : Ubuntu 24.04 LTS must enforce a minimum 15-character password length.
        DiscussMD5 : 7E5BD9D936FA74B1B735ED6C5C9FB7AA
        CheckMD5   : F950A95FCD4DF80DD6A39ABC27F85074
        FixMD5     : 7239DF31AC0155CDCFEE89C05AD23129
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
    $finding = $(grep -s -i ^[[:blank:]]*minlen /etc/security/pwquality.conf)
    $finding ??= "Check text: No results found."

    if ([int](($finding | awk '{$2=$2};1').replace(" ", "").Split("=")[1]).replace('"','') -ge 15) {
        $Status = "NotAFinding"
        $FindingMessage = "The pwquality configuration file enforces a minimum 15-character password length."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The pwquality configuration file does not enforce a minimum 15-character password length."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270733 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270733
        STIG ID    : UBTU-24-400330
        Rule ID    : SV-270733r1066688_rule
        CCI ID     : CCI-004065, CCI-004066
        Rule Name  : SRG-OS-000266-GPOS-00101
        Rule Title : Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one special character be used.
        DiscussMD5 : 6401914A53846EED634C0494051B3759
        CheckMD5   : 681F25974C022D2FE0061DEC2F82EFF2
        FixMD5     : 3461CAEFD671AB3D20BC6140403F7936
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
    $finding = $(grep -s -i ^[[:blank:]]*ocredit /etc/security/pwquality.conf)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The field 'ocredit' is set in the '/etc/security/pwquality.conf'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The field 'ocredit' is not set in the '/etc/security/pwquality.conf'."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270734 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270734
        STIG ID    : UBTU-24-400340
        Rule ID    : SV-270734r1066691_rule
        CCI ID     : CCI-002007
        Rule Name  : SRG-OS-000383-GPOS-00166
        Rule Title : Ubuntu 24.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.
        DiscussMD5 : CC1503EB4AC6C661B16A41A973BC66E1
        CheckMD5   : E9D0B46BDF57C557AECFB98CCE6F93D1
        FixMD5     : 1F1B4B10FC7C2C407AA7DCCD812DE138
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
    $finding = $(grep -s -i ^[[:blank:]]*offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf)
    $finding ??= "Check text: No results found."

    if ($Finding -match "/etc/sssd/conf.d"){$finding = $Finding.split(":")[1]}

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=") -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "PAM prohibits the use of cached authentications after one day."
    }
    else {
        $Status = "Open"
        $FindingMessage = "PAM does not prohibit the use of cached authentications after one day."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270735 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270735
        STIG ID    : UBTU-24-400360
        Rule ID    : SV-270735r1066694_rule
        CCI ID     : CCI-000185, CCI-004909
        Rule Name  : SRG-OS-000066-GPOS-00034
        Rule Title : Ubuntu 24.04 LTS, for PKI-based authentication, SSSD must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
        DiscussMD5 : 50554C0CBAFC69FC028D7D728277EF7C
        CheckMD5   : 4BBAE7A638ACAD3B7314F0E03077747E
        FixMD5     : 7DD70EF59C96BBFEAFDACE44277B7B40
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
    $finding = $(grep -s -i -A 1 '^\[sssd\]' /etc/sssd/sssd.conf)
    $finding ??= "Check text: No results found."
    $finding_2 = ""
    $finding_3 = ""

    if ($finding[1] -match "pam") {
        $finding_2 = $(grep -s -i -A 1 '^\[pam]' /etc/sssd/sssd.conf)
        $finding_2 ??= "Check text: No results found."

        if (($finding_2[1] | awk '{$2=$2};1').ToLower() -eq "pam_cert_auth = true"){
            $finding_3 = $(grep -s -i certificate_verification /etc/sssd/sssd.conf)
            $finding_3 ??= "Check text: No results found."

            if (($finding_3 | awk '{$2=$2};1').ToLower() -match "ca"){
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system, for PKI-based authentication, SSSD validates certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
            }
            else{
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not enforce certificate verification via a 'ca'."
            }
        }
        else{
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system is not set to use pam for smart card authentication."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system, for PKI-based authentication, SSSD does not validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270736 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270736
        STIG ID    : UBTU-24-400370
        Rule ID    : SV-270736r1066697_rule
        CCI ID     : CCI-000187
        Rule Name  : SRG-OS-000068-GPOS-00036
        Rule Title : Ubuntu 24.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.
        DiscussMD5 : 4AC24BE571CD2A826C5A37762348F100
        CheckMD5   : D16F9D5846848AAAA03A2690BC0EAD62
        FixMD5     : 542B70547A5B85C18E7BB29DF5A4A751
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
    $finding = $(dpkg -l | grep -s libpam-pkcs11)

    if (($finding | awk '{print $2}') -match "libpam-pkcs11") {
        $finding_2 = $(grep -s -i ^[[:blank:]]*ldap_user_certificate /etc/sssd/sssd.conf)
        if ($finding_2) {
            if ((($finding_2 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "userCertificate;binary") {
                $Status = "NotAFinding"
                $FindingMessage = "Authenticated certificates are mapped to the appropriate user group in the '/etc/sssd/sssd.conf' file."
            }
            else {
                $Status = "Open"
                $FindingMessage = "Authenticated certificates are not mapped to the appropriate user group in the '/etc/sssd/sssd.conf' file."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "Authenticated certificates are not mapped to the appropriate user group in the '/etc/sssd/sssd.conf' file."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'libpam-pkcs11' package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270737 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270737
        STIG ID    : UBTU-24-400375
        Rule ID    : SV-270737r1067178_rule
        CCI ID     : CCI-000185, CCI-004909
        Rule Name  : SRG-OS-000066-GPOS-00034
        Rule Title : Ubuntu 24.04 LTS, for PKI-based authentication, Privileged Access Management (PAM) must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
        DiscussMD5 : 50554C0CBAFC69FC028D7D728277EF7C
        CheckMD5   : B567DB2EBE6CA901FAE27FA0E86A92F8
        FixMD5     : 3DD48192282DAB62FC2296579EE4BBA2
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
    $finding = $(grep -s -i use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep -s cert_policy | grep -s ca)
    $finding ??= "Check text: No results found."

    if (((($Finding.trimstart()).ToLower()).StartsWith("cert_policy")) -and (($finding.ToLower()).contains("ca"))) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is not configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270738 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270738
        STIG ID    : UBTU-24-400380
        Rule ID    : SV-270738r1066703_rule
        CCI ID     : CCI-004068
        Rule Name  : SRG-OS-000384-GPOS-00167
        Rule Title : Ubuntu 24.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.
        DiscussMD5 : F695B0E69E83A3C59D09A27D253E6A0A
        CheckMD5   : 237D379453C8882F0C95436FF1A89244
        FixMD5     : FEEAD3797C73C44F44017482FDF72CC2
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
    $finding = $(grep -s -i ^[[:blank:]]*cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -s -E -- 'crl_auto|crl_offline')
    $finding ??= "Check text: No results found."
    $correct_message_count = 0

    $finding | Foreach-Object {
        if ((($_.ToLower() -match "crl_auto")) -or (($_.ToLower() -match "crl_offline"))) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system uses local revocation data when unable to access it from the network."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not use local revocation data when unable to access it from the network."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270739 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270739
        STIG ID    : UBTU-24-400400
        Rule ID    : SV-270739r1067124_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-OS-000120-GPOS-00061
        Rule Title : Ubuntu 24.04 LTS must encrypt all stored passwords with a FIPS 140-3 approved cryptographic hashing algorithm.
        DiscussMD5 : 362BFA65936DD923B7EC8631E28BA5D3
        CheckMD5   : 359BE82F7B2D693B514739F739001EB2
        FixMD5     : B37C77915BC40B87F6178AC8DFFCE294
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
    $finding = $(grep -s -i ^[[:blank:]]*encrypt_method /etc/login.defs)
    $finding ??= "Check text: No results found."

    If (($Finding | awk '{$2=$2};1').ToUpper() -eq "ENCRYPT_METHOD SHA512") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system encrypts all stored passwords with a FIPS approved cryptographic hashing algorithm."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not encrypt all stored passwords with a FIPS approved cryptographic hashing algorithm."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270740 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270740
        STIG ID    : UBTU-24-500010
        Rule ID    : SV-270740r1066709_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : Ubuntu 24.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions, and other system-level access.
        DiscussMD5 : 7EAD581D4A0DA1E46847B1498588CAD4
        CheckMD5   : 563EF02E8D23E0DA1E280EC6995EFCBA
        FixMD5     : F5FD41ABCAC8C99A5E6F0CA2CA383C6D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s sudo.log)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/sudo.log[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system audits privileged activities."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system audits privileged activities."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270741 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270741
        STIG ID    : UBTU-24-500050
        Rule ID    : SV-270741r1066712_rule
        CCI ID     : CCI-000877
        Rule Name  : SRG-OS-000125-GPOS-00065
        Rule Title : Ubuntu 24.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
        DiscussMD5 : 5133FABF63BC036E7A26C084CB14E1A2
        CheckMD5   : 7BB3B941B99996636351E6B9ECC3082E
        FixMD5     : 2E3E00E85956007EABBBA5EFEE8BF04C
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
    $finding = $(dpkg -l | grep -s openssh)

    if (!($finding | awk '{print $2}').contains("openssh-server")) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The ssh package is not installed to validate check per Check Text."
    }
    else {
        $finding = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH ^[[:blank:]]*usepam)
        $finding ??= "Check text: No results found."
        $correct_message_count = 0

        $finding | ForEach-Object {
            if ((($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes"){
                $correct_message_count++
            }
        }

        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system is not configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270742 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270742
        STIG ID    : UBTU-24-600000
        Rule ID    : SV-270742r1066715_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity.
        DiscussMD5 : 72E2B943EFEA9C890BFAEAC4B7014F4A
        CheckMD5   : 8AC04A58280E9DB082DB46B4B8673358
        FixMD5     : 9C4E56AE3040833B78B0A31E902CD414
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
    $finding = $(dpkg -l | grep -s openssh)

    if (!($finding | awk '{print $2}').contains("openssh-server")) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The ssh package is not installed to validate check per Check Text."
    }
    else {
        $finding = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH ^[[:blank:]]*clientalivecountmax)
        $finding ??= "Check text: No results found."
        $correct_message_count = 0

        $finding | ForEach-Object { if (((($_.split(":")[1] | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "1"){
            $correct_message_count++
        } }
        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH server automatically terminates a user session after the SSH client has become unresponsive."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The SSH server does not automatically terminates a user session after the SSH client has become unresponsive."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270743 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270743
        STIG ID    : UBTU-24-600010
        Rule ID    : SV-270743r1066718_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.
        DiscussMD5 : 11778F0AEF89F10777239054711F06EC
        CheckMD5   : 268BEF4C55C7C3D50B869C3BEB7092B7
        FixMD5     : 904B37E751CF10E410D1D55E7880EDA3
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
    $finding = $(dpkg -l | grep -s openssh)

    if (!($finding | awk '{print $2}').contains("openssh-server")) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The ssh package is not installed to validate check per Check Text."
    }
    else {
        $finding = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH ^[[:blank:]]*clientaliveinterval)
        $finding ??= "Check text: No results found."
        $correct_message_count = 0

        $finding | ForEach-Object { if (((($_.split(":")[1] | awk '{$2=$2};1').split(" "))[1]).ToLower() -le 600){
            $correct_message_count++
        } }
        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The SSH server does not automatically terminates a user session after the SSH client has been unresponsive for 10 minutes."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270744 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270744
        STIG ID    : UBTU-24-600030
        Rule ID    : SV-270744r1066721_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-OS-000478-GPOS-00223
        Rule Title : Ubuntu 24.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
        DiscussMD5 : 1625743A3027EA21D44929FEB8D0B88C
        CheckMD5   : B8C8C72BA8295159148344BEE854B736
        FixMD5     : 49F33B30512EAB712B3D5FB5DE145DC0
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
    $finding = $(cat /proc/sys/crypto/fips_enabled)

    if ($finding -eq "1") {
        $Status = "NotAFinding"
        $FindingMessage = "The system is configured to run in FIPS mode."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system is not configured to run in FIPS mode."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270746 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270746
        STIG ID    : UBTU-24-600070
        Rule ID    : SV-270746r1101769_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-OS-000184-GPOS-00078
        Rule Title : Ubuntu 24.04 LTS must disable kernel core dumps.
        DiscussMD5 : 82F90B2D2B8346DED7240F4AEFD9184C
        CheckMD5   : AFC3007C74985F8F4B4EDC231124781F
        FixMD5     : A24B546C95FC7496FCF911878EAFE27F
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
    $finding = $(dpkg -l | grep -s kdump-tools)

    if (($finding | awk '{print $2}') -eq "kdump-tools") {
        $finding = $(systemctl is-active kdump-tools.service)

        If ($finding -eq "inactive") {
            $Status = "NotAFinding"
            $FindingMessage = "Kernel core dumps are disabled."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The 'kdump' service is active. Ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO)."
            $FindingMessage += "`r'`n"
            $FindingMessage += "The 'kdump-tools.service' is active."
        }
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "Kdump-tools is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270748 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270748
        STIG ID    : UBTU-24-600130
        Rule ID    : SV-270748r1066733_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-OS-000134-GPOS-00068
        Rule Title : Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group.
        DiscussMD5 : DA8A50595816E762FEDBAF51A9CAA010
        CheckMD5   : 386B8C1CAF739AE3A979BC890178D607
        FixMD5     : FA7899D6E0C9995860EB5F20766E8383
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
    $finding = $(grep -s sudo /etc/group)

    $FindingMessage = "Verify that the sudo group has only members who should have access to security functions."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270749 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270749
        STIG ID    : UBTU-24-600140
        Rule ID    : SV-270749r1067179_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : Ubuntu 24.04 LTS must restrict access to the kernel message buffer.
        DiscussMD5 : 84F6C0A2F1E04B895CE976C11AFBFBB3
        CheckMD5   : 8B1572DC86AE3D109046BA155079492C
        FixMD5     : 3C48EB7F82A991376C3F259E6771F6EC
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
    $finding = $(sysctl kernel.dmesg_restrict)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $finding_2 = $(grep -s -i ^[[:blank:]]*kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf)
        $finding_2 ??= "Check text: No results found."
        $foundcount = 1

        $finding_2 | Foreach-Object {
            if ((($_ | awk '{$2=$2};1').replace(" ", "")).split("=")[1] -eq 1) {
                $foundcount++
            }
        }
        if ($finding_2.count -eq $foundcount-1){
            $Status = "NotAFinding"
            $FindingMessage = "The operating system is configured to restrict access to the kernel message buffer."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system is not configured to restrict access to the kernel message buffer."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to restrict access to the kernel message buffer."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270750 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270750
        STIG ID    : UBTU-24-600150
        Rule ID    : SV-270750r1066739_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : Ubuntu 24.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
        DiscussMD5 : 66C368AF5F6C706E0A5AECCC92769842
        CheckMD5   : C3620FDA517AF5A6D65131392E78A9AA
        FixMD5     : FAFF080EBCE45E3B9CF4AFCD031B91BB
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
    $finding = $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -type d -perm -002 ! -perm -1000)

    if ($Finding) {
        $Status = "Open"
        $FindingMessage = "The below files do not have their sticky bit set."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The below files have their sticky bit set."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270751 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270751
        STIG ID    : UBTU-24-600160
        Rule ID    : SV-270751r1066742_rule
        CCI ID     : CCI-004922, CCI-004923
        Rule Name  : SRG-OS-000785-GPOS-00250
        Rule Title : Ubuntu 24.04 LTS must compare internal information system clocks at least every 24 hours with an authoritative time server.
        DiscussMD5 : 4564B0B404FE3F18D56C85953CCEF00D
        CheckMD5   : 9E9155F0AF343F25380BD94833F2B5DE
        FixMD5     : 42156A8F40C21AFA9136F0D8D2151B0D
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
    $finding = $(grep -s maxpoll /etc/chrony/chrony.conf)
    $finding ??= "Check text: No results found."
    $finding_2 = ""
    $found = 0

    $finding | Foreach-Object {
        $maxpoll = $($_ | grep -s -oP '(?<=maxpoll )[^ ]*')
        if (($_.ToLower()).startswith("server") -and ($maxpoll -le "16")) {
            $found++
        }
    }

    if ($found -eq $finding.count) {
        $finding_2 = $(grep -s -i server /etc/chrony/chrony.conf)
        if ($finding_2) {
            $Status = "Not_Reviewed"
            $FindingMessage = "Verify that the 'chrony.conf' file is configured to an authoritative DoD time source."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The 'chrony.conf' file is not configured to an authoritative time source."
        }
    }
    else {
        $finding_2 -eq ""
        $Status = "Open"
        $FindingMessage = "The system clock is not configured to compare the system clock at least every 24 hours to the authoritative time source."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270752 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270752
        STIG ID    : UBTU-24-600180
        Rule ID    : SV-270752r1068365_rule
        CCI ID     : CCI-004926
        Rule Name  : SRG-OS-000356-GPOS-00144
        Rule Title : Ubuntu 24.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
        DiscussMD5 : 1472D8DE6373FBFF1062653F99ECA39B
        CheckMD5   : CD88115B641808FD5111056511692FF3
        FixMD5     : 9AC7E5C3402EE24E32340B1E1D90966D
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
    $finding = $(grep -s -i ^[[:blank:]]*makestep /etc/chrony/chrony.conf)
    $finding ??= "Check text: No results found."
    $finding_2 = $(timedatectl | grep -Ei '(synchronized|service)')
    $finding_2 ??= "Check text: No results found."

    if (((($finding | awk '{$2=$2};1').replace("makestep ", "")) -eq "1 -1") -and ($finding_2 -match "NTP Service: active")) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system synchronizes internal system clocks to the authoritative time source when the time difference is greater than one second and the NTP service is active."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not synchronize internal system clocks to the authoritative time source when the time difference is greater than one second or the NTP service is not active."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270753 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270753
        STIG ID    : UBTU-24-600190
        Rule ID    : SV-270753r1066748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-OS-000142-GPOS-00071
        Rule Title : Ubuntu 24.04 LTS must be configured to use TCP syncookies.
        DiscussMD5 : A0F3A58F6B925B8EDC09213FFC5F751A
        CheckMD5   : BCD19C280E208D8BF7DE5FA39D5151C2
        FixMD5     : 49E00C8A2A8AA25FB69CC42AB8E50EDC
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
    $variable = "net.ipv4.tcp_syncookies"
    $value = "1"

    $finding = $(sysctl $variable)
    $finding ??= "Check text: No results found."
    $finding_2 = $(grep -s -i $variable /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf)
    $finding_2 ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq $value) {
        If ((($finding_2 | awk '{$2=$2};1').replace(" ", "")).split("=")[1] -eq $value) {
            $Status = "NotAFinding"
            $FindingMessage = "The system uses syncookies."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system does not use syncookies."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system does not use syncookies."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270755 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270755
        STIG ID    : UBTU-24-600230
        Rule ID    : SV-270755r1066754_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-OS-000481-GPOS-00481
        Rule Title : Ubuntu 24.04 LTS must disable all wireless network adapters.
        DiscussMD5 : 896DB115F163501478D61F7CCB2589AB
        CheckMD5   : BB7986434C71A5B0ABF46F0908096391
        FixMD5     : 44077AE47FAE1B48DFA30741BE08FD46
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
    $finding = $(ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename)

    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "A wireless interface is configured and must be documented and approved by the Information System Security Officer (ISSO)"
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "This requirement is Not Applicable for systems that do not have physical wireless network radios."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270756 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270756
        STIG ID    : UBTU-24-700010
        Rule ID    : SV-270756r1066757_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-OS-000205-GPOS-00083
        Rule Title : Ubuntu 24.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
        DiscussMD5 : 7A6BA1BDB4E31F3546DC89C1C346C2A4
        CheckMD5   : F297D461FB5888AF16E6A81EDAFE3445
        FixMD5     : 58A92F8AEAA4CE3F2DA71745EF006DBB
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
    $command = @'
#!/bin/sh

find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($Finding) {
        $Status = "Open"
        $FindingMessage += "The below files do not have their permissions set to 640 or more."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage += "The below files have their permissions set to 640 or more."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270757 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270757
        STIG ID    : UBTU-24-700020
        Rule ID    : SV-270757r1066760_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-OS-000205-GPOS-00083
        Rule Title : Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.
        DiscussMD5 : 30E378F75115C0C84B34E7900AFAA63A
        CheckMD5   : 0722CB31DB9FC496DCBF8DB23E46FEA3
        FixMD5     : E020E03E2D29A72B5F7EF423F9572DF3
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
    $finding = $(CheckPermissions -FindPath "/run/log/journal" -MinPerms 2640 -Type Directory)
    $finding_2 = $(CheckPermissions -FindPath "/var/log/journal" -MinPerms 2640 -Type Directory)
    $finding_3 = $(CheckPermissions -FindPath "/run/log/journal"  -MinPerms 640 -Type File -Recurse)
    $finding_4 = $(CheckPermissions -FindPath "/var/log/journal" -MinPerms 640 -Type File -Recurse)

    if ($finding -eq $True -and $finding_2 -eq $True){
        $FindingMessage = "The /run/log/journal and /var/log/journal directories have permissions set to 2640 or less permissive."
    }
    else {
        $FindingMessage = "The /run/log/journal and /var/log/journal directories do not have permissions set to '2640' or less permissive."
    }

    $FindingMessage = "`r`n"

    if ($finding_3 -eq $True -and $finding_4 -eq $True){
        $FindingMessage += "All files in the /run/log/journal and /var/log/journal directories have permissions set to '640' or less permissive."
    }
    else {
        $FindingMessage += "All files in the /run/log/journal and /var/log/journal directories do not have permissions set to '640' or less permissive."
    }

    if ($finding -eq $True -and $finding_2 -eq $True -and $finding_3 -eq $True -and $finding_4 -eq $True){
        $Status = "NotAFinding"
    }
    else{
        $Status = "Open"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_4
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270758 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270758
        STIG ID    : UBTU-24-700030
        Rule ID    : SV-270758r1066763_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-OS-000205-GPOS-00083
        Rule Title : Ubuntu 24.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users.
        DiscussMD5 : 30E378F75115C0C84B34E7900AFAA63A
        CheckMD5   : D3BA738A9A37EF6FE29A5C428D6D2E0B
        FixMD5     : 8A39282F57F82C99B11366A1193A6475
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
    $finding = $(stat -c "%n %a" /usr/bin/journalctl)

    if ($finding) {
        if ($(CheckPermissions -FindPath "/usr/bin/journalctl" -MinPerms 740) -eq $True){
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system configures the /usr/bin/journalctl file with mode '740' or more (less permissive)."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system configures the /usr/bin/journalctl file with mode '740' (more permissive)."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system in missing the /usr/bin/journalctl file."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270759 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270759
        STIG ID    : UBTU-24-700040
        Rule ID    : SV-270759r1068367_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must be configured so that the "journalctl" command is owned by "root".
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : FFDA27AC8FB01E6C2760A978C368B546
        FixMD5     : A1306A63507D8FCA72CF0D3DAF64F605
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
    $finding = $(stat -c "%n %U" /usr/bin/journalctl)

    if ($finding -eq "/usr/bin/journalctl root") {
        $Status = "NotAFinding"
        $FindingMessage = "The /usr/bin/journalctl directory is owned by root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /usr/bin/journalctl directory is not owned by root."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270760 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270760
        STIG ID    : UBTU-24-700050
        Rule ID    : SV-270760r1066769_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must be configured so that the "journalctl" command is group-owned by "root".
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : EBC978BF466A3AD69F70771642E3EAD2
        FixMD5     : E96AED1FCFC95B9BB5BE0196058A0890
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
    $finding = $(stat -c "%n %G" /usr/bin/journalctl)

    if ($finding -eq "/usr/bin/journalctl root") {
        $Status = "NotAFinding"
        $FindingMessage = "The /usr/bin/journalctl directory is group-owned by root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /usr/bin/journalctl directory is not group-owned by root."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270761 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270761
        STIG ID    : UBTU-24-700060
        Rule ID    : SV-270761r1067180_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : 42DC9B46FEA69E971B5B79E7F25231E1
        FixMD5     : CE246DBE36FF686F8CCE8CB2B6AAA8ED
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
    $command = @'
#!/bin/sh

find /run/log/journal /var/log/journal -xdev ! -group systemd-journal -type d -exec stat -c "%n %G" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The directories '/run/log/journal' and '/var/log/journal' are not group-owned by systemd-journal."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The directories '/run/log/journal' and '/var/log/journal' are group-owned by systemd-journal."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) are not group-owned by systemd-journal."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270762 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270762
        STIG ID    : UBTU-24-700070
        Rule ID    : SV-270762r1066775_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal".
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : 242BFFEC9DE2DC8A0687A87D6E646A7B
        FixMD5     : CDCA81AA968DFFFACB6D3B1081ED76E0
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
    $command = @'
#!/bin/sh

find /run/log/journal /var/log/journal -xdev ! -group systemd-journal -type f -exec stat -c "%n %G" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The files in '/run/log/journal' and '/var/log/journal' are not group-owned by systemd-journal."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The files in '/run/log/journal' and '/var/log/journal' are group-owned by systemd-journal."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not group-owned by systemd-journal."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270763 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270763
        STIG ID    : UBTU-24-700080
        Rule ID    : SV-270763r1066778_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the directories used by the system journal to be owned by "root".
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : 768428DCC199B1193A6C71020926CED4
        FixMD5     : AFA70FF1C347E6206AEFA9F5FD77AC09
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
    $command = @'
#!/bin/sh

find /run/log/journal /var/log/journal -xdev ! -user root -type d -exec stat -c "%n %U" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The /run/log/journal and /var/log/journal directories are not owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The /run/log/journal and /var/log/journal directories are owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270764 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270764
        STIG ID    : UBTU-24-700090
        Rule ID    : SV-270764r1066781_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the files used by the system journal to be owned by "root"
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : 06A890D4F26907FCBB8E11FBD6324710
        FixMD5     : 7EA3C7DEF45EE8787487646F9F876A17
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
    $command = @'
#!/bin/sh

find /run/log/journal /var/log/journal -xdev ! -user root -type f -exec stat -c "%n %U" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The /run/log/journal and /var/log/journal files are not owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The /run/log/journal and /var/log/journal files are owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270765 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270765
        STIG ID    : UBTU-24-700100
        Rule ID    : SV-270765r1066784_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the /var/log directory to be group-owned by syslog.
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : D14ACC209286D6E3DBD3ACBDE4BE53B5
        FixMD5     : AECD92BB82066C4506EE521A3300F132
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
    $finding = $(stat -c "%n %G" /var/log)

    if ($finding -eq "/var/log syslog") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log directory is group owned by syslog."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log directory is not group owned by syslog."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270766 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270766
        STIG ID    : UBTU-24-700110
        Rule ID    : SV-270766r1066787_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the /var/log directory to be owned by root.
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : 1941FC556E6D6EB6B0B7C7303DDE75CB
        FixMD5     : 53D39C49FC6B30B455C8977FCCC3D93C
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
    $finding = $(stat -c "%n %U" /var/log)

    if ($finding -eq "/var/log root") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log directory is owned by root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log directory is not owned by root."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270767 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270767
        STIG ID    : UBTU-24-700120
        Rule ID    : SV-270767r1066790_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the /var/log directory to have mode "0755" or less permissive.
        DiscussMD5 : 4C44B788711F32479732BDDA1D47DE50
        CheckMD5   : 946234EF4DFC333B346FEF2EDD10076C
        FixMD5     : 7EEBE69508D1804E5E7DEDAD19FC03BC
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
    $finding = $(dpkg -l | grep -s rsyslog)

    if (($finding | awk '{print $2}') -eq "rsyslog") {
        $finding = $(systemctl is-enabled rsyslog)
        if ($finding -eq "enabled") {
            $finding = $(systemctl is-active rsyslog)
            if ($finding -eq "active") {
                $Status = "Not_Applicable"
                $FindingMessage += "rsyslog is active and enabled on the operating system."
            }
        }
    }
    if ($Status -ne "Not_Applicable"){
        $finding = $(stat -c "%n %a" /var/log)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $Status = "NotAFinding"
            $FindingMessage = "The mode of the /var/log directory is '755' or more (more permissive)."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The mode of the /var/log directory is less than '755' (less permissive)."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270768 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270768
        STIG ID    : UBTU-24-700130
        Rule ID    : SV-270768r1066793_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure the /var/log/syslog file to be group-owned by adm.
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : 13E10FFA5DDD4A913C39DABD66B25D05
        FixMD5     : A4681565979CE75F4DADE522DD0E65A7
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
    $finding = $(stat -c "%n %G" /var/log/syslog)

    if ($finding -eq "/var/log/syslog adm") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log/syslog file is group owned by adm."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log/syslog file is not group owned by adm."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270769 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270769
        STIG ID    : UBTU-24-700140
        Rule ID    : SV-270769r1066796_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure /var/log/syslog file to be owned by syslog.
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : D835272E5EE91A7D4988162FB56347AA
        FixMD5     : 3167421A0E99B99046B06133D9AB4DFB
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
    $finding = $(stat -c "%n %U" /var/log/syslog)

    if ($finding -eq "/var/log/syslog syslog") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log/syslog file is owned by syslog."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log/syslog file is not owned by syslog."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270770 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270770
        STIG ID    : UBTU-24-700150
        Rule ID    : SV-270770r1066799_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Ubuntu 24.04 LTS must configure /var/log/syslog file with mode "0640" or less permissive.
        DiscussMD5 : C706D789D65EF364E82A127F50138646
        CheckMD5   : BC15364093A291E8CCF612C13708BB62
        FixMD5     : E917E133F84C1CD7AF3DAD95A0BD52AD
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
    $finding = $(stat -c "%n %a" /var/log/syslog)

    if ($finding) {
        $better_finding = $(CheckPermissions -FindPath "/var/log/syslog" -MinPerms 640)
        if ($better_finding -eq $True){
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system configures the /var/log/syslog file with mode '0640' or more (less permissive)."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system configures the /var/log/syslog file with mode '0640' (more permissive)."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system in missing the /var/log/syslog file."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270771 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270771
        STIG ID    : UBTU-24-700300
        Rule ID    : SV-270771r1066802_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00192
        Rule Title : Ubuntu 24.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.
        DiscussMD5 : 6BC4AFAD2808D5D622BB5721B427F8F3
        CheckMD5   : CB1609030F149C57BE4A846C250412CE
        FixMD5     : C254920FF9D4306132E1F4A8591F2AA7
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
    $finding = $(dmesg | grep -s -i "execute disable")
    $finding ??= "Check text: No results found."
    $finding_2 = ""

    if ($finding -match "NX (Execute Disable) protection: active" ) {
        $Status = "NotAFinding"
        $FindingMessage = "The NX (no-execution) bit flag is set on the system."
    }
    else {
        $finding_2 = $(grep -s flags /proc/cpuinfo | grep -s -w nx | Sort-Object -u)
        $finding_2 ??= "Check text: No results found."

        if ($Finding_2.contains("nx")) {
            $Status = "NotAFinding"
            $FindingMessage = "The NX (no-execution) bit flag is set on the system."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The NX (no-execution) bit flag is not set on the system."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270772 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270772
        STIG ID    : UBTU-24-700310
        Rule ID    : SV-270772r1066805_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00193
        Rule Title : Ubuntu 24.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution.
        DiscussMD5 : 6BC4AFAD2808D5D622BB5721B427F8F3
        CheckMD5   : D9877D72D74449CB7952F9372335CBFD
        FixMD5     : F3A2F765C20CCE0F93206303E38D6DB3
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
    $finding = $(sysctl kernel.randomize_va_space)
    $finding_2 = ""
    $finding_3 = ""

    if ((($Finding.ToLower()).StartsWith("kernel.randomize_va_space")) -and (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 2)) {
        $finding_2 = $(cat /proc/sys/kernel/randomize_va_space)

        if ($Finding_2 -eq 2) {
            $finding_3 = $(egrep -s -R "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d)

            if ($finding_3) {
                $status = "Open"
                $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)."
                $FindingMessage += "`r`n"
                $FindingMessage += "The saved value of the kernel.randomize_va_space variable is different from 2."
            }
            else {
                $status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system implements address space layout randomization (ASLR)."
                $FindingMessage += "`r`n"
                $FindingMessage += "The saved value of the kernel.randomize_va_space variable is not different from 2."
            }
        }
        else {
            $status = "Open"
            $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)."
            $FindingMessage += "`r`n"
            $FindingMessage += "The kernel parameter randomize_va_space is not set to 2."
        }
    }
    else {
        $status = "Open"
        $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270773 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270773
        STIG ID    : UBTU-24-700320
        Rule ID    : SV-270773r1066808_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-OS-000437-GPOS-00194
        Rule Title : Ubuntu 24.04 LTS must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed.
        DiscussMD5 : 1664F2CB47698D309E1F3C0682B43A4C
        CheckMD5   : 84C9B9307879607EB842CB6CEDFD0A73
        FixMD5     : C095A6CEE29EF379CD25F25FE0570B31
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
    $finding = $(grep -s -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades | grep -v "^#")
    $finding ??= "Check text: No results found."

    if (($finding.Contains('Unattended-Upgrade::Remove-Unused-Dependencies "true";')) -and ($finding.Contains('Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'))) {
        $Status = "NotAFinding"
        $FindingMessage = "APT is configured to remove all software components after updating."
    }
    else {
        $Status = "Open"
        $FindingMessage = "APT is not configured to remove all software components after updating."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270774 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270774
        STIG ID    : UBTU-24-700400
        Rule ID    : SV-270774r1066811_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-OS-000439-GPOS-00195
        Rule Title : Ubuntu 24.04 LTS must be a vendor-supported release.
        DiscussMD5 : 8F6A0FBC4C4E893EE4DD642AD400F6F2
        CheckMD5   : 59F0AFA8B96FE6BE7B4D0594C511897D
        FixMD5     : 25E4D65AAE63ADCAFBDC7BC5C912DDEE
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
    $finding = $(grep -s -i DISTRIB_DESCRIPTION /etc/lsb-release)
    $finding ??= "Check text: No results found."

    if ($finding -like "*24.04*LTS*") {
        $Status = "NotAFinding"
        $FindingMessage = "The version of Ubuntu 24.04 LTS is vendor supported."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The version of Ubuntu 24.04 LTS is not vendor supported."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270775 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270775
        STIG ID    : UBTU-24-900040
        Rule ID    : SV-270775r1068369_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : Ubuntu 24.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.
        DiscussMD5 : 62CB8ACA8106DFE3D3D59C5A43F5053B
        CheckMD5   : A29190BEB3523ABD9E94BBE3181FA8C5
        FixMD5     : FE0C98203CA929D72A686E648C83CD14
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
    $finding = $(CheckPermissions -FindPath /etc/audit/ -MinPerms 640 -Type File -Recurse)

    if ($finding -ne $true) {
        $Status = "Open"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files do not have a mode of 0640 or less permissive."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files have a mode of 0640 or less permissive."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270776 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270776
        STIG ID    : UBTU-24-900050
        Rule ID    : SV-270776r1066817_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : Ubuntu 24.04 LTS must permit only authorized accounts to own the audit configuration files.
        DiscussMD5 : 860761B6BE2F1B3D2795F41FDF9B8772
        CheckMD5   : C75C2D3D6FB9E01EC81C42BA00CCF558
        FixMD5     : 95D798BD494209617C795D542170162E
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
    $finding = $(ls -al /etc/audit/ /etc/audit/rules.d/)
    $correct_message_count = 0
    $line_count = 0

    $finding | ForEach-Object {
        if ($_.StartsWith("-")) {
            $line_count++
            if (($_ | awk '{$2=$2};1').split(" ")[2] -eq "root") {
                $correct_message_count++
            }
        }
    }
    if ($correct_message_count -eq $line_count) {
        $Status = "NotAFinding"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are owned by root account."
    }
    else {
        $Status = "Open"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are not owned by root account."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270777 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270777
        STIG ID    : UBTU-24-900060
        Rule ID    : SV-270777r1066820_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : Ubuntu 24.04 LTS must permit only authorized groups to own the audit configuration files.
        DiscussMD5 : 860761B6BE2F1B3D2795F41FDF9B8772
        CheckMD5   : 62483CD186E5985713DD6348575107B7
        FixMD5     : C68BA48A6E3D4A9F6970BB9F61BF29D4
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
    $finding = $(ls -al /etc/audit/ /etc/audit/rules.d/)
    $correct_message_count = 0
    $line_count = 0

    $finding | ForEach-Object {
        if ($_.StartsWith("-")) {
            $line_count++
            if (($_ | awk '{$2=$2};1').split(" ")[3] -eq "root") {
                $correct_message_count++
            }
        }
    }
    if ($correct_message_count -eq $line_count) {
        $Status = "NotAFinding"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are owned by root group."
    }
    else {
        $Status = "Open"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are not owned by root group."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270778 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270778
        STIG ID    : UBTU-24-900070
        Rule ID    : SV-270778r1066823_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the su command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 7C8C4619D15D7DE5B9FD0BA6D079EFFC
        FixMD5     : 3EE52DF52F345A4169E317412B23E309
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/bin/su')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/bin/su ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/bin\/su[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'su' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'su' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'su' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270779 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270779
        STIG ID    : UBTU-24-900080
        Rule ID    : SV-270779r1066826_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 798AA02731721E897B99E429685FCC55
        FixMD5     : D5A5AEFA20A8CD35F160CFEE89105217
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/chfn')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chfn ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chfn[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'chfn' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'chfn' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'chfn' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270780 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270780
        STIG ID    : UBTU-24-900090
        Rule ID    : SV-270780r1066829_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the mount command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : A07522B0EF4F1D2AA5DB432C8547FF47
        FixMD5     : 4C33D4093B13CE2A7DC93ABA60225426
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/mount')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/mount ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/mount[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'mount' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'mount' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'mount' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'mount' command occur."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270781 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270781
        STIG ID    : UBTU-24-900100
        Rule ID    : SV-270781r1066832_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the umount command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 84AEF03885A2304961CF7080517D77BE
        FixMD5     : B52E7B4BBB43216A91B99B0E285AF37C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/umount')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/umount ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/umount[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'umount' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'umount' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'umount' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'umount' command occur."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270782 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270782
        STIG ID    : UBTU-24-900110
        Rule ID    : SV-270782r1066835_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 20A725CD13A21BA892F34269D0F9A746
        FixMD5     : 2CB0B939758FAC17E1096DA9822DB286
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/ssh-agent')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/ssh-agent ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/ssh-agent[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'ssh-agent' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'ssh-agent' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'ssh-agent' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270783 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270783
        STIG ID    : UBTU-24-900120
        Rule ID    : SV-270783r1066838_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 7B6EB987EC038293CA27EBD4E4FF9E97
        FixMD5     : C5654BD035F88F0ECCFBDAF700E34C28
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s ssh-keysign)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/lib/openssh/ssh-keysign ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/lib\/openssh\/ssh-keysign[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270784 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270784
        STIG ID    : UBTU-24-900130
        Rule ID    : SV-270784r1068371_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
        DiscussMD5 : E06AF97A3240DB36CB8A67C283358151
        CheckMD5   : 225C36CBCB2F505A828134E2E5FB1170
        FixMD5     : 97E667E5C39F072458A83B3B48FF9889
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s xattr)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+setxattr[\s]+|([\s]+|[,])setxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+setxattr[\s]+|([\s]+|[,])setxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fsetxattr[\s]+|([\s]+|[,])fsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fsetxattr[\s]+|([\s]+|[,])fsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lsetxattr[\s]+|([\s]+|[,])lsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lsetxattr[\s]+|([\s]+|[,])lsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+removexattr[\s]+|([\s]+|[,])removexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+removexattr[\s]+|([\s]+|[,])removexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fremovexattr[\s]+|([\s]+|[,])fremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fremovexattr[\s]+|([\s]+|[,])fremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lremovexattr[\s]+|([\s]+|[,])lremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lremovexattr[\s]+|([\s]+|[,])lremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr' commands occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270785 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270785
        STIG ID    : UBTU-24-900140
        Rule ID    : SV-270785r1068373_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls.
        DiscussMD5 : 69F9BC6464FFFBAB25E985D50BDE419B
        CheckMD5   : E6AB344F46B14B1377DA8683AD69E12B
        FixMD5     : FD1BF09A1F76FF8BB22FBB4F28992935
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chown)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+chown[\s]+|([\s]+|[,])chown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+chown[\s]+|([\s]+|[,])chown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchown[\s]+|([\s]+|[,])fchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchown[\s]+|([\s]+|[,])fchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lchown[\s]+|([\s]+|[,])lchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lchown[\s]+|([\s]+|[,])lchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchownat[\s]+|([\s]+|[,])fchownat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchownat[\s]+|([\s]+|[,])fchownat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'chown,fchown,fchownat,lchown' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'chown,fchown,fchownat,lchown' commands occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270786 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270786
        STIG ID    : UBTU-24-900150
        Rule ID    : SV-270786r1068375_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls.
        DiscussMD5 : 69F9BC6464FFFBAB25E985D50BDE419B
        CheckMD5   : CF77A409694B9975FF235B5824554546
        FixMD5     : 35FD8708B7F5A001F0B65EE2572AA91D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chmod)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+chmod[\s]+|([\s]+|[,])chmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+chmod[\s]+|([\s]+|[,])chmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchmod[\s]+|([\s]+|[,])fchmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchmod[\s]+|([\s]+|[,])fchmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchmodat[\s]+|([\s]+|[,])fchmodat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchmodat[\s]+|([\s]+|[,])fchmodat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'chmod,fchmod,fchmodat' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'chmod,fchmod,fchmodat' commands occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270787 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270787
        STIG ID    : UBTU-24-900160
        Rule ID    : SV-270787r1068378_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.
        DiscussMD5 : 08B090A011A8E89427AF20303D078214
        CheckMD5   : E9097A2DCF1F2D67AD85E8D73E5944B9
        FixMD5     : 21BF2946A6827F432E2E1FF69F8FCB4E
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s open)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when unsuccessful attempts to use the 'creat,open,openat,open_by_handle_at,truncate,ftruncate' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'creat,open,openat,open_by_handle_at,truncate,ftruncate' system calls."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270788 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270788
        STIG ID    : UBTU-24-900170
        Rule ID    : SV-270788r1066853_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : BB6BC7232E9FF68FE75FBF6F9765A87D
        FixMD5     : DD7F1A32966E58D84230726531CD6309
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s /usr/bin/sudo)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/sudo ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/sudo[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'sudo' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'sudo' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'sudo' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270789 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270789
        STIG ID    : UBTU-24-900180
        Rule ID    : SV-270789r1066856_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : B8D86140AD3E57B6B43B4DE1F68B1206
        FixMD5     : 6388E8643885BB1A0C586AB61FE11EB7
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s /usr/bin/sudoedit)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/sudoedit ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/sudoedit[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'sudoedit' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'sudoedit' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'sudoedit' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270790 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270790
        STIG ID    : UBTU-24-900190
        Rule ID    : SV-270790r1068380_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 57E78C51F8EB14C907DEC89FE3D67831
        FixMD5     : C2E6358E62A42D7FB217886FFF3DAFEC
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chsh)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chsh ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chsh[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chsh' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chsh' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chsh' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270791 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270791
        STIG ID    : UBTU-24-900200
        Rule ID    : SV-270791r1066862_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 866624F90B1B980AAE01D64EBBF36EFD
        FixMD5     : F094BE5B3135AFB128FE6ADF9EEAF13C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s newgrp)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/newgrp ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/newgrp[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'newgrp' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'newgrp' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'newgrp' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270792 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270792
        STIG ID    : UBTU-24-900210
        Rule ID    : SV-270792r1066865_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : BE530D81AFBB935D2960217F3D150726
        FixMD5     : EF5D46D859242BCA09104A82E59585AA
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chcon)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chcon ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chcon[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chcon' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chcon' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chcon' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270793 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270793
        STIG ID    : UBTU-24-900220
        Rule ID    : SV-270793r1066868_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 51999832D68B2D4508B0D6BAC058C717
        FixMD5     : AA52203BD1D5DB7170F23DCB2BB1A091
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s apparmor_parser)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/sbin/apparmor_parser ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/sbin\/apparmor_parser[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'apparmor_parser' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'apparmor_parser' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'apparmor_parser' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270794 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270794
        STIG ID    : UBTU-24-900230
        Rule ID    : SV-270794r1066871_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 05FF6B8C4B41A742B79C09263FAE3AB2
        FixMD5     : BD97B036E3A827F54042A8461339827D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s setfacl)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/setfacl ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/setfacl[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'setfacl' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'setfacl' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'setfacl' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270795 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270795
        STIG ID    : UBTU-24-900240
        Rule ID    : SV-270795r1066874_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : F76F0DA2CB52B19ECDD1DFABD240FAC1
        FixMD5     : B634CB78DE70066D5D3AA70932578899
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chacl)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chacl ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chacl[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chacl' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chacl' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chacl' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270796 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270796
        STIG ID    : UBTU-24-900250
        Rule ID    : SV-270796r1066877_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for the use and modification of faillog file.
        DiscussMD5 : 5EDDC99EDDED33E960646109F3E38199
        CheckMD5   : 00BF3D0D93D32099E0AF334EFEC8ADFF
        FixMD5     : EECFFF375B96208D3FC89E272868379C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s faillog)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/faillog[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful modifications to the 'faillog' file occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when successful/unsuccessful modifications to the 'faillog' file occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270797 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270797
        STIG ID    : UBTU-24-900260
        Rule ID    : SV-270797r1066880_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for the use and modification of the lastlog file.
        DiscussMD5 : 5EDDC99EDDED33E960646109F3E38199
        CheckMD5   : F501FEB38E4DABBE77B9BC5131B240B5
        FixMD5     : 0F825D873DB7EE4D4E9900E2B380C36D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s lastlog)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/lastlog[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful modifications to the 'lastlog' file occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when successful/unsuccessful modifications to the 'lastlog' file occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270798 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270798
        STIG ID    : UBTU-24-900270
        Rule ID    : SV-270798r1068382_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 8A7C889405A4D8B0A6902A39C3C8FF4A
        FixMD5     : 06CFCE0963E4B03ED3EF318826784B21
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w passwd)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/passwd ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/passwd[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'passwd' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'passwd' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'passwd' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270799 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270799
        STIG ID    : UBTU-24-900280
        Rule ID    : SV-270799r1066886_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 425190D42CA4BE44061C83249F42FCD7
        FixMD5     : F9627D26DA126CB614B228D7CE77729F
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w unix_update)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/sbin/unix_update ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/sbin\/unix_update[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'unix_update' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'unix_update' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'unix_update' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270800 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270800
        STIG ID    : UBTU-24-900290
        Rule ID    : SV-270800r1066889_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 7DCC5A120CE3A5EFBFC377CEC57D1F89
        FixMD5     : 3CBC9BF10D677CDCFBE2AB4713152330
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w gpasswd)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/gpasswd ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/gpasswd[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'gpasswd' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'gpasswd' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'gpasswd' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270801 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270801
        STIG ID    : UBTU-24-900300
        Rule ID    : SV-270801r1066892_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the chage command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : D74AF7343DF76EE010474D24230747A7
        FixMD5     : 7E8B51B230F010000DB4D924FEF888F0
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w chage)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chage ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chage[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chage' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chage' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chage' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270802 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270802
        STIG ID    : UBTU-24-900310
        Rule ID    : SV-270802r1066895_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : F1EFAE6F7787BE3DBA67E4B014E36349
        FixMD5     : C2F34980663D3136029F9B85E36B56FC
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w usermod)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/sbin/usermod ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/sbin\/usermod[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'usermod' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'usermod' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'usermod' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270803 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270803
        STIG ID    : UBTU-24-900320
        Rule ID    : SV-270803r1066898_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 36FFF286933AD1CAFDE508F7EB6F5DBF
        FixMD5     : B5F20F8EDE8734A7F64FB1D62F534CFB
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w crontab)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/crontab ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/crontab[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'crontab' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'crontab' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'crontab' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270804 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270804
        STIG ID    : UBTU-24-900330
        Rule ID    : SV-270804r1066901_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : C71862F1971366A381E8C476EFB8F546
        FixMD5     : C05F3A6458BE0C72D7AD2C933DF2BE9B
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w pam_timestamp_check)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/sbin/pam_timestamp_check ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/sbin\/pam_timestamp_check[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'pam_timestamp_check' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'pam_timestamp_check' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'pam_timestamp_check' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270805 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270805
        STIG ID    : UBTU-24-900340
        Rule ID    : SV-270805r1068384_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls.
        DiscussMD5 : 3065EBD8B86F0BC939829FC1A3A338AE
        CheckMD5   : 3C545D103BBC4F23FA9C71D042103970
        FixMD5     : 9ED96A586FDB2819DB6D4514ED57658E
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w init_module)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+init_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+init_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+finit_module[\s]+|([\s]+|[,])finit_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+finit_module[\s]+|([\s]+|[,])finit_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'init_module,finit_module' commands occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'init_module,finit_module' system calls."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270806 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270806
        STIG ID    : UBTU-24-900350
        Rule ID    : SV-270806r1068386_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module syscall.
        DiscussMD5 : 8CA3AC6A2721CCB69F16AA786252C4B6
        CheckMD5   : 485F0805C9291B55B01CF437D128E284
        FixMD5     : 23B5011548B3B96A9E52C3CAEB6B94A6
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | egrep -s delete_module)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (
                (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])delete_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                    ) -and (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])delete_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                )
            ) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'delete_module' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'delete_module' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'delete_module' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270807
        STIG ID    : UBTU-24-900510
        Rule ID    : SV-270807r1066910_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000466-GPOS-00210
        Rule Title : Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur.
        DiscussMD5 : 791D2283E612D7149273FFE3ECFF02D6
        CheckMD5   : F87E144BBD95198820525BE5DD0B3DD7
        FixMD5     : 017FF2C4BDA86B3FC4E4DDB3F152EA23
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s "sudoers ")
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/sudoers[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record for all modifications that affect '/etc/sudoers'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for all modifications that affect '/etc/sudoers'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270808 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270808
        STIG ID    : UBTU-24-900520
        Rule ID    : SV-270808r1067100_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000466-GPOS-00210
        Rule Title : Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.
        DiscussMD5 : 791D2283E612D7149273FFE3ECFF02D6
        CheckMD5   : 0FDAC16F68740DC75F880AB6EF44A80D
        FixMD5     : B09CD43931C4289806B7A27517C1C1F7
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s sudoers.d)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/sudoers.d[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record for all modifications that affect '/etc/sudoers.d' directory."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for all modifications that affect '/etc/sudoers.d' directory."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270809
        STIG ID    : UBTU-24-900540
        Rule ID    : SV-270809r1068388_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000468-GPOS-00212
        Rule Title : Ubuntu 24.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.
        DiscussMD5 : 734D2D3E62B91B89BBDADD9B1B6E4A98
        CheckMD5   : 97AAE304C9683A8DDFAF7F3D8F0F9ECD
        FixMD5     : 71629A7DB5EE8E9A8C81AA7252C14A54
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -i "unlink\|rename\|rmdir")
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+renameat[\s]+|([\s]+|[,])renameat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+renameat[\s]+|([\s]+|[,])renameat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rmdir[\s]+|([\s]+|[,])rmdir([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rmdir[\s]+|([\s]+|[,])rmdir([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+unlink[\s]+|([\s]+|[,])unlink([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+unlink[\s]+|([\s]+|[,])unlink([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+unlinkat[\s]+|([\s]+|[,])unlinkat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+unlinkat[\s]+|([\s]+|[,])unlinkat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'unlink,unlinkat,rename,renameat,rmdir' commands occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'unlink,unlinkat,rename,renameat,rmdir' system calls."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270810
        STIG ID    : UBTU-24-900590
        Rule ID    : SV-270810r1066919_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000472-GPOS-00217
        Rule Title : Ubuntu 24.04 LTS must generate audit records for the /var/log/wtmp file.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : BEF4946FFCDDAA23E7B1751DDF3453CA
        FixMD5     : 55DB9DAB8905F7A6B7EE13C0CAFE88CF
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/var/log/wtmp')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/wtmp[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/log/wtmp."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records showing start and stop times for user access to the system via /var/log/wtmp."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270811 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270811
        STIG ID    : UBTU-24-900600
        Rule ID    : SV-270811r1066922_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000472-GPOS-00217
        Rule Title : Ubuntu 24.04 LTS must generate audit records for the /var/run/utmp file.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 87983332605BB533673686BBC573E81D
        FixMD5     : F91BAD674B880901D5909520EC560661
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/var/run/utmp')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/run\/utmp[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/run/utmp."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records showing start and stop times for user access to the system via /var/run/utmp."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270812
        STIG ID    : UBTU-24-900610
        Rule ID    : SV-270812r1066925_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000472-GPOS-00217
        Rule Title : Ubuntu 24.04 LTS must generate audit records for the /var/log/btmp file.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 86ACF1934C291BAEB69C7B1753854EBC
        FixMD5     : ECAA6AD3F47A485A90B4096FFC13649D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/var/log/btmp')
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/btmp[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/log/btmp."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records showing start and stop times for user access to the system via /var/log/btmp."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270813 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270813
        STIG ID    : UBTU-24-900730
        Rule ID    : SV-270813r1066928_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use modprobe command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 279C17DF297FD70823FA99F91067E4C0
        FixMD5     : BE6CDF6550FD2975215B534C0665B949
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -i "/sbin/modprobe")
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/sbin\/modprobe[\s]+)(?:-p[\s]+x[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the '/sbin/modprobe' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the '/sbin/modprobe' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the '/sbin/modprobe' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270814 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270814
        STIG ID    : UBTU-24-900740
        Rule ID    : SV-270814r1066931_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use the kmod command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 6F872B9CDB7768381D9D81BF14B6B9F8
        FixMD5     : F0B791A2840B6318FBB8645365A3D9BC
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s kmod)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/bin\/kmod[\s]+)(?:-p[\s]+x[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'kmod' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'kmod' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'kmod' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270815 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270815
        STIG ID    : UBTU-24-900750
        Rule ID    : SV-270815r1066934_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use the fdisk command.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 6126B338686806F9CA02A5C6C0FDC7C9
        FixMD5     : D9F700C58B60880283897234A726C71E
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s fdisk)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/usr\/sbin\/fdisk[\s]+)(?:-p[\s]+x[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'fdisk' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'fdisk' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'fdisk' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270816 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270816
        STIG ID    : UBTU-24-900920
        Rule ID    : SV-270816r1066937_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-OS-000341-GPOS-00132
        Rule Title : Ubuntu 24.04 LTS must allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
        DiscussMD5 : 05A6321C8DE140A885403DABEC744128
        CheckMD5   : 98B75F4D7ADA6D46F49115385819413C
        FixMD5     : 63AB305BC010DE0AA77A6DC705FE7A6D
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
    $finding = $(grep -s -i ^[[:blank:]]*log_file /etc/audit/auditd.conf)
    $finding ??= "Check text: No results found."

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $finding_2 = $(df -h $dirname)
    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "Check the size of the partition ($dirname) that audit records are written to."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270817 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270817
        STIG ID    : UBTU-24-900950
        Rule ID    : SV-270817r1066940_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : Ubuntu 24.04 LTS must have a crontab script running weekly to offload audit events of standalone systems.
        DiscussMD5 : 00FF23A4F2024F2CDF319F03B049F332
        CheckMD5   : 47C73F4384C16060785F5234034103D5
        FixMD5     : 7A3D73D076B00D49678398DE92AF66ED
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
    $finding = $(ls /etc/cron.weekly)

    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "There is a script in the /etc/cron.weekly directory but must be verified it does offloading of audit logs to external media"
    }
    else {
        $STatus = "Open"
        $FindingMessage = "The script file does not exist."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270818 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270818
        STIG ID    : UBTU-24-900960
        Rule ID    : SV-270818r1066943_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : Ubuntu 24.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
        DiscussMD5 : 0DF0177AAF60F082FAA4CD9600573FF3
        CheckMD5   : E24BC1371CC602536478D33458EA1433
        FixMD5     : 5BDE82BDE7167853EAB475D78DA705C2
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
    $finding = $(grep -s -i ^[[:blank:]]*space_left_action /etc/audit/auditd.conf)
    $finding_2 = $(grep -s -i "^[[:blank:]]*space_left " /etc/audit/auditd.conf) #differentiate between space_left = and space_left_action
    $finding_3 = $(grep -s action_mail_acct /etc/audit/auditd.conf)

    $finding ??= "Check text: No results found."
    $finding_2 ??= "Check text: No results found."
    $finding_3 ??= "Check text: No results found."

    switch -Wildcard ($finding.ToLower()) {
        "*email" {
            $FindingMessage = "The 'space_left_action' is set to 'email'."
            $FindingMessage += "`r`n"
            if ($finding_3) {
                $FindingMessage += "The email address is $finding_3 and should be the e-mail address of the system administrator(s) and/or ISSO."
                $FindingMessage += "`r`n"
                $FindingMessage += "Note: If the email address of the system administrator is on a remote system a mail package must be available."
                $FindingMessage += "`r`n"
            }
            elseif ($finding_3.contains("root")) {
                $FindingMessage += "The email defaults to root."
                $FindingMessage += "`r`n"
            }
            else {
                $FindingMessage += "The email address missing."
                $FindingMessage += "`r`n"
            }
        }
        "*exec" {
            $FindingMessage = "The 'space_left_action' is set to 'exec'."
            $FindingMessage += "`r`n"
            $FindingMessage += "The system executes a designated script. If this script informs the SA of the event."
            $FindingMessage += "`r`n"
        }
        "*syslog" {
            $FindingMessage = "The 'space_left_action' is set to 'syslog'."
            $FindingMessage += "`r`n"
            $FindingMessage += "The system logs the event, but does not generate a notification."
            $FindingMessage += "`r`n"
        }
    }

    If ((($Finding_2.ToLower()).startswith("space_left")) -and ((($Finding_2 | awk '{$2=$2};1').replace(" ","")).split("=")[1] -eq "25%")) {
        $FindingMessage += "$finding_2 is at least 25% of the space free in the allocated audit record storage."
    }
    else {
        $FindingMessage += "The 'space_left' parameter is missing or not equal to 25%."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String

    $Status = "Not_Reviewed"
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

Function Get-V270819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270819
        STIG ID    : UBTU-24-900980
        Rule ID    : SV-270819r1068390_rule
        CCI ID     : CCI-000139
        Rule Name  : SRG-OS-000046-GPOS-00022
        Rule Title : Ubuntu 24.04 LTS must alert the system administrator (SA) and information system security officer (ISSO) (at a minimum) in the event of an audit processing failure.
        DiscussMD5 : 002D4B408C1DF9505021F5507D35C9BA
        CheckMD5   : AC2FFEC756B8A416F4265FAC7CFF0CB1
        FixMD5     : F52A532B8769843B0C869E8BDDC23DB6
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
    $finding = $(grep -s -i ^[[:blank:]]*action_mail_acct /etc/audit/auditd.conf)

    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are notified in the event of an audit processing failure."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified in the event of an audit processing failure."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270820
        STIG ID    : UBTU-24-901220
        Rule ID    : SV-270820r1066949_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-OS-000359-GPOS-00146
        Rule Title : Ubuntu 24.04 LTS must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
        DiscussMD5 : ADA729A41386340F8F75BB126BF42FD8
        CheckMD5   : 67320BEDC94979176245581C8292D378
        FixMD5     : 51A436D9BFD3BFD3483857A7C58D377B
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
    $finding = $(timedatectl status | grep -s -i "time zone")
    $finding ??= "Check text: No results found."

    if ($Finding.ToUpper() -match "UTC") {
        $Status = "NotAFinding"
        $FindingMessage = "The time zone is configured to use Coordinated Universal Time (UTC)."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The time zone is not configured to use Coordinated Universal Time (UTC)."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270821
        STIG ID    : UBTU-24-901230
        Rule ID    : SV-270821r1068391_rule
        CCI ID     : CCI-001493, CCI-001494
        Rule Name  : SRG-OS-000257-GPOS-00098
        Rule Title : Ubuntu 24.04 LTS must configure audit tools with a mode of "0755" or less permissive.
        DiscussMD5 : 1236BD922AA09CD7F05D4C8BF38EF4D1
        CheckMD5   : 6B91869957CDDF96AFF3C57E193E69BC
        FixMD5     : 98EF410F849D7F3D4F30D204D08D4438
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
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd*", "/sbin/augenrules")
    $incorrect_message_count = 0

    $audit_tools | ForEach-Object {
        $finding = $(stat -c "%n %a" $_)

        if ((CheckPermissions -FindPath $_ -MinPerms 755) -eq $false) {
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $incorrect_message_count++
        }
    }
    if ($incorrect_message_count -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The audit tools are protected from unauthorized access, deletion, or modification."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit tools are protected from unauthorized access, deletion, or modification."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails | Out-String
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

Function Get-V270822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270822
        STIG ID    : UBTU-24-901240
        Rule ID    : SV-270822r1068392_rule
        CCI ID     : CCI-001493, CCI-001494
        Rule Name  : SRG-OS-000257-GPOS-00098
        Rule Title : Ubuntu 24.04 LTS must configure audit tools to be owned by root.
        DiscussMD5 : 1236BD922AA09CD7F05D4C8BF38EF4D1
        CheckMD5   : E75644B41AA55A510E68B7C74180E06E
        FixMD5     : 0909413CE4057A54579542EA02A8B3FA
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
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd", "/sbin/augenrules")
    $correct_message_count = 0

    $audit_tools | ForEach-Object {
        $finding = $(stat -c "%n %U" $_)
        $FindingDetails += $(FormatFinding $finding) | Out-String

        if ($finding -eq "$_ root") {
            $correct_message_count++
        }
    }
    if ($correct_message_count -eq $audit_tools.Count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the audit tools to be owned by root to prevent any unauthorized access, deletion, or modification."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not configure the audit tools to be owned by root to prevent any unauthorized access, deletion, or modification."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails | Out-String
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

Function Get-V270823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270823
        STIG ID    : UBTU-24-901250
        Rule ID    : SV-270823r1068393_rule
        CCI ID     : CCI-001493, CCI-001494
        Rule Name  : SRG-OS-000257-GPOS-00098
        Rule Title : Ubuntu 24.04 LTS must configure the audit tools to be group-owned by root.
        DiscussMD5 : 1236BD922AA09CD7F05D4C8BF38EF4D1
        CheckMD5   : 9D67A1369C22AB71646DD651F1390B15
        FixMD5     : B82B738C67E165053223C2E804B9843F
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
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd", "/sbin/augenrules")
    $correct_message_count = 0

    $audit_tools | ForEach-Object {
        $finding = $(stat -c "%n %G" $_)
        $FindingDetails += $(FormatFinding $finding) | Out-String

        if ($finding -eq "$_ root") {
            $correct_message_count++
        }
    }
    if ($correct_message_count -eq $audit_tools.Count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the audit tools to be group-owned by root to prevent any unauthorized access, deletion, or modification."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not configure the audit tools to be group-owned by root to prevent any unauthorized access, deletion, or modification."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails | Out-String
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

Function Get-V270824 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270824
        STIG ID    : UBTU-24-901260
        Rule ID    : SV-270824r1066961_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-OS-000258-GPOS-00099
        Rule Title : Ubuntu 24.04 LTS must have directories that contain system commands set to a mode of "0755" or less permissive.
        DiscussMD5 : B57F827F6151B1967387DD1F159A7D8E
        CheckMD5   : 4B9D59048BE730F63E8265AF04948F31
        FixMD5     : 35F83B7384EF98EF2F6A31A41AF9413E
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -perm /022 -type d -exec stat -c "%n %a" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $finding | ForEach-Object {
        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands directories have mode 0755 or less permissive:"
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system commands directories do not have mode 0755 or less permissive:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) do not have mode 0755 or less permissive."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270825 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270825
        STIG ID    : UBTU-24-901270
        Rule ID    : SV-270825r1066964_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-OS-000258-GPOS-00099
        Rule Title : Ubuntu 24.04 LTS must have directories that contain system commands owned by root.
        DiscussMD5 : B57F827F6151B1967387DD1F159A7D8E
        CheckMD5   : 90F791341422AAAC998FAC6757013F6C
        FixMD5     : 0A27FE96D5DF45815358C7CCA1447561
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270826 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270826
        STIG ID    : UBTU-24-901280
        Rule ID    : SV-270826r1066967_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-OS-000258-GPOS-00099
        Rule Title : Ubuntu 24.04 LTS must have directories that contain system commands group-owned by root.
        DiscussMD5 : B57F827F6151B1967387DD1F159A7D8E
        CheckMD5   : 2696061B71D9043CDBED160FCCC361DE
        FixMD5     : 56D362ACE8957083E1511664A15DA7A8
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' +
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not group-owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are group-owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270827 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270827
        STIG ID    : UBTU-24-901300
        Rule ID    : SV-270827r1066970_rule
        CCI ID     : CCI-000162, CCI-000163
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Ubuntu 24.04 LTS must be configured so that audit log files are not read or write-accessible by unauthorized users.
        DiscussMD5 : 4298E514FFFD83A0F9AC721E5290D1FE
        CheckMD5   : F7EF8B4832108AA883420E510F6CD4C6
        FixMD5     : 0E2BE5DC66E68F3D22356D239B47F6BD
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding ??= "Check text: No results found."

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $finding_2 = $(stat -c "%n %a" $dirname)
    if ($finding) {
        if ((($finding_2 | Select-String (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -le 600) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files have a mode of '0600' or less permissive."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log files do not have a mode of '0600' or less permissive."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270828 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270828
        STIG ID    : UBTU-24-901310
        Rule ID    : SV-270828r1066973_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Ubuntu 24.04 LTS must be configured to permit only authorized users ownership of the audit log files.
        DiscussMD5 : 46DDB695BE245D63A72A189EA426DC31
        CheckMD5   : 6E4020B577CA5D27042B613E1300F46A
        FixMD5     : 8984D66CB466E1453C264EA774710C21
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding ??= "Check text: No results found."

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $finding_2 = $(stat -c "%n %U" $dirname)
    if ($finding) {
        if ((($finding_2 | Select-String (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files are owned by 'root' account."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log files are owned by 'root' account."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270829 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270829
        STIG ID    : UBTU-24-901350
        Rule ID    : SV-270829r1066976_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Ubuntu 24.04 LTS must permit only authorized groups ownership of the audit log files.
        DiscussMD5 : 46DDB695BE245D63A72A189EA426DC31
        CheckMD5   : 277EF5E74CB25A18CFD64992B0D49B0A
        FixMD5     : 668BFAB896D367CD8D335E698D681E10
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding ??= "Check text: No results found."

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $finding_2 = $(stat -c "%n %G" $dirname)
    if ($finding) {
        if ((($finding_2 | Select-String (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270830 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270830
        STIG ID    : UBTU-24-901380
        Rule ID    : SV-270830r1068397_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-OS-000059-GPOS-00029
        Rule Title : Ubuntu 24.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users.
        DiscussMD5 : 8D3F4EAD67C9D91E64F6B9305A1EDEBC
        CheckMD5   : 731CF7EA6289277AE8D690838A868137
        FixMD5     : DE1103211EAB4DF19402CBD77DFA9226
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding_2 = ""

    if ($finding) {
        $dirname = dirname $finding.replace(" ", "").split("=")[1]
        $finding_2 = $(stat -c "%n %a" $dirname)
        $better_finding_2 = $(CheckPermissions -FindPath $dirname -MinPerms 750 -Type Directory -Recurse)

        if ($better_finding_2 -eq $True) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory has a mode of '0750' or less permissive."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log directory has a mode of '0750' or less permissive."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270831 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270831
        STIG ID    : UBTU-24-90890
        Rule ID    : SV-270831r1066982_rule
        CCI ID     : CCI-001496
        Rule Name  : SRG-OS-000278-GPOS-00108
        Rule Title : Ubuntu 24.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.
        DiscussMD5 : A4A2BBC685622D736EECD1322436B8F9
        CheckMD5   : 07E26592FAE3854E285929E3BE2EDF5A
        FixMD5     : D877917E55A5AF68ECCD6A633D9CC42E
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
    $finding = $(egrep -s '(\/sbin\/(audit|au))' /etc/aide/aide.conf)
    $finding ??= "Check text: No results found."
    $audit_tools = @("/sbin/auditctl", "/sbin/auditd", "/sbin/ausearch", "/sbin/aureport", "/sbin/autrace", "/sbin/audispd", "/sbin/augenrules")
    $missing_audit_tools = @()
    $correct_message_count = 0

    $audit_tools | ForEach-Object {
        if ($finding -match "$_\s+p\+i\+n\+u\+g\+s\+b\+acl\+xattrs\+sha512") {
            $correct_message_count++
        }
        else {
            $missing_audit_tools += $_
        }
    }

    if ($correct_message_count -eq $audit_tools.count) {
        $Status = "NotAFinding"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is not properly configured to use cryptographic mechanisms to protect the integrity of audit tools."
        $FindingMessage += "`r`n"
        $FindingMEssage += "Missing audit tools - $missing_audit_tools"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V270832 {
    <#
    .DESCRIPTION
        Vuln ID    : V-270832
        STIG ID    : UBTU-24-909000
        Rule ID    : SV-270832r1068399_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-OS-000058-GPOS-00028
        Rule Title : Ubuntu 24.04 LTS audit system must protect auditing rules from unauthorized change.
        DiscussMD5 : 3091A031AB2C48BED50126C769E013A8
        CheckMD5   : 01D88187C37B3DCD43B6C581B786D6F7
        FixMD5     : D9772935F993AE8201B96B46B8EBF298
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
    $finding = $(grep -I -s -i "^\s*[^#]" /etc/audit/audit.rules | tail -1)
    $finding ??= "Check text: No results found."

    If (($Finding | awk '{$2=$2};1').ToLower() -eq "-e 2") {
        $Status = "NotAFinding"
        $FindingMessage = "The audit system prevents unauthorized changes."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit system does not prevent unauthorized changes."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V274868 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274868
        STIG ID    : UBTU-24-300020
        Rule ID    : SV-274868r1107313_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu 24.04 LTS must require users to provide a password for privilege escalation.
        DiscussMD5 : 514E6ED475CA5FD1089FC02C7D9E2D29
        CheckMD5   : A98DB027E1B26DBDDAA3AAA412CF9D59
        FixMD5     : B7D26350102F3E38CB05E18261772E8F
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
    $finding = $(grep -I -s -iR nopasswd /etc/sudoers /etc/sudoers.d/)
    $commented = 0

    If ($finding) {
        $finding | ForEach-Object {
            If (($_.split(":")[1]).StartsWith("#")) {
                $commented++
            }
        }

        if ($finding.count -ne $commented) {
            $Status = "Open"
            $FindingMessage = "The operating system does not require users to supply a password for privilege escalation."
        }
        else {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system requires users to supply a password for privilege escalation."
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires users to supply a password for privilege escalation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V274869 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274869
        STIG ID    : UBTU-24-300019
        Rule ID    : SV-274869r1107312_rule
        CCI ID     : CCI-002038, CCI-004895
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : Ubuntu 24.04 LTS must restrict privilege elevation to authorized personnel.
        DiscussMD5 : 459D912DB3DBAD8F8A2E8770C2183D12
        CheckMD5   : 89C673900062C4D19313E4C3E43E17DF
        FixMD5     : 7728FE228E46BBE44BFE1827DC3BF11D
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
    $finding = $(grep -I -s -iwr 'ALL' /etc/sudoers /etc/sudoers.d/)
    $found = 0

    If ($finding) {
        $finding | ForEach-Object {
            If (((($_ | awk '{$2=$2};1').split(":")[1]) -eq "ALL ALL=(ALL) ALL") -or ((($_ | awk '{$2=$2};1').split(":")[1]) -eq "ALL ALL=(ALL:ALL) ALL")) {
                $found++
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'sudoers' file restricts sudo access to authorized personnel."
    }

    if ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "The 'sudoers' file does not restrict sudo access to authorized personnel."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'sudoers' file restricts sudo access to authorized personnel."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V274870 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274870
        STIG ID    : UBTU-24-200270
        Rule ID    : SV-274870r1107304_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000471-GPOS-00215
        Rule Title : Ubuntu 24.04 LTS must audit any script or executable called by cron as root or by any privileged user.
        DiscussMD5 : B3264A9F74B797E04C7F62AC8F0E97B5
        CheckMD5   : 0384FB7BCC06B216B01EC7548C2F7E7E
        FixMD5     : D98AB2560BA2B392646DE2848918630C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep /etc/cron.d)
        $finding ??= "Check text: No results found."
        $finding_2 = $(auditctl -l | grep /var/spool/cron)
        $finding_2 ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w") -and ($finding_2 | awk '{$2=$2};1').StartsWith("-w")) {
            if ((($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/cron.d[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and
                (($finding_2 | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/spool\/cron[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$')){
                $Status = "NotAFinding"
                $FindingMessage = "The operating system is configured to audit the execution of any system call made by cron as root or as any privileged user."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system is not configured to audit the execution of any system call made by cron as root or as any privileged user."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system is not configured to audit the execution of any system call made by cron as root or as any privileged user."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V274871 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274871
        STIG ID    : UBTU-24-200043
        Rule ID    : SV-274871r1107302_rule
        CCI ID     : CCI-000060
        Rule Name  : SRG-OS-000031-GPOS-00012
        Rule Title : Ubuntu 24.04 LTS must conceal, via the session lock, information previously visible on the display with a publicly viewable image.
        DiscussMD5 : 1ECE3A0A3498E8AEE63D3E7D0AF1141C
        CheckMD5   : 2D14270829DFD27B38234D1155885037
        FixMD5     : 35D30041908A9D5F749B1FF30DF0486C
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."

    if ($finding.Contains("gdm3")) {
        $finding = $(gsettings writable org.gnome.desktop.screensaver picture-uri)
        $finding ??= "Check text: No results found."

        if ($finding -eq "false") {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system screensaver is configured to be blank."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system screensaver is not configured to be blank."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V274872 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274872
        STIG ID    : UBTU-24-200041
        Rule ID    : SV-274872r1107297_rule
        CCI ID     : CCI-000778, CCI-001958
        Rule Name  : SRG-OS-000114-GPOS-00059
        Rule Title : Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user interface autorun function.
        DiscussMD5 : 3893A41D09C176AEFB0350BBC7755E91
        CheckMD5   : C78491FBBBA77D8A74EAFEA914DFE1E7
        FixMD5     : CDF600643E6A2E7F273B02FD680FCAA2
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."

    if ($finding.Contains("gdm3")) {
        $finding = $(gsettings writable org.gnome.desktop.media-handling autorun-never)
        $finding ??= "Check text: No results found."

        if ($finding -eq "false") {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system disables the ability of the user to override the graphical user interface autorun setting."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not disable the ability of the user to override the graphical user interface autorun setting."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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

Function Get-V274873 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274873
        STIG ID    : UBTU-24-200042
        Rule ID    : SV-274873r1107300_rule
        CCI ID     : CCI-000056, CCI-000057, CCI-000058
        Rule Name  : SRG-OS-000028-GPOS-00009
        Rule Title : Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user smart card removal action.
        DiscussMD5 : 0C1FF983079358ECA6783BCABB85FDED
        CheckMD5   : 6D1FA5674EC61FA7FED7247657EA6669
        FixMD5     : FD6B172E88A0E02C659F13FFB3239157
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ??= "Check text: No results found."

    if ($finding.Contains("gdm3")) {
        $finding = $(gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action)
        $finding ??= "Check text: No results found."

        if ($finding -eq "false") {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system disables the ability of the user to override the smart card removal action setting."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not disable the ability of the user to override the smart card removal action setting."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTz7iPoueu6/gK
# 7AvcVNITsOAPqJgmt4YrHLQQFNFGe6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDn6rzDr2tMrMZWXxWvdaMu54B0o8/gTi8mnC80SLbgkDANBgkqhkiG9w0BAQEF
# AASCAQBQheRi848rFmvXdrCkQXAEP2WhIQGyWbby7FcEC91MkqoB96OQEVtGXMrd
# Sy38FFYr9px5YoR234S6rpnUewLM1J/Pi/c1k0Z05medG+mYhMIK7QHgCzdCnI61
# c6yudMb17SL+GRzBxQ3LZG6E6rkR6BZEdfXA0Yo+jXjB5uIzbHWYNH1P2qPM/DCY
# +K5lWYHGmmPkyq8+IQzYYsRufZktajwtb5D1mawe5R02eCVW3LF4mklivG1KqMCq
# 2wv71BlUfMPLWe2MCLKiXCfUgbexpN46KAKgwB4wRzIM9y5tCVBQL6LRcdMEwUAh
# 3QLhi895togohec6S9chexn7dCy/oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTA1MVowLwYJKoZIhvcNAQkEMSIEIKyqTGzxfLOm33oXIfrbC+xXkJs9
# SsqCXKoFbtNcOfwpMA0GCSqGSIb3DQEBAQUABIICALEJJ8EMlBA7SbDRrDJ8EBgr
# PyrGOFdc1lanj1ttigRfV8UOVS+L4GTxI+q+JpkiepRqBzYx+XL2P48GcfORFi/d
# VZJyUtkX/iA9FcbzVuiBJ+qrYco4BgKTKSv3U03dkFSPOCwdGokg7PtJNH1RglzD
# TlL0gZtuP+9/tT7gE9aJ5j8h+aAnhY3Drt53lxHpzr0/CVDcP0HmWQHxvYxmZC02
# cd1xzfuZFBTklFEVpx/5FNEBm+QSQUfErqrUy6elcBNoxzFiBRXEQemnA5Urdk6+
# 4r55BoaHxmEE5jIkw5b7srYC9MUMcAeN78Ip/oZTdLJq3W0OGwaVXAkxup8A54vK
# QK/s19dvO1qyNBeH7mN6NGOXXCxcrIi7UKNxvSy3W2AXttsfiUXqnny1ixDTN/3l
# pPqIl+DlB8XIaqzjJfTFdomEDj/0ABXjkWTKY/TS7wc1RM2xzOVpLpyOh+G/Tw61
# xAGpVMKNcTBQQyS5pM9wVxzoBGcii4OD5ArL9wtTv7737hebvZaQX9fOGFUKa3Qv
# dciE2Pc3WKFEuEpu0co0NzN+ShXiowTckFTOnOhJ9wcml9id6SzjJ4x4gbLkpL0N
# OoVGCvFexfAUofhqp26FTnOK8FBFHt/Byz66KCeEedlYBuCMorKtJpjE7djKpK1t
# 3qM18tLS11mwkI0Gsd36
# SIG # End signature block
