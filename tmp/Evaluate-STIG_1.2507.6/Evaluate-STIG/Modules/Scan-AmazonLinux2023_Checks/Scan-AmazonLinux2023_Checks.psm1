##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Amazon Linux 2023
# Version:  V1R1
# Class:    UNCLASSIFIED
# Updated:  09/18/2025
# Author:   Naval Sea Systems Command (NAVSEA)
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

Function Get-V273995 {
    <#
    .DESCRIPTION
        Vuln ID    : V-273995
        STIG ID    : AZLX-23-000110
        Rule ID    : SV-273995r1119973_rule
        CCI ID     : CCI-003992
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : Amazon Linux 2023 must ensure cryptographic verification of vendor software packages.
        DiscussMD5 : DBC3243CEA924541C11B1CC5E8B1EE48
        CheckMD5   : 41AE9EFE6C6F05FECF0E368BDD7D68F9
        FixMD5     : 320980D9BEBA739A0467967B899A9DB8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
	$fingerprints = @('B21C 50FA 44A9 9720 EAA7  2F7F E951 904A D832 C631')

	$finding = $(rpm -q --queryformat '%{SUMMARY}\n' gpg-pubkey | grep -i -I -s 'Amazon Linux')
    $finding_2 = ""


    if ($finding){
        $keyfile = "/etc/pki/rpm-gpg/RPM-GPG-KEY-amazon-linux-2023"

        if (Test-Path $keyfile){
            $finding_2 = $(gpg -q --keyid-format short --with-fingerprint $keyfile 2>/dev/null | grep -v "gpg: out of core handler ignored in FIPS mode" | awk '{if($2=="fingerprint")fp=$0;if($1=="uid"){print $0;print fp}}')
            if (((($finding_2 | awk "/Key fingerprint/ {getline;print}").split("=")[1].trim()) -in $fingerprints)){
                $Status = "NotAFinding"
                $FindingMessage = "Amazon Linux package-signing keys are installed on the system, the keyfile exists and key fingerprints match."
            }
            else{
                $Status = "Open"
                $FindingMessage = "Amazon Linux package-signing keys are installed on the system, the keyfile exists but the key fingerprints do not match."
            }
        }
        else{
            $Status = "Open"
            $FindingMessage = "Amazon Linux package-signing keys are installed on the system but the keyfile is missing."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "Amazon Linux package-signing keys are not installed on the system."
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

Function Get-V273996 {
    <#
    .DESCRIPTION
        Vuln ID    : V-273996
        STIG ID    : AZLX-23-000115
        Rule ID    : SV-273996r1119976_rule
        CCI ID     : CCI-003992
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : Amazon Linux 2023 must check the GPG signature of locally installed software packages before installation.
        DiscussMD5 : 9B41462F96859266A065EAA0D5F1DC47
        CheckMD5   : 484D442175616EBFAD4A9D35F3B8A0DD
        FixMD5     : 4A5C78F764C70A4C64F3FAB77A5C54B9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*localpkg_gpgcheck /etc/dnf/dnf.conf)
    $finding ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq "1") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization."
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

Function Get-V273997 {
    <#
    .DESCRIPTION
        Vuln ID    : V-273997
        STIG ID    : AZLX-23-000120
        Rule ID    : SV-273997r1119979_rule
        CCI ID     : CCI-003992
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : Amazon Linux 2023 must check the GPG signature of software packages originating from external software repositories before installation.
        DiscussMD5 : 9B41462F96859266A065EAA0D5F1DC47
        CheckMD5   : 06E132911543DBA48FCED9D3484F4DA2
        FixMD5     : EA0768CE70C109804BC6317D529EE08B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*gpgcheck /etc/dnf/dnf.conf)
    $finding ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq "1") {
        $Status = "NotAFinding"
        $FindingMessage = "'dnf' always checks the GPG signature of software packages originating from external software repositories before installation."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "'dnf' does not always checks the GPG signature of software packages originating from external software repositories before installation."
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

Function Get-V273998 {
    <#
    .DESCRIPTION
        Vuln ID    : V-273998
        STIG ID    : AZLX-23-000125
        Rule ID    : SV-273998r1119982_rule
        CCI ID     : CCI-003992
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : Amazon Linux 2023 must have GPG signature verification enabled for all software repositories.
        DiscussMD5 : 9B41462F96859266A065EAA0D5F1DC47
        CheckMD5   : C6DAAE17CDF9871599F738E7983679FF
        FixMD5     : 7D657208AD5910EEBDAC9BD7D9FDD399
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s gpgcheck /etc/yum.repos.d/*.repo)
    $better_finding = $(grep -I -s ^gpgcheck /etc/yum.repos.d/*.repo)
    $found = 0

    $better_finding | ForEach-Object{
        if (((($_ | awk '{$2=$2};1').replace(" ","")).split("=")[1] -ne "1")){
            $FindingMessage += $_
            $found++
        }
    }

    if ($found -eq 0){
        $Status = "NotAFinding"
    }
    else{
        $Status = "Open"
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

Function Get-V273999 {
    <#
    .DESCRIPTION
        Vuln ID    : V-273999
        STIG ID    : AZLX-23-000130
        Rule ID    : SV-273999r1119985_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-OS-000439-GPOS-00195
        Rule Title : Amazon Linux 2023 must be a vendor-supported release.
        DiscussMD5 : 8F6A0FBC4C4E893EE4DD642AD400F6F2
        CheckMD5   : 861AB95D0D8B93C7EFDC8829B127CD50
        FixMD5     : C6F063ABCEA4A6EBDE2197F36FDCA5E9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/amazon-linux-release)

    $Status = "Not_Reviewed"
    $FindingMessage = "Check if the release is not supported by the vendor."

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

Function Get-V274000 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274000
        STIG ID    : AZLX-23-000135
        Rule ID    : SV-274000r1119988_rule
        CCI ID     : CCI-001665
        Rule Name  : SRG-OS-000269-GPOS-00103
        Rule Title : Amazon Linux 2023 systemd-journald service must be enabled.
        DiscussMD5 : FCC2FFFD3E1AB05787664EE579255BFB
        CheckMD5   : 95EC5596B9E12F1BBEA2F7022C03AC3C
        FixMD5     : 4051E93DAAD4673D9AB8D445D6A54413
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $service = "systemd-journald"
    $finding = $(systemctl is-active $service)

    if ($finding -eq "active"){
        $Status = "NotAFinding"
        $FindingMessage = "The '$service' service is active."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '$service' service is not active."
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

Function Get-V274001 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274001
        STIG ID    : AZLX-23-000200
        Rule ID    : SV-274001r1119991_rule
        CCI ID     : CCI-001082, CCI-001090
        Rule Name  : SRG-OS-000132-GPOS-00067
        Rule Title : Amazon Linux 2023 must restrict access to the kernel message buffer.
        DiscussMD5 : 29AB7FAED6F9E6FB8048A5C278F0A48E
        CheckMD5   : 1D7866E039FCF06861F02745AF54B41B
        FixMD5     : A28C737FB9EC135EADA551A35C799F65
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is configured to restrict access to the kernel message buffer."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to restrict access to the kernel message buffer."
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

Function Get-V274002 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274002
        STIG ID    : AZLX-23-000205
        Rule ID    : SV-274002r1119994_rule
        CCI ID     : CCI-001082, CCI-001090
        Rule Name  : SRG-OS-000132-GPOS-00067
        Rule Title : Amazon Linux 2023 must prevent kernel profiling by nonprivileged users.
        DiscussMD5 : 5817E1BB1C8230181F5DB35DFC1D2412
        CheckMD5   : 90D027D72F73A37857907BB1D6326B11
        FixMD5     : C89D0F78677D68B1D1A10F284C15143A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl kernel.perf_event_paranoid)
    $finding ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 2) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is configured to prevent kernel profiling by unprivileged users."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to prevent kernel profiling by unprivileged users."
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

Function Get-V274003 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274003
        STIG ID    : AZLX-23-000210
        Rule ID    : SV-274003r1119997_rule
        CCI ID     : CCI-001082, CCI-002824
        Rule Name  : SRG-OS-000132-GPOS-00067
        Rule Title : Amazon Linux 2023 must restrict exposed kernel pointer addresses access.
        DiscussMD5 : 7A8E1C27D06F2C892903C37CFF9AF53D
        CheckMD5   : 8C8D4F2F1672DCD84B7A53FD6F698CB9
        FixMD5     : D058139631A521D602211457187E0B44
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl kernel.kptr_restrict)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -in 1..2){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system restricts exposed kernel pointer addresses access."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not restrict exposed kernel pointer addresses access."
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

Function Get-V274004 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274004
        STIG ID    : AZLX-23-000215
        Rule ID    : SV-274004r1120000_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-OS-000132-GPOS-00067
        Rule Title : Amazon Linux 2023 must disable access to network bpf system call from nonprivileged processes.
        DiscussMD5 : 578916B47FC66F654A45E1AF551CC2DD
        CheckMD5   : 0423703F8EEC7081BA3B84EEA76163B1
        FixMD5     : 1E632E8ACAB75DEF504227E398CF602F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl kernel.unprivileged_bpf_disabled)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system prevents privilege escalation thru the kernel by disabling access to the bpf syscall."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent privilege escalation thru the kernel by disabling access to the bpf syscall."
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

Function Get-V274005 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274005
        STIG ID    : AZLX-23-000220
        Rule ID    : SV-274005r1120003_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-OS-000132-GPOS-00067
        Rule Title : Amazon Linux 2023 must restrict usage of ptrace to descendant processes.
        DiscussMD5 : A7B2F583414542C2C43E765AA1E0CB02
        CheckMD5   : DD56541917DCC51494B3DE2C1C2A89CF
        FixMD5     : 5BCE5167D06C7BE06DC380D8805AC0DE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl kernel.yama.ptrace_scope)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system restricts usage of ptrace to descendant processes."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not restrict usage of ptrace to descendant processes."
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

Function Get-V274006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274006
        STIG ID    : AZLX-23-000225
        Rule ID    : SV-274006r1120006_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00193
        Rule Title : Amazon Linux 2023 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.
        DiscussMD5 : F6B643231CCDF15E9513CC396586C63D
        CheckMD5   : 932950396119CA99B13DC6526EE79C8B
        FixMD5     : 24EFD24DEC994592530C978FEC72AEB9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $finding ??= "Check text: No results found."
    $finding_2 = $(/usr/lib/systemd/systemd-sysctl --cat-config | egrep -I -v '^(#|;)' |  grep -I -F kernel.randomize_va_space | tail -1)
    $finding_2 ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 2) {
        If ((($finding_2 | awk '{$2=$2};1').replace(" ", "")).split("=")[1] -eq 2) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system implements ASLR."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system does not implement ASLR."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not implement ASLR."
    }

    $FindingDetails += $FindingMessage | Out-String

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

Function Get-V274007 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274007
        STIG ID    : AZLX-23-000300
        Rule ID    : SV-274007r1120009_rule
        CCI ID     : CCI-000197, CCI-000381
        Rule Name  : SRG-OS-000074-GPOS-00042
        Rule Title : Amazon Linux 2023 must not have the vsftpd package installed.
        DiscussMD5 : 8810D588C785216C9697049653551F8B
        CheckMD5   : F4A301BEA0845F0F0791A84E053774CF
        FixMD5     : C2C10ED11DA7E07E8DF4954363DEC3A9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "vsftpd"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "Open"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274008
        STIG ID    : AZLX-23-000305
        Rule ID    : SV-274008r1120012_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : Amazon Linux 2023 must not have the sendmail package installed.
        DiscussMD5 : 7E1E96BC14D353F504A28CEE44FF3799
        CheckMD5   : 0DE6AA4BD7EEE57ED2AF181A2647139D
        FixMD5     : 3074551847067198D1870633E693A2D9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "sendmail"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "Open"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274009 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274009
        STIG ID    : AZLX-23-000310
        Rule ID    : SV-274009r1120015_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : Amazon Linux 2023 must not have the nfs-utils package installed.
        DiscussMD5 : 7E1E96BC14D353F504A28CEE44FF3799
        CheckMD5   : B13BD00C9176ABC88DE6279885F1B507
        FixMD5     : 89D6C7951F16FE40AEAF3E17780C882C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "nfs-utils"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "Open"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274010 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274010
        STIG ID    : AZLX-23-000315
        Rule ID    : SV-274010r1120018_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : Amazon Linux 2023 must not have the telnet-server package installed.
        DiscussMD5 : 7E1E96BC14D353F504A28CEE44FF3799
        CheckMD5   : BA840D98310A6FBF91FC6FA04A9234CF
        FixMD5     : EB7F39D60AD3975217622BF89D3A102E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "telnet-server"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "Open"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274011 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274011
        STIG ID    : AZLX-23-000320
        Rule ID    : SV-274011r1120021_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : Amazon Linux 2023 must not have the gssproxy package installed.
        DiscussMD5 : F142E637722A270F4CD415A038305287
        CheckMD5   : 3A87A989F3E2B09CC10A1DEADB7271C4
        FixMD5     : 32315A71B9D1D59510B41460C9DC2DBD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "gssproxy"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "Open"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274012 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274012
        STIG ID    : AZLX-23-001000
        Rule ID    : SV-274012r1120710_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-OS-000324-GPOS-00125
        Rule Title : Amazon Linux 2023 must have the sudo package installed.
        DiscussMD5 : F26D1C29A70CB2C3F817F692A34643B6
        CheckMD5   : 8AB3E8D4EF6851E2166B51FE3E2715A6
        FixMD5     : A270A4F493A8D3197E118A56B0D831BC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "sudo"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274013 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274013
        STIG ID    : AZLX-23-001005
        Rule ID    : SV-274013r1120027_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-OS-000312-GPOS-00123
        Rule Title : Amazon Linux 2023 must not be configured to bypass password requirements for privilege escalation.
        DiscussMD5 : 4AA3C290D831983FAD07477113A598E1
        CheckMD5   : 34CD79DF6418FE8299C34E1FAFC1416A
        FixMD5     : 83DF4B64C020A7040219A14DFCB5AFE8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i pam_succeed_if /etc/pam.d/sudo)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The operating system is configured to bypass password requirements for privilege escalation."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is not configured to bypass password requirements for privilege escalation."
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

Function Get-V274014 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274014
        STIG ID    : AZLX-23-001010
        Rule ID    : SV-274014r1120030_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00157
        Rule Title : Amazon Linux 2023 must require reauthentication when using the "sudo" command.
        DiscussMD5 : 9E21F3B909D0320A72047C3B782D7D9E
        CheckMD5   : 33A3BD452091CAFE016560F79FE244E9
        FixMD5     : 8DDA8D30437A3B75A0368E1179271143
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -iR 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/)
    $foundcount = 0

    $finding | Foreach-Object {
        If ((($_.split(":"))[1]).ToLower().StartsWith("defaults") -and ([int]((($_ | awk '{$2=$2};1').replace(" ","").split("="))[1]).replace('"','') -ge 0)) {
            $foundcount++
        }
    }

    if (($foundcount -gt 0) -and ($foundcount -eq $finding.count)){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires re-authentication when using the 'sudo' command to elevate privileges."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not require re-authentication when using the 'sudo' command to elevate privileges."
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

Function Get-V274015 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274015
        STIG ID    : AZLX-23-001015
        Rule ID    : SV-274015r1120033_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : Amazon Linux 2023 must require users to reauthenticate for privilege escalation.
        DiscussMD5 : 9E21F3B909D0320A72047C3B782D7D9E
        CheckMD5   : A73BAB51827D1C71DABA7B693239A484
        FixMD5     : D838027B1E0BDA7CA8057AE8D0896CA0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V274016 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274016
        STIG ID    : AZLX-23-001020
        Rule ID    : SV-274016r1120036_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Amazon Linux 2023 must require users to provide a password for privilege escalation.
        DiscussMD5 : 9E21F3B909D0320A72047C3B782D7D9E
        CheckMD5   : 7C192C1E41F43AEA8F722909D788B16D
        FixMD5     : DFDD0A463B0ED0D08FA138A74BFCAA90
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V274017 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274017
        STIG ID    : AZLX-23-001025
        Rule ID    : SV-274017r1120039_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000154, CCI-000158, CCI-000159, CCI-000169, CCI-000172, CCI-001464, CCI-001487, CCI-001875, CCI-001876, CCI-001877, CCI-001878, CCI-001879, CCI-001880, CCI-001881, CCI-001882, CCI-001889, CCI-001914, CCI-002884, CCI-003938
        Rule Name  : SRG-OS-000062-GPOS-00031
        Rule Title : Amazon Linux 2023 must have the audit package installed.
        DiscussMD5 : F0557A63B480B13AE364B311EB3F139E
        CheckMD5   : 19B4C29C0F8E24DAECFE20570D88E17A
        FixMD5     : ACF156B58F345548F0DB15F4FBD6B07F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "audit"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274018 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274018
        STIG ID    : AZLX-23-001030
        Rule ID    : SV-274018r1120042_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000154, CCI-000158, CCI-000169, CCI-000172, CCI-001464, CCI-001487, CCI-001875, CCI-001876, CCI-001877, CCI-001878, CCI-001879, CCI-001880, CCI-001881, CCI-001882, CCI-001889, CCI-001914, CCI-002884, CCI-003938, CCI-004188
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must produce audit records containing information to establish what type of events occurred.
        DiscussMD5 : D6B7228D2B5EAAC543D888C08EEA6FBB
        CheckMD5   : 1B0A84D7F7ADDE5BB7321D79549F6036
        FixMD5     : BFCEAAD8CD445EBEAD0F0008E3E5B28E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl status auditd.service)

    If ($finding -match "Active: active \(running\)") {
        $Status = "NotAFinding"
        $FindingMessage = "The audit service is configured to produce audit records."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit service is not configured to produce audit records."
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

Function Get-V274019 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274019
        STIG ID    : AZLX-23-001035
        Rule ID    : SV-274019r1120045_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : Amazon Linux 2023 audispd-plugins package must be installed.
        DiscussMD5 : 52AFEFAACFD0763EAD177136589998A0
        CheckMD5   : E30040E42707F611F042604F6388ACA6
        FixMD5     : 4AA7DE46BBCC45801979A9D286F82EC4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "audispd-plugins"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274020 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274020
        STIG ID    : AZLX-23-001040
        Rule ID    : SV-274020r1120048_rule
        CCI ID     : CCI-000154, CCI-001851
        Rule Name  : SRG-OS-000051-GPOS-00024
        Rule Title : Amazon Linux 2023 must have the rsyslog package installed.
        DiscussMD5 : 92154FBEC07E37CFF9A5431699A491E8
        CheckMD5   : 23438896770C97E6EC000D8F152447B5
        FixMD5     : 93372912F8530E3C59268BA959229471
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "rsyslog"
    $finding = $(dnf list --installed $package)
    $finding_2 = $(systemctl is-enabled $package)

    if ($finding -match $package -and $finding_2 -eq "enabled"){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed or the service is not enabled."
    }

    $FindingMessage = "`r`n"
    $FindingMessage = "NOTE: Check text has the incorrect command to validate the rsyslog service is enabled.  Evaluate-STIG is using 'systemctl is-enabled rsyslog' to determine if service is enabled."

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

Function Get-V274021 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274021
        STIG ID    : AZLX-23-001045
        Rule ID    : SV-274021r1120695_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000032-GPOS-00013
        Rule Title : Amazon Linux 2023 must monitor remote access methods.
        DiscussMD5 : 9C635EF12ECD9269F24D2E2334EF7BFE
        CheckMD5   : C507CCB39B5F6F115C0572D0D260C413
        FixMD5     : 11AB9CEDD99C7E2446B3512339F88324
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -iR -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf /etc/rsyslog.d/)

    if ($finding){
        $better_finding = $(grep -I -s -i "/var/log/secure" /etc/rsyslog.conf | grep -I -v "#")
        $authfound = $authprivfound = $daemonfound = $false

        $better_finding | Foreach-Object {
            if ($_ -match "auth.`*"){
                $authfound = $true
            }
            if ($_ -match "authpriv.`*"){
                $authprivfound = $true
            }
            if ($_ -match "daemon.`*"){
                $daemonfound = $true
            }
        }

        if ($authfound -and $authprivfound -and $daemonfound){
            $Status = "NotAFinding"
            $FindingMessage = "The operating system monitors all remote access methods."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system does not monitor all remote access methods."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not monitor all remote access methods."
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

Function Get-V274022 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274022
        STIG ID    : AZLX-23-001050
        Rule ID    : SV-274022r1120054_rule
        CCI ID     : CCI-004923
        Rule Name  : SRG-OS-000355-GPOS-00143
        Rule Title : Amazon Linux 2023 must have the chrony package installed.
        DiscussMD5 : 12688CEFCCFA8CA66D026CA6D97642FC
        CheckMD5   : F003F6D85872A8E5976A9DBDB01072C9
        FixMD5     : 80504F4ED418FB430C4321818E228C6A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "chrony"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274023 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274023
        STIG ID    : AZLX-23-001055
        Rule ID    : SV-274023r1120057_rule
        CCI ID     : CCI-004923
        Rule Name  : SRG-OS-000355-GPOS-00143
        Rule Title : Amazon Linux 2023 chronyd service must be enabled.
        DiscussMD5 : 12688CEFCCFA8CA66D026CA6D97642FC
        CheckMD5   : C21E995ABAF524162AC2344BE49726FB
        FixMD5     : 4CE23AE8ED6395D307D9798DAE06080E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $service = "chronyd"
    $finding = $(systemctl is-active $service)

    if ($finding -eq "active"){
        $Status = "NotAFinding"
        $FindingMessage = "The '$service' service is active."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '$service' service is not active."
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

Function Get-V274024 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274024
        STIG ID    : AZLX-23-001060
        Rule ID    : SV-274024r1120060_rule
        CCI ID     : CCI-001744, CCI-001889, CCI-002696
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : Amazon Linux 2023 must have the Advanced Intrusion Detection Environment (AIDE) package installed.
        DiscussMD5 : 3242BA89DA8100462658A68B952D82D2
        CheckMD5   : 0945EE4DA2DE2B125B2A7B95B7F5DDFC
        FixMD5     : 3B0D21323C9B0DBBFAAE7D173B1C066F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "aide"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $finding_2 = $(/usr/sbin/aide --check)

        if ($finding_2 -eq "Couldn't open file /var/lib/aide/aide.db.gz for reading"){
            $Status = "Open"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed but has not been initialized."
        }
        else{
            $Status = "NotAFinding"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed and initialized."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is not installed."
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

Function Get-V274025 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274025
        STIG ID    : AZLX-23-001065
        Rule ID    : SV-274025r1120723_rule
        CCI ID     : CCI-001744, CCI-002699, CCI-002702
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : Amazon Linux 2023 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.
        DiscussMD5 : 318F46D194DBFB2183A0548B6B9B1BA7
        CheckMD5   : 0773115AACCAF9532E8E86D8814D66C0
        FixMD5     : D0FCFDC1A24FF6CAA6A254C751A20538
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)
    $finding_2 = $(grep "aide --check" /etc/crontab /etc/cron.*/* /var/spool/cron/root)

    if ($Finding) {
        if ($finding_2) {
            $cron_daily = $(grep -H "aide --check" /etc/cron.daily/*)
            if ($cron_daily){
                $FindingMessage = "AIDE is installed and AIDE Check is executed from cron daily."
            }
            $cron_weekly = $(grep -H "aide --check" /etc/cron.weekly/*)
            if ($cron_weekly){
                $FindingMessage = "AIDE is installed and AIDE Check is executed from cron weekly."
            }
            $cron_monthly = $(grep -H "aide --check" /etc/cron.monthly/*)
            if ($cron_monthly) {
                $FindingMessage = "AIDE is installed; however, AIDE Check is executed from cron monthly."
            }
            if ($cron_daily -or $cron_weekly){
                $Status = "NotAFinding"
            }
            else{
                $cron_check = $(grep -H "aide --check" /etc/crontab /etc/cron.d/*)
                if ($cron_check) {
                    $cronrun = $($finding_2 | awk '{if($3$4=="**") print $5 ; else print "F"}')
                    if ($cronrun -eq "F") {
                        $Status = "Open"
                        $FindingMessage = "AIDE is installed; however, AIDE Check is NOT executed at least weekly."
                    }
                    elseif ($cronrun -eq '*') {
                        $Status = "NotAFinding"
                        $FindingMessage = "AIDE is installed and AIDE Check is executed from cron daily."
                    }
                    else {
                        $Status = "NotAFinding"
                        $FindingMessage = "AIDE is installed and AIDE Check is executed from cron weekly."
                    }
                }
            }

            if (($finding_2 | grep -I -s -i "mail") -and $(rpm -qa s-nail)) {
                $FindingMessage += "  The SA is notified via eMail."
            }
            else {
                $Status = "Open"
                $FindingMessage += "  The SA is NOT notified via eMail."
            }

       }
       else {
           $FindingMessage = "AIDE is installed; however, it is NOT executed from cron. Ask the SA how file integrity checks are performed on the system."
       }
    }
    else {
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
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

Function Get-V274026 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274026
        STIG ID    : AZLX-23-001070
        Rule ID    : SV-274026r1120066_rule
        CCI ID     : CCI-001493, CCI-001494, CCI-001495, CCI-001496
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : Amazon Linux 2023 must use cryptographic mechanisms to protect the integrity of audit tools.
        DiscussMD5 : 195EFA5FD818DA402E5A96C6B261B78C
        CheckMD5   : E0FDAE952470EE23849A7B6FE666D048
        FixMD5     : AFF176316A47825033B1AEBAA8570C9E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)

    If ($Finding) {
        $finding = $(egrep -I -s '(\/usr\/sbin\/au)' /etc/aide.conf)
        $finding ??= "Check text: No results found."

        $selections = "p+i+n+u+g+s+b+acl+xattrs+sha512"
        if ((($finding | awk '{$2=$2};1').ToLower() -contains "/usr/sbin/auditctl $selections") -and (($finding | awk '{$2=$2};1').ToLower() -contains "/usr/sbin/auditd $selections") -and (($finding | awk '{$2=$2};1').ToLower() -contains "/usr/sbin/ausearch $selections") -and (($finding | awk '{$2=$2};1').ToLower() -contains "/usr/sbin/aureport $selections") -and (($finding | awk '{$2=$2};1').ToLower() -contains "/usr/sbin/autrace $selections") -and (($finding | awk '{$2=$2};1').ToLower() -contains "/usr/sbin/augenrules $selections")){
            $Status = "NotAFinding"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools."
        }
        else{
            $Status = "Open"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is not properly configured to use cryptographic mechanisms to protect the integrity of audit tools."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
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

Function Get-V274027 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274027
        STIG ID    : AZLX-23-001075
        Rule ID    : SV-274027r1120069_rule
        CCI ID     : CCI-000015, CCI-000366, CCI-000382, CCI-002314, CCI-002322
        Rule Name  : SRG-OS-000096-GPOS-00050
        Rule Title : Amazon Linux 2023 must have the firewalld package installed.
        DiscussMD5 : D3E95FC93CAC2892438D6AEC44EE5C7E
        CheckMD5   : BD32E2F58FA9A69834A12392BE99CCA1
        FixMD5     : 8DFB25E5177D988FEBFF2C413ABAE35A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "firewalld"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274028 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274028
        STIG ID    : AZLX-23-001080
        Rule ID    : SV-274028r1120072_rule
        CCI ID     : CCI-000015, CCI-000366, CCI-000382, CCI-002314, CCI-002322
        Rule Name  : SRG-OS-000096-GPOS-00050
        Rule Title : Amazon Linux 2023 must have the firewalld servicew active.
        DiscussMD5 : 2A5AE452480EF8AA3F0E08BBC61696B3
        CheckMD5   : BBEDA7458DBE7D0EFF56861426A175CB
        FixMD5     : 9BBD437A2267034A5338960220857B74
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $service = "firewalld"
    $finding = $(systemctl is-active $service)

    if ($finding -eq "active"){
        $Status = "NotAFinding"
        $FindingMessage = "The '$service' service is active."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '$service' service is not active."
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

Function Get-V274029 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274029
        STIG ID    : AZLX-23-001085
        Rule ID    : SV-274029r1120075_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : Amazon Linux 2023 must be configured to disable nonessential capabilities.
        DiscussMD5 : F142E637722A270F4CD415A038305287
        CheckMD5   : 11EDB30EA8EA782C8EAF0E713BA53B32
        FixMD5     : A170BE93AD303CFCC60E0BB1CAF7A36E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa firewalld)

    if ($finding) {
        $finding = $(firewall-cmd --list-all-zones | grep -e "active" -e "services")

        $Status = "Not_Reviewed"
        $FindingMessage = "Inspect the firewall configuration and running services to verify it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have an enabled application firewall."
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

Function Get-V274030 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274030
        STIG ID    : AZLX-23-001090
        Rule ID    : SV-274030r1120078_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-OS-000142-GPOS-00071
        Rule Title : Amazon Linux 2023 must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks.
        DiscussMD5 : 921AE2B537EF68FF53CCBD0BD9D8275C
        CheckMD5   : E76150BA82801963D49CD2BB481B15EF
        FixMD5     : 2163EAFEABC95F61C53F4BEF3C58B5B9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*firewallbackend /etc/firewalld/firewalld.conf)
    $finding ??= "Check text: No results found."

    If ((($finding | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "nftables") {
        $Status = "NotAFinding"
        $FindingMessage = "'nftables' is configured to allow rate limits on any connection to the system."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "'nftables' is not configured to allow rate limits on any connection to the system."
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

Function Get-V274031 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274031
        STIG ID    : AZLX-23-001095
        Rule ID    : SV-274031r1120081_rule
        CCI ID     : CCI-001744
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : Amazon Linux 2023 must have the s-nail package installed.
        DiscussMD5 : 3258B4353B234EAF305D6AFD7FE78889
        CheckMD5   : D87997F0D18AAE30E3F0E62C4D2BF1CD
        FixMD5     : FC3DD4445EA6BC82C0064B4175EB644B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "s-nail"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274032 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274032
        STIG ID    : AZLX-23-001105
        Rule ID    : SV-274032r1120084_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-OS-000120-GPOS-00061
        Rule Title : Amazon Linux 2023 must have the libreswan package installed.
        DiscussMD5 : C2456A69F322EAFA7A9D26BE86B7034B
        CheckMD5   : 2DB80640A5E93BFA97EDD25277B36AA4
        FixMD5     : 49A0D8D6ACA18ADFB5B7DBE30CC8EA8B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "libreswan"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274033 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274033
        STIG ID    : AZLX-23-001110
        Rule ID    : SV-274033r1120087_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-OS-000134-GPOS-00068
        Rule Title : Amazon Linux 2023 must have the policycoreutils package installed.
        DiscussMD5 : AC13946B327525C26C8FDC3EB26F8820
        CheckMD5   : 8AA274DBDC36B700D402E0358E30523E
        FixMD5     : CD0EBE871C867B2D85D6CA4AC9B52BD7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "policycoreutils"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274034 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274034
        STIG ID    : AZLX-23-001115
        Rule ID    : SV-274034r1120090_rule
        CCI ID     : CCI-004046
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : Amazon Linux 2023 must have the pcsc-lite package installed.
        DiscussMD5 : AC14F8E7579A7F91869ED8F927E753D0
        CheckMD5   : 471650C8AEE25F6D8E8AC7521913EDE9
        FixMD5     : 82677514D84E18E8AB3228501826326A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "pcsc-lite"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274035 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274035
        STIG ID    : AZLX-23-001120
        Rule ID    : SV-274035r1120093_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-OS-000120-GPOS-00061
        Rule Title : Amazon Linux 2023 must have the packages required for encrypting off-loaded audit logs installed.
        DiscussMD5 : DEAD0AC74FBDE6EFD4B2F8A5F0EF36DD
        CheckMD5   : A34F1D44BDB70FAB037947EEE54F0459
        FixMD5     : 91B9EEBFECC05F66B8F4E5DA6DCCE47A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "rsyslog-openssl"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274036 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274036
        STIG ID    : AZLX-23-001125
        Rule ID    : SV-274036r1120096_rule
        CCI ID     : CCI-001953, CCI-004046
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : Amazon Linux 2023 must have the opensc package installed.
        DiscussMD5 : DC61E118258AE4926A9F292A89AB289C
        CheckMD5   : 8AC99744F51E9DEDD7335FDC293CE91E
        FixMD5     : 1CA77FFAA99123E4E7544F203FE4B2F9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "opensc"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274037 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274037
        STIG ID    : AZLX-23-001130
        Rule ID    : SV-274037r1120099_rule
        CCI ID     : CCI-001953, CCI-001954, CCI-004046
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : Amazon Linux 2023 must have the openssl-pkcs11 package installed.
        DiscussMD5 : 57B86BA80880A8757B7358A7E56A70BF
        CheckMD5   : A77694DD91AD19AEAD3BD3CDD4FC2A67
        FixMD5     : B0D79AECA46ECC3E4ABEFDB72813C044
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "openssl-pkcs11"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274038 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274038
        STIG ID    : AZLX-23-001180
        Rule ID    : SV-274038r1120102_rule
        CCI ID     : CCI-001941, CCI-002418, CCI-002420, CCI-002421, CCI-002422
        Rule Name  : SRG-OS-000112-GPOS-00057
        Rule Title : Amazon Linux 2023 must have SSH installed.
        DiscussMD5 : EF6AD0C22709C4ABDD9B40C58ED20724
        CheckMD5   : B25808489B872C69E2B5D50D48ECBCE0
        FixMD5     : 5E33C10196076801D15CD0E643F6040C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "openssh-server"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274039 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274039
        STIG ID    : AZLX-23-001185
        Rule ID    : SV-274039r1120105_rule
        CCI ID     : CCI-001941, CCI-002418, CCI-002420, CCI-002421, CCI-002422
        Rule Name  : SRG-OS-000112-GPOS-00057
        Rule Title : Amazon Linux 2023 must implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.
        DiscussMD5 : 0F5B24277C197664DFEC2A66EE306E93
        CheckMD5   : EEEC927B826E42C900111CC51E681F88
        FixMD5     : D4EB774938E7766DE82F3AE31ABD6256
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $service = "sshd"
    $finding = $(systemctl is-active $service)

    if ($finding -eq "active"){
        $Status = "NotAFinding"
        $FindingMessage = "The '$service' service is active."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '$service' service is not active."
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

Function Get-V274040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274040
        STIG ID    : AZLX-23-001195
        Rule ID    : SV-274040r1120108_rule
        CCI ID     : CCI-002421, CCI-002450, CCI-002890, CCI-003123
        Rule Name  : SRG-OS-000396-GPOS-00176
        Rule Title : Amazon Linux 2023 must have the crypto-policies package installed.
        DiscussMD5 : A873A3EC3F80312E544CF53C1E8A0637
        CheckMD5   : 18EF605D45F770DDCBCD6689A2288468
        FixMD5     : ABD78262AB15D56CEFA3A4F6F93AAFA6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $package = "crypto-policies"
    $finding = $(dnf list --installed $package)

    if ($finding -match $package){
        $Status = "NotAFinding"
        $FindingMessage = "The $package package is installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The $package package is not installed."
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

Function Get-V274041 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274041
        STIG ID    : AZLX-23-001200
        Rule ID    : SV-274041r1120111_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Amazon Linux 2023 SSH server must be configured to use systemwide crypto policies.
        DiscussMD5 : 9E115F9A2692ADB4A8FEE2AF8BDCF042
        CheckMD5   : BED6039AD5EB955D0B5AA11703930536
        FixMD5     : 8B5B0AB2C2509110F9DD1AE503051DA7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*include /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $better_finding = $(grep -I -s -i ^[[:blank:]]*include /etc/ssh/sshd_config)
    $better_finding ??= "Check text: No results found."
    $better_finding_2 = $(Test-Path /etc/ssh/sshd_config.d/50-redhat.conf)

    if ((((($better_finding | awk '{$2=$2};1').ToLower()).split(" ")[1] -eq "/etc/ssh/sshd_config.d/*.conf") -or ((($better_finding | awk '{$2=$2};1').ToLower()).split(" ")[1] -eq "/etc/crypto-policies/back-ends/opensshserver.config")) -and $better_finding_2) {
        $Status = "NotAFinding"
        $FindingMessage = "System-wide crypto policies are in effect."
    }
    else {
        $Status = "Open"
        $FindingMessage = "System-wide crypto policies are in effect."
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

Function Get-V274042 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274042
        STIG ID    : AZLX-23-001205
        Rule ID    : SV-274042r1120114_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Amazon Linux 2023 server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-2/140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.
        DiscussMD5 : D56B0C77511D1DEF857A1EF623E7664C
        CheckMD5   : 537CCF5E850B3830DA8497775F37DBA0
        FixMD5     : F3C258116C08F8F252FCF0CBF50FD79E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ciphers /etc/crypto-policies/back-ends/opensshserver.config)
    $finding ??= "Check text: No results found."

    if ((((($finding | awk '{$2=$2};1').replace(" ","")).ToLower()) -eq "ciphersaes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr")){
        $Status = "NotAFinding"
        $FindingMessage = "SSH client is configured to use only ciphers employing FIPS 140-3 approved algorithms."
    }
    else{
        $Status = "Open"
        $FindingMessage = "SSH client is not configured to use only ciphers employing FIPS 140-3 approved algorithms."
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

Function Get-V274043 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274043
        STIG ID    : AZLX-23-001210
        Rule ID    : SV-274043r1120117_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Amazon Linux 2023 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2/140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.
        DiscussMD5 : C855A018010F496561C19928BD2291B2
        CheckMD5   : 702611BD353B28C738141563E053D6A1
        FixMD5     : 1930221F1384497EB75B6F7BF463A181
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i macs /etc/crypto-policies/back-ends/opensshserver.config)
    $finding ??= "Check text: No results found."

    if ((((($finding | awk '{$2=$2};1').replace(" ","")).ToLower()) -eq "macshmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512")){
        $Status = "NotAFinding"
        $FindingMessage = "SSH client is configured to use only ciphers employing FIPS 140-3 approved algorithms."
    }
    else{
        $Status = "Open"
        $FindingMessage = "SSH client is not configured to use only ciphers employing FIPS 140-3 approved algorithms."
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

Function Get-V274044 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274044
        STIG ID    : AZLX-23-001215
        Rule ID    : SV-274044r1120120_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-OS-000364-GPOS-00151
        Rule Title : Amazon Linux 2023 SSH daemon must not allow Generic Security Service Application Program Interface (GSSAPI) authentication.
        DiscussMD5 : 3A50408430EC1044C70718B4AF8E17A0
        CheckMD5   : E1C365851A102FD14A36E25A828657B5
        FixMD5     : 7E96BA753221AABFD682E3172737B4B0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "gssapiauthentication"
    $setting = "no"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        if ((($_ | awk '{$2=$2};1').ToLower()) -match "$option\s+$setting") {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon does not allow $option authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does allows $option authentication."
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

Function Get-V274045 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274045
        STIG ID    : AZLX-23-001220
        Rule ID    : SV-274045r1120123_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-OS-000364-GPOS-00151
        Rule Title : Amazon Linux 2023 SSH daemon must not allow Kerberos authentication.
        DiscussMD5 : D32FB0B3B053DF52C570EE755DFBF4EC
        CheckMD5   : A319CFB28B1CDC11115CFA8D9EA0734A
        FixMD5     : 563E69350970F3981251D13A087E057B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "kerberosauthentication"
    $setting = "no"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        if ((($_ | awk '{$2=$2};1').ToLower()) -match "$option\s+$setting") {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon does not allow $option authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does allows $option authentication."
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

Function Get-V274046 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274046
        STIG ID    : AZLX-23-001225
        Rule ID    : SV-274046r1120126_rule
        CCI ID     : CCI-000068, CCI-002418, CCI-002421
        Rule Name  : SRG-OS-000423-GPOS-00187
        Rule Title : Amazon Linux 2023 must force a frequent session key renegotiation for SSH connections to the server.
        DiscussMD5 : 665B11E1EB7846790C07CC0740730F16
        CheckMD5   : 7870A9950F047DDA5341457F3A559342
        FixMD5     : A243FF969E2BCAEBA68C58C7204EC39B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "rekeylimit"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        if ((($_ | awk '{$2=$2};1').split(" ")[1] -eq "1G") -and (($_ | awk '{$2=$2};1').split(" ")[2] -eq "1h")) {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH server is configured to force frequent session key renegotiation."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH server is not configured to force frequent session key renegotiation."
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

Function Get-V274047 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274047
        STIG ID    : AZLX-23-001230
        Rule ID    : SV-274047r1120129_rule
        CCI ID     : CCI-000765, CCI-000766
        Rule Name  : SRG-OS-000105-GPOS-00052
        Rule Title : Amazon Linux 2023 SSHD must accept public key authentication.
        DiscussMD5 : A1EB8C3EDD603218A7296FB15A94B270
        CheckMD5   : F52DDD48D069387E6E963A303642E785
        FixMD5     : D0DC8AD7A205095A4B8A9999C9E4F303
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "pubkeyauthentication"
    $setting = "yes"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        If ((($_ | awk '{$2=$2};1').ToLower()) -match "$option\s+$setting") {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon accepts public key encryption."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not accept public key encryption."
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

Function Get-V274048 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274048
        STIG ID    : AZLX-23-001235
        Rule ID    : SV-274048r1120132_rule
        CCI ID     : CCI-000366, CCI-000766
        Rule Name  : SRG-OS-000106-GPOS-00053
        Rule Title : Amazon Linux 2023 SSHD must not allow blank passwords.
        DiscussMD5 : AB113D36DC4D5902FE1436CBE3917794
        CheckMD5   : D07EE58709A61E1803BDE75626535860
        FixMD5     : A75BF357CA2F7B36DBAA46A4D2FADBB5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "permitEmptypasswords"
    $setting = "no"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        If ((($_ | awk '{$2=$2};1').ToLower()) -match "$option\s+$setting") {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "Remote access using SSH prevents logging on with a blank password."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Remote access using SSH does not prevent logging on with a blank password."
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

Function Get-V274049 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274049
        STIG ID    : AZLX-23-001240
        Rule ID    : SV-274049r1120135_rule
        CCI ID     : CCI-004045
        Rule Name  : SRG-OS-000109-GPOS-00056
        Rule Title : Amazon Linux 2023 must not permit direct logons to the root account using remote access via SSH.
        DiscussMD5 : B170F3CC48F0E2C6F95EEDD4C924249B
        CheckMD5   : 5127F4EC00A86AF09345FAE6654038B6
        FixMD5     : 11536E2158CDA7677317810D2D7EE02F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "permitrootlogin"
    $setting = "no"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        If ((($_ | awk '{$2=$2};1').ToLower()) -match "$option\s+$setting") {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "Remote access using SSH prevents users from logging on directly as root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Remote access using SSH does not prevent users from logging on directly as root."
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

Function Get-V274050 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274050
        STIG ID    : AZLX-23-001245
        Rule ID    : SV-274050r1120138_rule
        CCI ID     : CCI-001133, CCI-002361, CCI-002891
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : Amazon Linux 2023 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.
        DiscussMD5 : 598C9E6411A0A175A7F539DA3B05ED5D
        CheckMD5   : 97601428D98657A3B8786CA3A292B8B4
        FixMD5     : 5DC973C8E245E2B989CAE0310FE139A9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "clientaliveinterval"
    $setting = "600"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1] -le $setting) {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "All network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All network connections associated with SSH traffic are not automatically terminated at the end of the session or after 10 minutes of inactivity."
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

Function Get-V274051 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274051
        STIG ID    : AZLX-23-001250
        Rule ID    : SV-274051r1120141_rule
        CCI ID     : CCI-001133, CCI-002361
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : Amazon Linux 2023 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.
        DiscussMD5 : F495CB80512C053E61F8F1CAE630E631
        CheckMD5   : 6097F9DBE3D3B949E02EDE51D46E48AE
        FixMD5     : CCC13577AB1B7FBBFEDD037C26B864CF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "clientalivecountmax"
    $setting = "1"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1] -eq $setting) {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "All network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All network connections associated with SSH traffic are automatically are not terminated at the end of the session or after 10 minutes of inactivity."
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

Function Get-V274052 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274052
        STIG ID    : AZLX-23-001255
        Rule ID    : SV-274052r1120144_rule
        CCI ID     : CCI-000877
        Rule Name  : SRG-OS-000125-GPOS-00065
        Rule Title : Amazon Linux 2023 must enable the Pluggable Authentication Module (PAM) interface for SSHD.
        DiscussMD5 : 757035F4734914A55559A1CE08A90E12
        CheckMD5   : 68675B95E2B61F5C469AFFB576133F6E
        FixMD5     : 4009001C45FAF0610599FAD878E5A0AE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "usepam"
    $setting = "yes"

    $lines = $(grep -I -s -i ^[[:blank:]]*$option /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $lines ?? $($finding = "Check text: No results found." ;$FindingDetails += $(FormatFinding $finding) | Out-String)
    $correct_message_count = 0

    $lines | ForEach-Object {
        If ((($_ | awk '{$2=$2};1').ToLower()) -match "$option\s+$setting") {
            $correct_message_count++
        }

        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if (($correct_message_count -gt 0) -and ($correct_message_count -eq $lines.count)) {
        $Status = "NotAFinding"
        $FindingMessage = "SSHD is configured to allow for the $option interface."
    }
    else {
        $Status = "Open"
        $FindingMessage = "SSHD is not configured to allow for the $option interface."
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

Function Get-V274053 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274053
        STIG ID    : AZLX-23-001260
        Rule ID    : SV-274053r1120147_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Amazon Linux 2023 must implement DOD-approved encryption in the OpenSSL package.
        DiscussMD5 : 9E115F9A2692ADB4A8FEE2AF8BDCF042
        CheckMD5   : AC62B4C3FE6B42982C3CDC929EE6A241
        FixMD5     : 178EA1E125E99F6159C8C15D40C60574
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i opensslcnf.config /etc/pki/tls/openssl.cnf)

    if ($finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The OpenSSL library is configured to use only ciphers employing FIPS 140-2/140-3 approved algorithms."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The OpenSSL library is not configured to use only ciphers employing FIPS 140-2 approved algorithms."
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

Function Get-V274054 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274054
        STIG ID    : AZLX-23-001265
        Rule ID    : SV-274054r1120150_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : Amazon Linux 2023 must implement DOD-approved TLS encryption in the OpenSSL package.
        DiscussMD5 : 9E115F9A2692ADB4A8FEE2AF8BDCF042
        CheckMD5   : B655A2C8838A2D8C15F1D9D5AFCF4A0D
        FixMD5     : 33FB0AEB75E768757F263AD044A1DED5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config)
    $finding ??= "Check text: No results found."

    if ($finding){
        $finding = $(grep -I -s -i ^[[:blank:]]*TLS.MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config)
        $finding ??= "Check text: No results found."
        $finding_2 = $(grep -I -s -i ^[[:blank:]]*DTLS.MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config)
        $finding_2 ??= "Check text: No results found."

        If (((($finding | awk '{$2=$2};1').replace(" ", "").ToLower()).split("=")[1] -eq "tlsv1.2") -and ((($finding_2 | awk '{$2=$2};1').replace(" ", "").ToLower()).split("=")[1] -eq "dtlsv1.2")) {
            $Status = "NotAFinding"
            $FindingMessage = "The OpenSSL library is configured to use only DoD-approved TLS encryption."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The OpenSSL library is not configured to use only DoD-approved TLS encryption."
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

Function Get-V274055 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274055
        STIG ID    : AZLX-23-001270
        Rule ID    : SV-274055r1120153_rule
        CCI ID     : CCI-000803, CCI-002421, CCI-002450, CCI-002890, CCI-003123
        Rule Name  : SRG-OS-000120-GPOS-00061
        Rule Title : Amazon Linux 2023 must implement a FIPS 140-2/140-3 compliant systemwide cryptographic policy.
        DiscussMD5 : E4DFA98D986AF7C6333203AF0FA13419
        CheckMD5   : 9E07D2CC79D96DF7D3A9F0FC5C96D929
        FixMD5     : C33F6D8F7DE4045AC260E385879C2B92
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(update-crypto-policies --show)
    $finding_2 = ""
    $finding_3 = ""

    if ($finding.startswith("FIPS")){
        if (Test-Path "/etc/crypto-policies/policies/modules/REQUIRE.pmod"){
            $finding_2 = $(cat /etc/crypto-policies/policies/modules/REQUIRE.pmod)
        }
        $finding_3 = $(grep -I -s -i 'rsa_size\|hash' /etc/crypto-policies/state/CURRENT.pol)

        if ($finding -match "AD-SUPPORT" -or $finding -match "NO-ENFORCE-EMS"){
            $Status = "Not_Reviewed"
            $FindingMessage = "GnuTLS uses defined DOD-approved TLS Crypto Policy but includes AD-SUPPORT or NO-ENFORCE-EMS."
        }
        else{
            $hashes = "SHA2-256","SHA2-384","SHA2-512","SHA2-224","SHA3-256","SHA3-384","SHA3-512","SHAKE-256"
            $hashcheck = $(grep -I -s -i hash /etc/crypto-policies/state/CURRENT.pol)
            $hashcount = 0
            $hashvalue = 0
            $hashes | Foreach-Object {if ($hashcheck -match $_){$hashcount++}}
            ((($hashcheck | awk '{$2=$2};1').split("=")[1]).split(" ")) | Where-Object {$_ -ne " "} | Foreach-Object {
                if ($_ -ne "SHA2-224"){
                    if ([int]($_.split("-")[1] -lt 256) -and $_){
                        $hashvalue++
                    }
                }
            }

            $rsacheck = $(grep -I -s -i rsa_size /etc/crypto-policies/state/CURRENT.pol)

            if (([int]((($rsacheck | awk '{$2=$2};1').replace(" ","")).split("=")[1]) -ge 2048) -and ($hashvalue -lt 1) -and ($hashcount -eq $hashes.count)){
                $Status = "NotAFinding"
                $FindingMessage = "GnuTLS uses defined DOD-approved TLS Crypto Policy but has not been configured correctly."
            }
            else {
                $Status = "Open"
                $FindingMessage = "GnuTLS does not use defined DOD-approved TLS Crypto Policy but has not been configured correctly."
            }
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "GnuTLS does not use defined DOD-approved TLS Crypto Policy."
    }

    $FindingMessage += "`n"
    $FindingMessage += "'SHA2-224' was excluded from the check for less than 256 per DISA"

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

Function Get-V274056 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274056
        STIG ID    : AZLX-23-001275
        Rule ID    : SV-274056r1120156_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : Amazon Linux 2023 must implement DOD-approved encryption to protect the confidentiality of remote access sessions.
        DiscussMD5 : 7B0721842BCFCAAA52D6DD5F61C3AE37
        CheckMD5   : D58BE495084B4021D976ABED4F0E0B12
        FixMD5     : 0CD6EC8852D13344CA06A9DAC11F271F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ciphers /etc/crypto-policies/back-ends/opensshserver.config)
    $finding ??= "Check text: No results found."

    if ((((($finding | awk '{$2=$2};1').replace(" ","")).ToLower()) -eq "ciphersaes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr")){
        $Status = "NotAFinding"
        $FindingMessage = "SSH client is configured to use only ciphers employing FIPS 140-3 approved algorithms."
    }
    else{
        $Status = "Open"
        $FindingMessage = "SSH client is not configured to use only ciphers employing FIPS 140-3 approved algorithms."
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

Function Get-V274057 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274057
        STIG ID    : AZLX-23-001280
        Rule ID    : SV-274057r1120159_rule
        CCI ID     : CCI-000068, CCI-000877, CCI-002418, CCI-002450
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : Amazon Linux 2023 must enable FIPS mode.
        DiscussMD5 : 5D745031631E243A2C22B8192782C82C
        CheckMD5   : 350D08626B4D702920755F07A5DD99A0
        FixMD5     : EF5F7A129387986780BF68AB014F7A2D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(fips-mode-setup --check)

    if ($finding -match "enabled"){
        $Status = "NotAFinding"
        $FindingMessage = "FIPS mode is enabled."
    }
    else{
        $Status = "Open"
        $FindingMessage = "FIPS mode is not enabled."
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

Function Get-V274058 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274058
        STIG ID    : AZLX-23-001285
        Rule ID    : SV-274058r1120162_rule
        CCI ID     : CCI-000803, CCI-002421, CCI-002450, CCI-002890, CCI-003123, CCI-004062
        Rule Name  : SRG-OS-000396-GPOS-00176
        Rule Title : Amazon Linux 2023 crypto policy must not be overridden.
        DiscussMD5 : A8AE82354781CCE0B35107DA7DF8D000
        CheckMD5   : 3F16ADF28631DC328921E674A5A54D35
        FixMD5     : 0C631980191201C269772C8A8FF81227
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ls -l /etc/crypto-policies/back-ends/)
    $better_finding = $(ls -ld /etc/crypto-policies/back-ends/* | awk '{print $9, $11}')
    $correct_path = 0

    $better_finding | Foreach-Object {
        if ($_.split(" ")[1]){
            if ((Split-Path ($_.split(" ")[0]).replace(".config","") -leaf) -eq (Split-Path ($_.split(" ")[1]).replace(".txt","") -leaf)){
                if (($_.split(" ")[1]).ToUpper() -match "FIPS"){
                    $correct_path++
                }
            }
        }
        elseif ((Split-Path ($_.split(" ")[0]) -leaf) -match "nss.config"){
            $correct_path++
        }
    }

    if ($correct_path -eq $better_finding.count){
        $Status = "NotAFinding"
        $FindingMessage = "The Amazon Linux 2023 custom crypto policies are loaded correctly."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The Amazon Linux 2023 custom crypto policies are not loaded correctly."
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

Function Get-V274059 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274059
        STIG ID    : AZLX-23-001290
        Rule ID    : SV-274059r1120165_rule
        CCI ID     : CCI-004046, CCI-004047
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : Amazon Linux 2023 must enable certificate-based smart card authentication.
        DiscussMD5 : 3A80F0997F562F23F7F6A7A3650BFFD0
        CheckMD5   : 15BBBA8B94ED87122CCC241FD6476F7A
        FixMD5     : C87D0A19AE22DD654A7C4EA5314AEDB7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "pam_cert_auth"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf)

    if ($finding){
        if ((($finding | awk '{$2=$2};1').split("=")[1]).replace(" ", "").ToLower() -eq "true") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system has smart cards are enabled in System Security Services Daemon (SSSD)."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not have smart cards are enabled in System Security Services Daemon (SSSD)."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have smart cards are enabled in System Security Services Daemon (SSSD)."
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

Function Get-V274061 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274061
        STIG ID    : AZLX-23-001300
        Rule ID    : SV-274061r1120171_rule
        CCI ID     : CCI-001954, CCI-004046
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : Amazon Linux 2023 must implement certificate status checking for multifactor authentication.
        DiscussMD5 : 836292D2676307E32F93A3C5D8D6D772
        CheckMD5   : 4E556155BE93386D9196CBF8631511EB
        FixMD5     : F39A4D516D82118017C9B87578E277E3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf)
    $finding ??= "Check text: No results found."

    if ((($finding | awk '{$2=$2};1').split(":")[1]).replace(" ", "").ToLower() -eq "certificate_verification=ocsp_dgst=sha512") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system implements certificate status checking for multifactor authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not implement certificate status checking for multifactor authentication."
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

Function Get-V274062 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274062
        STIG ID    : AZLX-23-001305
        Rule ID    : SV-274062r1120174_rule
        CCI ID     : CCI-002007
        Rule Name  : SRG-OS-000383-GPOS-00166
        Rule Title : Amazon Linux 2023 must prohibit the use of cached authenticators after one day.
        DiscussMD5 : CC1503EB4AC6C661B16A41A973BC66E1
        CheckMD5   : 43391C9CB37536F83F279CAF6222E326
        FixMD5     : F8C14DBBC37A4C94F6ED4A1F4AA5C231
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*cache_credentials /etc/sssd/sssd.conf /etc/sssd/sssd.d/*.conf)

    if ($Finding){
        If ((($finding | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "true") {
            $finding_2 = $(grep -I -s -i ^[[:blank:]]*offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/sssd.d/*.conf)
            $foundcount = 0

            $finding_2 | Foreach-Object {
                If ((($_ | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=") -eq "1") {
                    $foundcount++
                }
            }

            if (($foundcount -gt 0) -and ($foundcount -eq $finding_2.count)){
                $Status = "NotAFinding"
                $FindingMessage = "The SSSD prohibits the use of cached authentications after one day."
            }
            else{
                $Status = "Open"
                $FindingMessage = "The SSSD does not prohibit the use of cached authentications after one day."
            }
        }
        elseif ((($finding | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "false") {
            $Status = "NotAFinding"
            $FindingMessage = "The SSSD prohibits the use of cached authentications after one day."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The SSSD does not prohibit the use of cached authentications after one day."
        }
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The SSSD prohibits the use of cached authentications after one day."
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

Function Get-V274063 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274063
        STIG ID    : AZLX-23-001310
        Rule ID    : SV-274063r1120712_rule
        CCI ID     : CCI-000185, CCI-002470, CCI-004068, CCI-004909
        Rule Name  : SRG-OS-000066-GPOS-00034
        Rule Title : Amazon Linux 2023, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
        DiscussMD5 : 2523B38C42154E5CCFE292528CAE4B2A
        CheckMD5   : E4240553753B7E5E1E35A014C1D51E77
        FixMD5     : CC46E5B0248FF57321672AE2E504780B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Test-Path "/etc/sssd/pki/sssd_auth_ca_db.pem"){
        $finding = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("/etc/sssd/pki/sssd_auth_ca_db.pem") | Select-Object Issuer,NotAFter

        if ($finding.Issuer -match "DoD Root CA" -and $finding.NotAfter -gt $(Get-Date)) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system, for PKI-based authentication, has valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system, for PKI-based authentication, does not have valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system, for PKI-based authentication, does not have valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor as '/etc/sssd/pki/sssd_auth_ca_db.pem' does not exist."
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

Function Get-V274064 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274064
        STIG ID    : AZLX-23-001315
        Rule ID    : SV-274064r1120180_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-OS-000067-GPOS-00035
        Rule Title : Amazon Linux 2023, for PKI-based authentication, must enforce authorized access to the corresponding private key.
        DiscussMD5 : B1AF332046D22D4ED0A7F735E5184094
        CheckMD5   : 008FF0C550F3C94CEF7BE367CA19F8FF
        FixMD5     : 3D0162423BDE21A6C714080362358044
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $userlist = $(cut -d: -f 1,3,6 /etc/passwd | egrep -I -s -i ":[1-4][0-9]{3}")
    $found = 0

    foreach ($user in $userlist) {
        $privatekey = (Test-Path "$($user.split(":")[2])/.ssh/id_rsa")

        if ($privatekey) {
            $passphrasetest = $(ssh-keygen -y -f "$($user.split(":")[2])/.ssh/id_rsa" -P `"`" 2>/dev/null)
            If ($passphrasetest){
                $finding = "$($user.split(":")[2])/.ssh/id_rsa"
                $FindingDetails += $(FormatFinding $finding) | Out-String
                $found++
            }
        }
    }

    $Status = "Not_Reviewed"

    if ($found -eq 0) {
        $FindingMessage = "All SSH private key files have a passcode."
    }
    else {
        $FindingMessage = "All SSH private key files do not have a passcode or could not be determined (not default)."
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

Function Get-V274065 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274065
        STIG ID    : AZLX-23-002000
        Rule ID    : SV-274065r1120699_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : Amazon Linux 2023 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system.
        DiscussMD5 : 64A691FE1386898927E2F1BB2357F1AD
        CheckMD5   : 6B432B9C047F7EB510D404BA5414D44B
        FixMD5     : 83FF9115B6DD6B68FC77543C428AA02B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/issue)
    $finding ??= "Check text: No results found."
    $finding_2 = ""

    $finding_2 = $((cat /etc/issue | awk '{$2=$2};1').replace(" ", "").replace('"','')) | tr -d "\n"
    if ($finding_2 -eq "YouareaccessingaU.S.Government(USG)InformationSystem(IS)thatisprovidedforUSG-authorizeduseonly.ByusingthisIS(whichincludesanydeviceattachedtothisIS),youconsenttothefollowingconditions:-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct(PM),lawenforcement(LE),andcounterintelligence(CI)investigations.-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.-ThisISincludessecuritymeasures(e.g.,authenticationandaccesscontrols)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
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

Function Get-V274066 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274066
        STIG ID    : AZLX-23-002005
        Rule ID    : SV-274066r1120186_rule
        CCI ID     : CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388
        Rule Name  : SRG-OS-000228-GPOS-00088
        Rule Title : Amazon Linux 2023 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon.
        DiscussMD5 : 0EBC4CD94DB761EF61981AFC61EFEA3D
        CheckMD5   : D64A9A879215D1DC83C734509B4FF84A
        FixMD5     : BD2D3313A245D24D2C49F0134622CB71
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*banner')
    $finding ??= "Check text: No results found."

    if ($finding.split(":")[1].StartsWith("#")){
        $Status = "Open"
        $FindingMessage = "Any SSH connection to Amazon Linux 2023 does not display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "Any SSH connection to Amazon Linux 2023 displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system."
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

Function Get-V274067 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274067
        STIG ID    : AZLX-23-002015
        Rule ID    : SV-274067r1120653_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-OS-000341-GPOS-00132
        Rule Title : Amazon Linux 2023 must allocate audit record storage capacity to store at least one week's worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
        DiscussMD5 : A3F1F182C35241702E1F25320D301DA9
        CheckMD5   : 8A1FB94F5C3A503DBC56DDE79EB0B3F6
        FixMD5     : E10F1003DBDAB9901127F7536AA7ADA4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -iw log_file /etc/audit/auditd.conf)
    $finding_2 = ""

    If ($finding) {
        $auditlogpath = (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]).split("/")
        $partition = ([string]$auditlogpath[0..($auditlogpath.count - 2)]).replace(" ", "/")
        $finding_2 = $(df -h $partition)

        $Status = "Not_Reviewed"
        $FindingMessage = "Verify Amazon Linux 2023 allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit records are not being written to a log file."
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

Function Get-V274068 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274068
        STIG ID    : AZLX-23-002020
        Rule ID    : SV-274068r1120192_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-OS-000341-GPOS-00132
        Rule Title : Amazon Linux 2023 must use a separate file system for the system audit data path.
        DiscussMD5 : 9790533ADCA4EA5E4014DE3ADA298E2C
        CheckMD5   : 226E7A22C8F4C9B1313D2F538D89E1D4
        FixMD5     : 0BF7D5BF1AA076C0B22D896839C19763
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $mountpoint = " /var/log/audit "
    $finding = $(mount | grep -I $mountpoint)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "A separate file system/partition has been created for '$mountpoint'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "A separate file system/partition has not been created for '$mountpoint'."
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

Function Get-V274069 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274069
        STIG ID    : AZLX-23-002025
        Rule ID    : SV-274069r1120195_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : Amazon Linux 2023 must label all off-loaded audit logs before sending them to the central log server.
        DiscussMD5 : F6E7671F2637F0E376954C1A764E9C38
        CheckMD5   : E8A45D893C11450C49170CCDBC2B037D
        FixMD5     : EBA091C8591E2795C5ECB9EE39AFFA02
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "name_format"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)

    if ($finding){
        If (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -in "hostname", "fqd", "numeric") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit daemon is configured to take an appropriate action when the internal queue is full."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit daemon is not configured to take an appropriate action when the internal queue is full."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit daemon is not configured to take an appropriate action when the internal queue is full."
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

Function Get-V274070 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274070
        STIG ID    : AZLX-23-002030
        Rule ID    : SV-274070r1120198_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : Amazon Linux 2023 must take appropriate action when the internal event queue is full.
        DiscussMD5 : D7BCAF6B3308FBA0B1DC9B831DAB54D7
        CheckMD5   : 0E82F1A07816C30C461616A95A80C3C5
        FixMD5     : BA393918DD69647EA08A76E0E519276A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "overflow_action"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)

    If ($finding){
        If (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -in "syslog", "single", "halt") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit daemon is configured to take an appropriate action when the internal queue is full."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit daemon is not configured to take an appropriate action when the internal queue is full."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit daemon is not configured to take an appropriate action when the internal queue is full."
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

Function Get-V274071 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274071
        STIG ID    : AZLX-23-002035
        Rule ID    : SV-274071r1120201_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : Amazon Linux 2023 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
        DiscussMD5 : 0DF0177AAF60F082FAA4CD9600573FF3
        CheckMD5   : 642C980EF89C5A27C23FE07B8C09F7ED
        FixMD5     : 58CF03BEDEDDF19817D341BAF82E623A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "space_left "

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)

    if ($finding){
        If (([int]((($Finding | awk '{$2=$2};1').replace(" ","")).split("=")[1]).replace("%","").replace('"','')) -ge 25) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system does not take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
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

Function Get-V274072 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274072
        STIG ID    : AZLX-23-002040
        Rule ID    : SV-274072r1120204_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : Amazon Linux 2023 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.
        DiscussMD5 : 0DF0177AAF60F082FAA4CD9600573FF3
        CheckMD5   : CB24438F1F54610D95FDD227DA14EA68
        FixMD5     : 069711B3F79A46EE85111AFAE1EB0A03
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "space_left_action"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)

    if ($Finding){
        If ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -eq "email")) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system immediately notifies the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
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

Function Get-V274073 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274073
        STIG ID    : AZLX-23-002045
        Rule ID    : SV-274073r1120207_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : Amazon Linux 2023 must take action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity.
        DiscussMD5 : 84C0398EB991F31421B31940687E80D5
        CheckMD5   : 06FC6AC232D048FC8267F082A7A2CC75
        FixMD5     : 41FEE6632B9AE16FB63B1FA546C06344
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "admin_space_left"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)
    $finding ??= "Check text: No results found."

    If ((($Finding | awk '{$2=$2};1').replace(" ","")).split("=")[1] -eq "5%") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system takes action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity."
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

Function Get-V274074 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274074
        STIG ID    : AZLX-23-002050
        Rule ID    : SV-274074r1120210_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : Amazon Linux 2023 must take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity.
        DiscussMD5 : 84C0398EB991F31421B31940687E80D5
        CheckMD5   : 73543EF7784933FB118C0FA49B085307
        FixMD5     : 53BF1212F4116FB95129712C772890CF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "admin_space_left_action"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)
    $finding ??= "Check text: No results found."

    If ((($finding | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "single") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system configured to take action when the allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to take action when the allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity."
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

Function Get-V274075 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274075
        STIG ID    : AZLX-23-002055
        Rule ID    : SV-274075r1120700_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : Amazon Linux 2023 must immediately notify the system administrator (SA) and information system security officer (ISSO), at a minimum, of an audit processing failure event.
        DiscussMD5 : D7DEB737B08C0E22FAE36DD32DB4DED6
        CheckMD5   : 9ABCA86C8CFFF189FD97948A998E6C8A
        FixMD5     : DF35F29F8B4ABD90E087FD67BF9F39FC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "action_mail_acct"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)

    if ($finding){
        If (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system immediately notifies the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
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

Function Get-V274076 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274076
        STIG ID    : AZLX-23-002060
        Rule ID    : SV-274076r1120216_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : Amazon Linux 2023 must be configured to off-load audit records onto a different system from the system being audited via syslog.
        DiscussMD5 : 5462C12F32E0348C87F192D66643ABA2
        CheckMD5   : 1D1C9FE27AE6759FF7297ABCD301A163
        FixMD5     : 2E942110B8E37F7A1193FF8A1697BBBC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*active /etc/audit/plugins.d/syslog.conf)
    $finding ??= "Check text: No results found."

    If (((($finding | awk '{$2=$2};1').replace(" ","")).ToLower()).split("=")[1] -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is configured use the audisp-remote syslog service."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured use the audisp-remote syslog service."
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

Function Get-V274077 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274077
        STIG ID    : AZLX-23-002065
        Rule ID    : SV-274077r1120219_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : Amazon Linux 2023 must authenticate the remote logging server for off-loading audit logs via rsyslog.
        DiscussMD5 : FF6E6568FBA0ACEC9A071356B59EF50F
        CheckMD5   : FF17A20AAF607824FE100C0A4DC141E9
        FixMD5     : 489D551BDECB1DBB52F8F21D04921716
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = '$ActionSendStreamDriverAuthMode'

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
    $finding ??= "Check text: No results found."

    If ((($Finding | awk '{$2=$2};1').split(":")[1].ToLower()).split(" ")[1] -eq "x509/name") {
        $status = "NotAFinding"
        $FindingMessage = "The operating system authenticates the remote logging server for offloading audit logs."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not authenticate the remote logging server for offloading audit logs."
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

Function Get-V274078 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274078
        STIG ID    : AZLX-23-002070
        Rule ID    : SV-274078r1120222_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : Amazon Linux 2023 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited via rsyslog.
        DiscussMD5 : FF6E6568FBA0ACEC9A071356B59EF50F
        CheckMD5   : 636FBB76AB3D8165A6A1BDCEC47F2A87
        FixMD5     : C9825942E6D510F12CAA1654837BA023
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = '$ActionSendStreamDriverMode'

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
    $finding ??= "Check text: No results found."

    If ((($Finding | awk '{$2=$2};1').split(":")[1]).split(" ")[1] -eq "1") {
        $status = "NotAFinding"
        $FindingMessage = "The operating system encrypts audit records offloaded onto a different system or media from the system being audited via rsyslog."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not encrypt audit records offloaded onto a different system or media from the system being audited via rsyslog."
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

Function Get-V274079 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274079
        STIG ID    : AZLX-23-002075
        Rule ID    : SV-274079r1120724_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : Amazon Linux 2023 must encrypt via the gtls driver the transfer of audit records off-loaded onto a different system or media from the system being audited via rsyslog.
        DiscussMD5 : 13541BF28706F68CC349FA6DC1AEFF8B
        CheckMD5   : E75CD9F459CCB17D6495825BCB69E053
        FixMD5     : F3A5DA9F833DA0DA2D2F2615449526A9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = '$DefaultNetstreamDriver'

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
    $finding ??= "Check text: No results found."

    If ((($Finding | awk '{$2=$2};1').split(":")[1].ToLower()).split(" ")[1] -eq "gtls") {
        $status = "NotAFinding"
        $FindingMessage = "The operating system uses the gtls driver to encrypt audit records offloaded onto a different system or media from the system being audited via rsyslog."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not uses the gtls driver to encrypt audit records offloaded onto a different system or media from the system being audited via rsyslog."
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

Function Get-V274080 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274080
        STIG ID    : AZLX-23-002080
        Rule ID    : SV-274080r1120228_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : Amazon Linux 2023 must be configured to off-load audit records onto a different system from the system being audited via syslog.
        DiscussMD5 : 9682590594B10126E24EF4BA9E29FA82
        CheckMD5   : 088F92F347923238606BFBD2D6EE8F28
        FixMD5     : 83880E7B004FDEFA3BD45092997F027F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Test-Path /etc/systemd/journal-upload.conf)

    if ($finding){
        $finding = $(cat /etc/systemd/journal-upload.conf)

        $Status = "Not_Reviewed"
        $FindingMessage = "The operating system does off-loads audit records onto a different system."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not off-load audit records onto a different system."
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

Function Get-V274081 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274081
        STIG ID    : AZLX-23-002085
        Rule ID    : SV-274081r1120231_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.
        DiscussMD5 : 4E4D2D2B2EA93491504CC94DB3435913
        CheckMD5   : F909305E184FEA554A045CA00B770BA1
        FixMD5     : 863DC3954D49930C2F27C2DCF3F0B3F5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_path = "/etc/sudoers "

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/sudoers[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to access the '$system_path' file."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to access the '$system_path' file."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to access the '$system_path' file."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274082 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274082
        STIG ID    : AZLX-23-002090
        Rule ID    : SV-274082r1120234_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d/ directory.
        DiscussMD5 : 4E4D2D2B2EA93491504CC94DB3435913
        CheckMD5   : 3B29D9769454FCF5AA446921443F5E0A
        FixMD5     : A620D997C2058B22FAF9C972E5720D09
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_path = "/etc/sudoers.d"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/sudoers.d[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to access the '$($system_path)' file."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to access the '$($system_path)' file."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to access the '$($system_path)' file."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274083 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274083
        STIG ID    : AZLX-23-002095
        Rule ID    : SV-274083r1120237_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
        DiscussMD5 : EB9C69999F7F403A88A36F9F05B69398
        CheckMD5   : C63CBBFB4A6224853A234C3D0DFFF90B
        FixMD5     : A1CFA5DBB504515259C9D5542685B514
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/etc/group"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/group[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274084 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274084
        STIG ID    : AZLX-23-002100
        Rule ID    : SV-274084r1120240_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
        DiscussMD5 : EB9C69999F7F403A88A36F9F05B69398
        CheckMD5   : BBC47F3CAC72687273164C7E8E7D1042
        FixMD5     : 67FA9E43B5692C3F8182D2946E61801E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/etc/gshadow"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/gshadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274085 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274085
        STIG ID    : AZLX-23-002105
        Rule ID    : SV-274085r1120243_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.
        DiscussMD5 : EB9C69999F7F403A88A36F9F05B69398
        CheckMD5   : 9ED2AFD7D0E0229A3E6840CACD3381AF
        FixMD5     : 610D93423509F85C76D08BBFA79CB7E6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/etc/security/opasswd"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/security\/opasswd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274086 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274086
        STIG ID    : AZLX-23-002110
        Rule ID    : SV-274086r1120246_rule
        CCI ID     : CCI-002233, CCI-002234
        Rule Name  : SRG-OS-000326-GPOS-00126
        Rule Title : Amazon Linux 2023 must audit uses of the "execve" system call.
        DiscussMD5 : 73CA88E5279D16F8E4D953D69661B94D
        CheckMD5   : 8C83D103787F2755F1DB1AE8AC2F90B6
        FixMD5     : 861619EB7C3AF01DD4538DFA1D3EE110
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "execve"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        $not_commented = 0
        $line = 0
        ($finding | grep -I -s -i " $system_call ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " $system_call ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if ((($finding | awk '{$2=$2};1')) -and (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+$($system_call)[\s]))(?:-C[\s]+uid!=euid[\s]+)(?:-F[\s]+euid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") -and
                (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+$($system_call)[\s]))(?:-C[\s]+gid!=egid[\s]+)(?:-F[\s]+egid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$")) {
                $Status = "NotAFinding"
                $FindingMessage = "Amazon Linux 2023 is configured to audit the execution of the '$($system_call)' system call."
            }
            else {
                $Status = "Open"
                $FindingMessage = "Amazon Linux 2023 is not configured to audit the execution of the '$($system_call)' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "Amazon Linux 2023 is not configured to audit the execution of the '$($system_call)' system call."
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

Function Get-V274087 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274087
        STIG ID    : AZLX-23-002115
        Rule ID    : SV-274087r1120249_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the chmod, fchmod, and fchmodat system calls.
        DiscussMD5 : 483FAF904AB13DB8B52C1881093CE34A
        CheckMD5   : 1BFBA3CE78E2AE95F4383214DDB62E03
        FixMD5     : 63859FDBE4E551E5F143C2A8C101AC72
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "chmod"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]"^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+$($system_call)[\s]+|([\s]+|[,])$($system_call)([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$"
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]"^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+f$($system_call)[\s]+|([\s]+|[,])f$($system_call)([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$"
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]"^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+f$($system_call)at[\s]+|([\s]+|[,])f$($system_call)at([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$"
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call),f$($system_call),f$($system_call)at' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call),f$($system_call),f$($system_call)at' syscalls occur."
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

Function Get-V274088 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274088
        STIG ID    : AZLX-23-002120
        Rule ID    : SV-274088r1120252_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the chown, fchown, fchownat, and lchown system calls.
        DiscussMD5 : 483FAF904AB13DB8B52C1881093CE34A
        CheckMD5   : 1C97CCDEC2D5D2D5C74066F689A3D984
        FixMD5     : 799FF55D329FEA4D29F7541013783AF5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "chown"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+$($system_call)\s+|(\s+|,)$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+l$($system_call)\s+|(\s+|,)l$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+f$($system_call)at\s+|(\s+|,)f$($system_call)at(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+f$($system_call)\s+|(\s+|,)f$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call),f$($system_call),f$($system_call)at,l$($system_call)' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call),f$($system_call),f$($system_call)at,l$($system_call)' syscalls occur."
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

Function Get-V274089 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274089
        STIG ID    : AZLX-23-002125
        Rule ID    : SV-274089r1120255_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
        DiscussMD5 : 2963A7D5E878D4563D50B891F937C863
        CheckMD5   : D78832D1B6DA3762879397B3513E1A61
        FixMD5     : 0526BA50EBF8170EE6470FA83F405946
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "xattr"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (
        	(
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+set$($system_call)\s+|(\s+|,)set$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+set$($system_call)\s+|(\s+|,)set$($system_call)(\s+|,))).*-F\s+auid=0(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+fremove$($system_call)\s+|(\s+|,)fremove$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+fremove$($system_call)\s+|(\s+|,)fremove$($system_call)(\s+|,))).*-F\s+auid=0(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+fset$($system_call)\s+|(\s+|,)fset$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+fset$($system_call)\s+|(\s+|,)fset$($system_call)(\s+|,))).*-F\s+auid=0(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+lset$($system_call)\s+|(\s+|,)lset$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+lset$($system_call)\s+|(\s+|,)lset$($system_call)(\s+|,))).*-F\s+auid=0(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+remove$($system_call)\s+|(\s+|,)remove$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+remove$($system_call)\s+|(\s+|,)remove$($system_call)(\s+|,))).*-F\s+auid=0(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+lremove$($system_call)\s+|(\s+|,)lremove$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	) -and (
        		($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+lremove$($system_call)\s+|(\s+|,)lremove$($system_call)(\s+|,))).*-F\s+auid=0(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
        	)
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'set$($system_call),fset$($system_call),lset$($system_call),remove$($system_call),fremove$($system_call),lremove$($system_call)' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'set$($system_call),fset$($system_call),lset$($system_call),remove$($system_call),fremove$($system_call),lremove$($system_call)' syscalls occur."
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

Function Get-V274090 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274090
        STIG ID    : AZLX-23-002130
        Rule ID    : SV-274090r1120258_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls.
        DiscussMD5 : 483FAF904AB13DB8B52C1881093CE34A
        CheckMD5   : E6067477D8E282947C6A2A88FC14BFA9
        FixMD5     : D194D222E03F9126755E960947279B87
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "open\|truncate\|creat"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+truncate\s+|(\s+|,)truncate(\s+|,))).*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+truncate\s+|(\s+|,)truncate(\s+|,))).*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+openat\s+|(\s+|,)openat(\s+|,))).*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+openat\s+|(\s+|,)openat(\s+|,))).*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+open\s+|(\s+|,)open(\s+|,))).*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+open\s+|(\s+|,)open(\s+|,))).*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+open_by_handle_at\s+|(\s+|,)open_by_handle_at(\s+|,))).*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+open_by_handle_at\s+|(\s+|,)open_by_handle_at(\s+|,))).*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+ftruncate\s+|(\s+|,)ftruncate(\s+|,))).*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+ftruncate\s+|(\s+|,)ftruncate(\s+|,))).*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+creat\s+|(\s+|,)creat(\s+|,))).*-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+creat\s+|(\s+|,)creat(\s+|,))).*-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'truncate,ftruncate,creat,open,openat,open_by_handle_at' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'truncate,ftruncate,creat,open,openat,open_by_handle_at' syscalls occur."
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

Function Get-V274091 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274091
        STIG ID    : AZLX-23-002135
        Rule ID    : SV-274091r1120261_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the init_module and finit_module system calls.
        DiscussMD5 : 483FAF904AB13DB8B52C1881093CE34A
        CheckMD5   : 5F82DF1D0CFF681177DEAFDE269027D4
        FixMD5     : 0227B1D4E35AAF87FAD368E675B75F7C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "init_module"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        $not_commented = 0
        $line = 0
        ($finding | grep -I -s -i " $system_call ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " $system_call ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+$($system_call)\s+|(\s+|,)$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]"^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+f$($system_call)\s+|(\s+|,)f$($system_call)(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$"
                )
            ) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' and 'f$($system_call)' syscall occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' and 'f$($system_call)' syscall occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' and 'f$($system_call)' syscall occur."
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

Function Get-V274092 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274092
        STIG ID    : AZLX-23-002140
        Rule ID    : SV-274092r1120264_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the create_module system call.
        DiscussMD5 : 483FAF904AB13DB8B52C1881093CE34A
        CheckMD5   : 59D07B0702EFF49E3A07A602FF9A54A4
        FixMD5     : D52728D1BA88F4EA462CD2669D8AE694
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "create_module"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        $not_commented = 0
        $line = 0
        ($finding | grep -I -s -i " $system_call ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " $system_call ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:-S[\s]+$($system_call)[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' syscall occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' syscall occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' syscall occur."
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

Function Get-V274093 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274093
        STIG ID    : AZLX-23-002145
        Rule ID    : SV-274093r1120267_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the kmod command.
        DiscussMD5 : 483FAF904AB13DB8B52C1881093CE34A
        CheckMD5   : 4D3B3E1B205831A220D70A3278BC068E
        FixMD5     : 5FD9426A62FC8E5A03ACC11C8CDEFDF6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "kmod"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/$($system_call)[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
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

Function Get-V274094 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274094
        STIG ID    : AZLX-23-002150
        Rule ID    : SV-274094r1120270_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the rename, unlink, rmdir, renameat, and unlinkat system calls.
        DiscussMD5 : E0B781BC059263D2B3B065B6FFEE53B9
        CheckMD5   : 1788A53B4033A5931185DE7B3436B9CA
        FixMD5     : 62FFD0ECC82CE82B2B13CB621C17E72B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "rename\|unlink\|rmdir"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+rename\s+|(\s+|,)rename(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+renameat\s+|(\s+|,)renameat(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+rmdir\s+|(\s+|,)rmdir(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+unlink\s+|(\s+|,)unlink(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^\s*-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+(?:.*(-S\s+unlinkat\s+|(\s+|,)unlinkat(\s+|,))).*-F\s+auid>=1000\s+-F\s+auid!=(4294967295|-1|unset)(\s+(-k\s+|-F\s+key=)[-\w]+)*\s*$'
                )
            ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'rename,unlink,rmdir,renameat,unlinkat' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'rename,unlink,rmdir,renameat,unlinkat' syscalls occur."
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

Function Get-V274095 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274095
        STIG ID    : AZLX-23-002155
        Rule ID    : SV-274095r1120273_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the chcon command.
        DiscussMD5 : 664FA614E7F4987BF9677F10B15E0E88
        CheckMD5   : 7451F9066006B971D19190E15FEEDEBA
        FixMD5     : BF44A12A16D1E55DDCBE70850742867E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "chcon"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/$($system_call)[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
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

Function Get-V274096 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274096
        STIG ID    : AZLX-23-002160
        Rule ID    : SV-274096r1120276_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/faillock.
        DiscussMD5 : A5633BAB7B207077168A27AA5AB0210A
        CheckMD5   : 03A5CD876DDA3B73D8CC0B2A909AC059
        FixMD5     : AFF865675C59D1140EC1651FB2CE8742
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/var/log/faillock"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/faillock[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274097 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274097
        STIG ID    : AZLX-23-002165
        Rule ID    : SV-274097r1120279_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/lastlog.
        DiscussMD5 : E3B7A6CBABBBCED4ED08F61E1FC3DF17
        CheckMD5   : D2EA377FB67C5171C132138B18B96DF6
        FixMD5     : 8EFD80925F8CA4DE94F4B2B0539DD34A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/var/log/lastlog"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/lastlog[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274098 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274098
        STIG ID    : AZLX-23-002175
        Rule ID    : SV-274098r1120282_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : Amazon Linux 2023 must audit all uses of the init command.
        DiscussMD5 : 09E16B75644FCF63C8900DC9D153FBA2
        CheckMD5   : 922964813B49A9D8A27CC3FCE405EB72
        FixMD5     : 8A9F427CC9812573C1BDB4CE43559E90
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "init"

        $finding = $(auditctl -l | grep -I "bin/$system_call")
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/sbin\/$($system_call)[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
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

Function Get-V274099 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274099
        STIG ID    : AZLX-23-002180
        Rule ID    : SV-274099r1120285_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : Amazon Linux 2023 must audit all uses of the reboot command.
        DiscussMD5 : 8E9332F7A93AA4546E54286AA736C71C
        CheckMD5   : 78B155865EB737E3BF3A21F34933CB1C
        FixMD5     : 1AC983BDC19F9FBC21283678DBF8F2ED
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "reboot"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/sbin\/$($system_call)[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
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

Function Get-V274100 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274100
        STIG ID    : AZLX-23-002185
        Rule ID    : SV-274100r1120288_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : Amazon Linux 2023 must audit all uses of the shutdown command.
        DiscussMD5 : 6508E708246134BBA0D914D22BAEB731
        CheckMD5   : E069ACDF5E6CF06F255E3D54AFC6C016
        FixMD5     : FD914B2A670495E4F99996B286B1AB6F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "shutdown"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/sbin\/$($system_call)[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
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

Function Get-V274101 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274101
        STIG ID    : AZLX-23-002190
        Rule ID    : SV-274101r1120291_rule
        CCI ID     : CCI-001493
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : Amazon Linux 2023 audit tools must have a mode of "0755" or less permissive.
        DiscussMD5 : B229FC5AE54A9D48B21A0B47F99F1BDC
        CheckMD5   : 17F243403E5FBFD8A44815A6F401ACF1
        FixMD5     : 1130C4E2B4DD8A2EEF5C69A11EE63E80
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules)
    $found = 0

    $finding | Foreach-Object {
        if ((CheckPermissions -FindPath $_.split(" ")[1] -MinPerms "0755") -ne $true){
            $found++
        }
    }

    if ($found -gt 0){
        $Status = "Open"
        $FindingMessage = "The audit tools are not protected from unauthorized access, deletion, or modification."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The audit tools are protected from unauthorized access, deletion, or modification."
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

Function Get-V274102 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274102
        STIG ID    : AZLX-23-002195
        Rule ID    : SV-274102r1120294_rule
        CCI ID     : CCI-001493
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : Amazon Linux 2023 audit tools must be owned by root.
        DiscussMD5 : B229FC5AE54A9D48B21A0B47F99F1BDC
        CheckMD5   : E4A3B4DCACD404CA970F2BA98C37618C
        FixMD5     : EB60ABE96293D6971D652024AAAB8A26
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules)
    $found = 0

    $finding | Foreach-Object {
        if ($_.split(" ")[0] -ne "root"){
            $found++
        }
    }

    if ($found -gt 0){
        $Status = "Open"
        $FindingMessage = "The audit tools are not owned by 'root' to prevent any unauthorized access, deletion, or modification."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The audit tools are owned by 'root' to prevent any unauthorized access, deletion, or modification."
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

Function Get-V274103 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274103
        STIG ID    : AZLX-23-002200
        Rule ID    : SV-274103r1120297_rule
        CCI ID     : CCI-001493
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : Amazon Linux 2023 audit tools must be group-owned by root.
        DiscussMD5 : B229FC5AE54A9D48B21A0B47F99F1BDC
        CheckMD5   : FFBE0E5D74D82DC1829EF31B3F525EA2
        FixMD5     : 3CC1FB836068B36D6081D515A5E0F078
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules)
    $found = 0

    $finding | Foreach-Object {
        if ($_.split(" ")[0] -ne "root"){
            $found++
        }
    }

    if ($found -gt 0){
        $Status = "Open"
        $FindingMessage = "The audit tools are not group-owned by 'root' to prevent any unauthorized access, deletion, or modification."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The audit tools are group-owned by 'root' to prevent any unauthorized access, deletion, or modification."
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

Function Get-V274104 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274104
        STIG ID    : AZLX-23-002205
        Rule ID    : SV-274104r1120300_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
        DiscussMD5 : 0FCFE798211B299F8081E7748DACFF10
        CheckMD5   : 30C90236C018C1074D377E518F3E023D
        FixMD5     : 24EB5632A8B5D21DE3A1754DB324A4E7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/etc/passwd"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/passwd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274105 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274105
        STIG ID    : AZLX-23-002210
        Rule ID    : SV-274105r1120661_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all successful/unsuccessful uses of the chage command.
        DiscussMD5 : 9A12300916C2F9C10E52A57AC6223D4B
        CheckMD5   : 793F0764616C01C8F34A521BC7E9CA8D
        FixMD5     : 797539D3D7A9426DBEBBD23D0A0676DB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "chage"

        $finding = $(auditctl -l | grep -I $system_call)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/$($system_call)[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
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

Function Get-V274106 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274106
        STIG ID    : AZLX-23-002215
        Rule ID    : SV-274106r1120657_rule
        CCI ID     : CCI-000139
        Rule Name  : SRG-OS-000046-GPOS-00022
        Rule Title : Amazon Linux 2023 must alert the information system security officer (ISSO) and system administrator (SA), at a minimum, in the event of an audit processing failure.
        DiscussMD5 : D7DEB737B08C0E22FAE36DD32DB4DED6
        CheckMD5   : F0753DD4EDFACC84F3DADD7BC2BABD96
        FixMD5     : 20D2172BE7696DEF01E92E0D2B1D79DF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "action_mail_acct"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)

    if ($finding){
        If (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system immediately notifies the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
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

Function Get-V274107 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274107
        STIG ID    : AZLX-23-002220
        Rule ID    : SV-274107r1120309_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : Amazon Linux 2023 must off-load audit records onto a different system in the event the audit storage volume is full.
        DiscussMD5 : 12FFD3C03701BE9B47C761E0CCB72458
        CheckMD5   : BD267E331270FFC958C8D5858E027410
        FixMD5     : A66C9DBD9C4B8D2113B225BE1117400C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "disk_full_action"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)

    If ($finding){
        If (($Finding.ToLower() | awk '{$2=$2};1').replace(" ", "").split("=")[1] -in "syslog", "single", "halt") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system takes an appropriate action if the disk the audit records are written to becomes full."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not take an appropriate action if the disk the audit records are written to becomes full."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not take an appropriate action if the disk the audit records are written to becomes full."
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

Function Get-V274108 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274108
        STIG ID    : AZLX-23-002225
        Rule ID    : SV-274108r1120312_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164, CCI-001314
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Amazon Linux 2023 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access.
        DiscussMD5 : DEF088B0A8A29E0A6897ED2D9E6F42EF
        CheckMD5   : 5B12CA8006FF38CD24FC940866FF5E7F
        FixMD5     : 77E3DF9B0D3C7D66137F4E2381DBD8A6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i log_group /etc/audit/auditd.conf)
    $finding_2 = $(grep -I -s -iw log_file /etc/audit/auditd.conf)
    $finding_3 = ""

    If ($finding -and $(Test-Path $finding_2)) {
        $finding_3 = $((stat -c "%G %n" $($Finding_2 | awk '{$2=$2};1')).replace(" ", "").split("=")[1])

        if (($finding_3.split(" ")[0] -eq $finding)){
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory is owned by 'root'."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The audit log directory is not owned by 'root'."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have audit logs."
    }

    $FindingDetails += $FindingMessage | Out-String

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

Function Get-V274109 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274109
        STIG ID    : AZLX-23-002230
        Rule ID    : SV-274109r1120315_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164, CCI-001314
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Amazon Linux 2023 audit log directory must be owned by root to prevent unauthorized read access.
        DiscussMD5 : DEF088B0A8A29E0A6897ED2D9E6F42EF
        CheckMD5   : 07522F35DB777F5427195EA3B5B4FFC4
        FixMD5     : A02C2FED57334AFF3FFB69E1AD6946A5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -iw log_file /etc/audit/auditd.conf)

    If ($finding) {
        $finding_2 = $(stat -c "%G %n" $(Split-Path $($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]))

        if ($finding_2.split(" ")[0] -eq "root"){
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory is owned by 'root'."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The audit log directory is not owned by 'root'."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have audit logs."
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

Function Get-V274110 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274110
        STIG ID    : AZLX-23-002235
        Rule ID    : SV-274110r1120318_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164, CCI-001314
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Amazon Linux 2023 audit logs file must have mode "0600" or less permissive to prevent unauthorized access to the audit log.
        DiscussMD5 : DEF088B0A8A29E0A6897ED2D9E6F42EF
        CheckMD5   : B32891CCA8AB32616B06E48F76F68A1A
        FixMD5     : 920B6F0C98016BC62C90A8C48F3A4964
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -iw log_file /etc/audit/auditd.conf)

    If ($finding) {
        if ((CheckPermissions -FindPath $(Split-Path $($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) -MinPerms "0600")  -ne $true) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directories have a mode of '0600' or less permissive."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log directories do not have a mode of '0600' or less permissive."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have audit logs."
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

Function Get-V274111 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274111
        STIG ID    : AZLX-23-002240
        Rule ID    : SV-274111r1120321_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : Amazon Linux 2023 must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
        DiscussMD5 : 1488C27E4AB5648A64BC001815954ABD
        CheckMD5   : 136678A4D14FBF5C45CF295CD0030C8B
        FixMD5     : B98078715AE0FAED9C5DF456A4624E49
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $path = "/etc/audit/auditd.conf"
    $path_2 = "/etc/audit/rules.d/*.rules"
    $perms = "640"

    $finding = $(ls -ld $path)
    [array]$finding_2 = $(ls -ld $path_2)

    if ((CheckPermissions -FindPath $path -MinPerms $perms) -eq $true){
        $correct_perm = 0
        $finding_2 | Foreach-object {
            if ((CheckPermissions -FindPath $_[-1] -MinPerms $perms) -eq $true){
                $correct_perm++
            }
        }
        if ($correct_perm -eq $finding_2.count){
            $Status = "NotAFinding"
            $FindingMessage = "The files in directory '/etc/audit/rules.d/' and '/etc/audit/auditd.conf' have a mode of '0640' or less permissive."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The files in directory '/etc/audit/rules.d/' do not have a mode of '0640' or less permissive."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The '/etc/audit/auditd.conf' does not have a mode of '0640' or less permissive."
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

Function Get-V274112 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274112
        STIG ID    : AZLX-23-002245
        Rule ID    : SV-274112r1120324_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must audit all uses of the sudo command.
        DiscussMD5 : 850629D2FCE502805143E6B5B223DE0B
        CheckMD5   : B7D811B4433364D1C0AB26C723526296
        FixMD5     : 7168264ED9A207A26BC9AD6358BC6886
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dnf list --installed audit)

    if ($finding) {
        $system_call = "sudo"

        $finding = $(auditctl -l | grep -I "/bin/$system_call")
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]"^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/$($system_call)[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the '$($system_call)' command occur."
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

Function Get-V274113 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274113
        STIG ID    : AZLX-23-002250
        Rule ID    : SV-274113r1120327_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
        DiscussMD5 : FD0C5B8A9EDB0C58258E0C5B4881BD68
        CheckMD5   : 30C90236C018C1074D377E518F3E023D
        FixMD5     : 6A0D64C36F0A69F93282B27A26084B1D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/etc/passwd"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/passwd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274114 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274114
        STIG ID    : AZLX-23-002255
        Rule ID    : SV-274114r1120330_rule
        CCI ID     : CCI-000015, CCI-000018, CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130, CCI-002884
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : Amazon Linux 2023 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
        DiscussMD5 : 552092D1F85095C84FFBB54EE75564CF
        CheckMD5   : 355A0EADC14CA0BD57A38CF5D6EBD47F
        FixMD5     : 52E54D839781D181B741CBA2954AE873
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $system_path = "/etc/shadow"

        $finding = $(auditctl -l | grep -I $system_path)
        $finding ??= "Check text: No results found."

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/shadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '$($system_path)'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
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

Function Get-V274115 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274115
        STIG ID    : AZLX-23-002260
        Rule ID    : SV-274115r1120333_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-OS-000255-GPOS-00096
        Rule Title : Amazon Linux 2023 must produce audit records containing information to establish the identity of any individual or process associated with the event.
        DiscussMD5 : 30DFD780F02A5CD1FD8BF2AF3C6D4D93
        CheckMD5   : F457892C5223774986FCA18D68286C91
        FixMD5     : 33993C5E7C640133FF4D293C3A791C76
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $action = "log_format"

    $finding = $(grep -I -s -i ^[[:blank:]]*$action /etc/audit/auditd.conf)
    $finding ??= "Check text: No results found."

    If (((($Finding | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1]) -eq "enriched") {
        $Status = "NotAFinding"
        $FindingMessage = "The audit system is configured to resolve audit information before writing to disk."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit system is not configured to resolve audit information before writing to disk."
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

Function Get-V274116 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274116
        STIG ID    : AZLX-23-002265
        Rule ID    : SV-274116r1120336_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : 008576F9E9A5EACB64F40FC0954F5E79
        FixMD5     : 1879982B52BD375AAACA9999C9C071DF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i log_group /etc/audit/auditd.conf)
    $finding_2 = $(grep -I -s -iw log_file /etc/audit/auditd.conf)
    $finding_3 = ""

    If ($finding -and $(Test-Path $finding_2)) {
        $finding_3 = $((stat -c "%G %n" $($Finding_2 | awk '{$2=$2};1')).replace(" ", "").split("=")[1])

        if (($finding_3.split(" ")[0] -eq $finding)){
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory is owned by 'root'."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The audit log directory is not owned by 'root'."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have audit logs."
    }

    $FindingDetails += $FindingMessage | Out-String

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

Function Get-V274117 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274117
        STIG ID    : AZLX-23-002270
        Rule ID    : SV-274117r1120339_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 must ensure the audit log directory be owned by root to prevent unauthorized read access.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : 9E1AD9F2A8843B1BC40FAB505075C98B
        FixMD5     : 4D4F2ED3C97D9D4CAD97AA30AFCFF595
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -iw log_file /etc/audit/auditd.conf)

    If ($finding) {
        $finding_2 = $(stat -c "%U %n" $(Split-Path $($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]))

        if ($finding_2.split(" ")[0] -eq "root"){
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory is owned by 'root'."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The audit log directory is not owned by 'root'."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have audit logs."
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

Function Get-V274118 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274118
        STIG ID    : AZLX-23-002275
        Rule ID    : SV-274118r1120342_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 audit logs file must have mode "0600" or less permissive to prevent unauthorized access to the audit log.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : 922D3C67A7360A85A8D18724F0BB6DFD
        FixMD5     : 674A5E303FE04F5050111D3E8711696C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -iw log_file /etc/audit/auditd.conf)

    If ($finding) {
        if ((CheckPermissions -FindPath $(Split-Path $($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) -MinPerms "0600")  -ne $true) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directories have a mode of '0600' or less permissive."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log directories do not have a mode of '0600' or less permissive."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have audit logs."
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

Function Get-V274119 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274119
        STIG ID    : AZLX-23-002280
        Rule ID    : SV-274119r1120345_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 library directories must be group-owned by root or a system account.
        DiscussMD5 : E87660811A25858B2EAE1CF2047887B4
        CheckMD5   : DBDE5D633549F810EB7B6512FEEDA770
        FixMD5     : E46168B79C581A0D312712070B770720
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F: '($3<1000){print $1}' /etc/group | xargs printf -- ' ! -group %s' | xargs -I % bash -c 'find -L /lib /lib64 /usr/lib /usr/lib64 -xdev ! -group root ! -type d % -stat -L -c "%G %n" {} +'
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are group-owned by 'root'."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not group-owned by 'root'."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/lib /lib64 /usr/lib /usr/lib64"

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

Function Get-V274120 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274120
        STIG ID    : AZLX-23-002285
        Rule ID    : SV-274120r1120348_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 library directories must have mode "755" or less permissive.
        DiscussMD5 : E87660811A25858B2EAE1CF2047887B4
        CheckMD5   : 8CEF65F56EE35327C8BD47BED8DB6FB7
        FixMD5     : AA9F1914BD4F11250747BB4C4DDDD824
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
find /lib /lib64 /usr/lib /usr/lib64 -xdev -perm /022 -type d -exec stat -c "%n %a" '{}' +
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
        $found = 0
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
        $found = 1
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories have mode '0755' or less permissive."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories do not have mode '0755' or less permissive."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/lib /lib64 /usr/lib /usr/lib64"

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

Function Get-V274121 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274121
        STIG ID    : AZLX-23-002290
        Rule ID    : SV-274121r1120351_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 library files must have mode "755" or less permissive.
        DiscussMD5 : 78780B02F5383DB1BB27FF217946A9FF
        CheckMD5   : 238A46CFA3B16B26F2A8C01230A2C3C2
        FixMD5     : 7830A1629B3EAB96E1604DACD8BC5ECB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
find -L /lib /lib64 /usr/lib /usr/lib64 -xdev -perm /0022 -type f -exec ls -l {} +
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories have mode '0755' or less permissive."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories do not have mode '0755' or less permissive."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/lib /lib64 /usr/lib /usr/lib64"

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

Function Get-V274122 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274122
        STIG ID    : AZLX-23-002295
        Rule ID    : SV-274122r1120354_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 library files must be owned by root.
        DiscussMD5 : 2780FF95F7A08663FFC187CB93D0CF2C
        CheckMD5   : FD058A811C6267C5E7453A94F30011B1
        FixMD5     : 161EE864484F648D95F6C5CCA0AD26CB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F: '($3<1000){print $1}' /etc/passwd | xargs printf -- ' ! -user %s' | xargs -I % bash -c 'find -L /lib /lib64 /usr/lib /usr/lib64 -xdev ! -user root ! -type f -name ''*.so*'' % -exec stat -c "%U %n" {} +'
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The systemwide shared library files contained in the following directories are owned by 'root'."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The systemwide shared library files contained in the following directories are not owned by 'root'."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/lib /lib64 /usr/lib /usr/lib64"

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

Function Get-V274123 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274123
        STIG ID    : AZLX-23-002300
        Rule ID    : SV-274123r1120357_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 library files must be group-owned by root or a system account.
        DiscussMD5 : E87660811A25858B2EAE1CF2047887B4
        CheckMD5   : B50777419361EC01DA3998E69D840F2B
        FixMD5     : ED17C015F621E8FB405B0DDE0D8B4043
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F: '($3<1000){print $1}' /etc/group | xargs printf -- ' ! -group %s' | xargs -I % bash -c 'find -L /lib /lib64 /usr/lib /usr/lib64 -xdev ! -group root ! -type d % -stat -L -c "%G %n" {} +'
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are group-owned by 'root'."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not group-owned by 'root'."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/lib /lib64 /usr/lib /usr/lib64"

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

Function Get-V274124 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274124
        STIG ID    : AZLX-23-002305
        Rule ID    : SV-274124r1120360_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 library directories must be owned by root.
        DiscussMD5 : E87660811A25858B2EAE1CF2047887B4
        CheckMD5   : 7779F575C53E5FB201833CB6E529E79A
        FixMD5     : 4722F41279BFD19B687B531E18D818D8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F: '($3<1000){print $1}' /etc/passwd | xargs printf -- ' ! -user %s' | xargs -I % bash -c 'find /lib /lib64 /usr/lib /usr/lib64 -xdev % -type d -exec stat -c "%n %U" '{}' +'
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are owned by 'root'."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not owned by 'root'."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/lib /lib64 /usr/lib /usr/lib64"

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

Function Get-V274125 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274125
        STIG ID    : AZLX-23-002315
        Rule ID    : SV-274125r1120363_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 must ensure the /var/log directory have mode "0755" or less permissive.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : 18B8FCFE10D773A5598C1FBAC06FD5BC
        FixMD5     : 4524964C0B6C100351A879232FC35CDF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $path = "/var/log"
    $perms = "0755"

    $finding = $(ls -ld $path)

    if ((CheckPermissions -FindPath $path -MinPerms $perms) -eq $true){
        $Status = "NotAFinding"
        $FindingMessage = "The '$path' directory has a mode of '$perms' or less."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The '$path' directory does not have a mode of '$perms' or less."
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

Function Get-V274126 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274126
        STIG ID    : AZLX-23-002320
        Rule ID    : SV-274126r1120366_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 must ensure the /var/log directory be owned by root.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : FB49B635F145203B767C16A03622A3D5
        FixMD5     : F715BE7B13B13B1AA1594CDC23B4A0E5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $path = "/var/log"
    $owner = "root"

    $finding = $(ls -ld $path)

    if ($finding.split(" ")[2] -eq $owner){
        $Status = "NotAFinding"
        $FindingMessage = "The '$path' directory is owned by '$owner'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The '$path' directory is not owned by '$owner'."
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

Function Get-V274127 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274127
        STIG ID    : AZLX-23-002325
        Rule ID    : SV-274127r1120369_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 must ensure the /var/log directory be group-owned by root.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : 0FCC3C31754A0DAB349CD2E53D9468A6
        FixMD5     : 15C662D71D3394B3A2BA2304500204DF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $path = "/var/log"
    $owner = "root"

    $finding = $(ls -ld $path)

    if ($finding.split(" ")[3] -eq $owner){
        $Status = "NotAFinding"
        $FindingMessage = "The '$path' directory is group owned by '$owner'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The '$path' directory is not group owned by '$owner'."
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

Function Get-V274128 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274128
        STIG ID    : AZLX-23-002330
        Rule ID    : SV-274128r1120372_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 must ensure the /var/log/messages file have mode "0640" or less permissive.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : 4583908338A142C9F36CB91BEA19BB97
        FixMD5     : 8C4177C99BE9CAEF5F3C985DA0D2D529
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $path = "/var/log/messages"
    $perms = "0640"

    $finding = $(ls -ld $path)

    if ((CheckPermissions -FindPath $path -MinPerms $perms) -eq $true){
        $Status = "NotAFinding"
        $FindingMessage = "The '$path' directory has a mode of '$perms' or less."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The '$path' directory does not have a mode of '$perms' or less."
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

Function Get-V274129 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274129
        STIG ID    : AZLX-23-002335
        Rule ID    : SV-274129r1120375_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 must ensure the /var/log/messages file be group-owned by root.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : F411A6F97AD4657F0F21FAB2EDFFB9D6
        FixMD5     : 3AC12A842F58A6A92C038744F68269ED
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $path = "/var/log/messages"
    $owner = "root"

    $finding = $(ls -ld $path)

    if ($finding.split(" ")[3] -eq $owner){
        $Status = "NotAFinding"
        $FindingMessage = "The '$path' directory is group owned by '$owner'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The '$path' directory is not group owned by '$owner'."
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

Function Get-V274130 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274130
        STIG ID    : AZLX-23-002340
        Rule ID    : SV-274130r1120378_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : Amazon Linux 2023 must ensure the /var/log/messages file be owned by root.
        DiscussMD5 : 6BBFE299E83E7CC2CBEA03F682A02916
        CheckMD5   : C6B2CAAD115A078B553B23CFB960998D
        FixMD5     : D62EB5E6F9A74C35D6DE7959AFA846FA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $path = "/var/log/messages"
    $owner = "root"

    $finding = $(ls -ld $path)

    if ($finding.split(" ")[2] -eq $owner){
        $Status = "NotAFinding"
        $FindingMessage = "The '$path' directory is owned by '$owner'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The '$path' directory is not owned by '$owner'."
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

Function Get-V274131 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274131
        STIG ID    : AZLX-23-002345
        Rule ID    : SV-274131r1120381_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 system commands must be owned by root.
        DiscussMD5 : E87660811A25858B2EAE1CF2047887B4
        CheckMD5   : E163197837324C4CD562F83CAB0E06F2
        FixMD5     : 2B52F14E9820FF068B595130B72BFB77
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F: '($3<1000){print $1}' /etc/passwd | xargs printf -- ' ! -user %s' | xargs -I % bash -c 'find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -xdev % -exec ls -l {} +'
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are owned by 'root'."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not owned by 'root'."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"

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

Function Get-V274132 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274132
        STIG ID    : AZLX-23-002350
        Rule ID    : SV-274132r1120384_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Amazon Linux 2023 system commands must be group-owned by root or a system account.
        DiscussMD5 : E87660811A25858B2EAE1CF2047887B4
        CheckMD5   : CDBD3BED5C0B172C172A5475A9E451E9
        FixMD5     : 933E55F0F226C49F1133EC896972901D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F: '($3<1000){print $1}' /etc/group | xargs printf -- ' ! -group %s' | xargs -I % bash -c 'find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -xdev % -exec ls -l {} +'
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($filelist.count -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are group-owned by 'root'."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not group-owned by 'root'."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"

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

Function Get-V274133 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274133
        STIG ID    : AZLX-23-002355
        Rule ID    : SV-274133r1120387_rule
        CCI ID     : CCI-004064, CCI-004066
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : Amazon Linux 2023 must enforce password complexity by requiring that at least one uppercase character be used.
        DiscussMD5 : F1FA146F5765C86416DEEACD5EF0A315
        CheckMD5   : CFEFF75A7E25436FEE45A07883DF0925
        FixMD5     : B70246E084D84B0FF416755C958F7158
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "ucredit"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ??= "Check text: No results found."
    $foundcount = 1

    $finding | Foreach-Object {
        If (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0 -lt 0) {
            $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $Status = "NotAFinding"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is negative."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is not negative."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of upper-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

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

Function Get-V274134 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274134
        STIG ID    : AZLX-23-002360
        Rule ID    : SV-274134r1120390_rule
        CCI ID     : CCI-004064, CCI-004066
        Rule Name  : SRG-OS-000070-GPOS-00038
        Rule Title : Amazon Linux 2023 must enforce password complexity by requiring that at least one lowercase character be used.
        DiscussMD5 : A7895155364B3BD37C9922865DFB0D38
        CheckMD5   : 5DBD8F9079172CA6896F2B45805E701D
        FixMD5     : 0B984D0E1C42C1FD504C19826BDD7562
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "lcredit"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ??= "Check text: No results found."
    $foundcount = 1

    $finding | Foreach-Object {
        If (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0 -lt 0) {
            $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $Status = "NotAFinding"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is negative."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is not negative."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of upper-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

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

Function Get-V274135 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274135
        STIG ID    : AZLX-23-002365
        Rule ID    : SV-274135r1120393_rule
        CCI ID     : CCI-004064, CCI-004066
        Rule Name  : SRG-OS-000071-GPOS-00039
        Rule Title : Amazon Linux 2023 must enforce password complexity by requiring that at least one numeric character be used.
        DiscussMD5 : 63221F5F969785A61998551685DEA7D2
        CheckMD5   : D1FD17F409C0F456D5FCA17C6788538C
        FixMD5     : F50EFE4040694F22D0090774B11CF6B9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "dcredit"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ??= "Check text: No results found."
    $foundcount = 1

    $finding | Foreach-Object {
        If (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0 -lt 0) {
            $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $Status = "NotAFinding"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is negative."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is not negative."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of upper-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

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

Function Get-V274136 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274136
        STIG ID    : AZLX-23-002370
        Rule ID    : SV-274136r1120697_rule
        CCI ID     : CCI-004064, CCI-004066
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : Amazon Linux 2023 must require the change of at least 50 percent of the total number of characters when passwords are changed.
        DiscussMD5 : 9AE6CDCEFE3B848191E76A6D4632A9B7
        CheckMD5   : E0A813DDD1729D9D16340FA4600ABE39
        FixMD5     : BBA096957B6C452E1605789CE4DF4E5E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "difok"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
	$foundcount = 0

    $finding | Foreach-Object {
        If ([int](($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1]).replace('"','') -ge 8) {
            $foundcount++
        }
    }

    if (($foundcount -gt 0) -and ($foundcount -eq $finding.count)){
        $Status = "NotAFinding"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is 8 or more."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for '$option' in '/etc/security/pwquality.conf' is less than 8."
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

Function Get-V274137 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274137
        STIG ID    : AZLX-23-002375
        Rule ID    : SV-274137r1120725_rule
        CCI ID     : CCI-004064, CCI-004066
        Rule Name  : SRG-OS-000078-GPOS-00046
        Rule Title : Amazon Linux 2023 must enforce a minimum 15-character password length.
        DiscussMD5 : CF10808A9B7A440A10EF3C0702CD0371
        CheckMD5   : 6C9CCDDBF44929E6CB399A2603D8ACAB
        FixMD5     : 5F60B8F618FC738E35EA8C99E068CC7E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "minlen"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ??= "Check text: No results found."
	$foundcount = 1

    $finding | Foreach-Object {
        if ($_ -notmatch "none"){
            If ([int](($_ | awk '{$2=$2};1').split("=")[1]).replace('"','') ?? 0 -ge 15) {
                $foundcount++
            }
        }
    }

    if ($finding.count -eq $foundcount-1){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system enforces a minimum 15-character password length."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not enforce a minimum 15-character password length."
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

Function Get-V274138 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274138
        STIG ID    : AZLX-23-002380
        Rule ID    : SV-274138r1120402_rule
        CCI ID     : CCI-004064, CCI-004066
        Rule Name  : SRG-OS-000266-GPOS-00101
        Rule Title : Amazon Linux 2023 must enforce password complexity by requiring that at least one special character be used.
        DiscussMD5 : 81454C76DB06269E05DC8E4076E25144
        CheckMD5   : 5A1D4F93B2F47E16515107E638EC96A2
        FixMD5     : 3173EA356D70222DE5470AFF4EC3C473
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "ocredit"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ??= "Check text: No results found."
    $foundcount = 1

    $finding | Foreach-Object {
        If (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0 -lt 0) {
            $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $Status = "NotAFinding"
        $FindingMessage = "Amazon Linux 2023 enforces password complexity by requiring at least one special character."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Amazon Linux 2023 does not enforce password complexity by requiring at least one special character."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of numeric characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

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

Function Get-V274139 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274139
        STIG ID    : AZLX-23-002385
        Rule ID    : SV-274139r1120405_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : Amazon Linux 2023 must enforce password complexity rules for the root account.
        DiscussMD5 : 0E291B961A7C4DD3364FF8C457A70909
        CheckMD5   : 1C40AD60CD5682BED8B99F28A5B4CCFB
        FixMD5     : EC51653D686B85E820587AD9EF24EEDC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)

    If ($finding) {
        $Status = "NotAFinding"
        $FindingMessage = "Amazon Linux 2023 enforces password complexity rules for the root account."
    }
    else{
        $Status = "Open"
        $FindingMessage = "Amazon Linux 2023 does not enforce password complexity rules for the root account."
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

Function Get-V274140 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274140
        STIG ID    : AZLX-23-002390
        Rule ID    : SV-274140r1120408_rule
        CCI ID     : CCI-000366, CCI-004061
        Rule Name  : SRG-OS-000480-GPOS-00225
        Rule Title : Amazon Linux 2023 must prevent the use of dictionary words for passwords.
        DiscussMD5 : 84854360A9CB67D524177EC02D4EDDBE
        CheckMD5   : 92E0448D5D64E779D5C609074EC9146A
        FixMD5     : 1B094C190D0DAAD4CD941648F3662DEE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "dictcheck"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $foundcount = 0

    $finding | Foreach-Object {
        If ([int](($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1]).replace('"','') -ge 1) {
            $foundcount++
        }
    }

    if (($foundcount -gt 0) -and ($foundcount -eq $finding.count)){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system prevents the use of dictionary words for passwords."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent the use of dictionary words for passwords."
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

Function Get-V274141 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274141
        STIG ID    : AZLX-23-002395
        Rule ID    : SV-274141r1120411_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-OS-000027-GPOS-00008
        Rule Title : Amazon Linux 2023 must limit the number of concurrent sessions to ten for all accounts and/or account types.
        DiscussMD5 : D447C49C1787DBEAD7B0BE2282723F64
        CheckMD5   : 7414C3699612483C7256ED091F0C62C4
        FixMD5     : 1DACA405F6644EC0EC248F80B5ADFE46
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V274142 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274142
        STIG ID    : AZLX-23-002396
        Rule ID    : SV-274142r1120414_rule
        CCI ID     : CCI-000057, CCI-001133
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : Amazon Linux 2023 must automatically exit interactive command shell user sessions after 15 minutes of inactivity.
        DiscussMD5 : 7D4AB74DD9466D2125E61ED83AC236F9
        CheckMD5   : 91A0D19CCF47680109B6FE4D07AA3636
        FixMD5     : 7794EC739128782442649DCB7156D89F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -ir tmout /etc/profile.d/*.sh)

    if ($finding){
        if ([int](($finding | awk '{$2=$2};1' | grep -I -s -i "=").replace(" ", "").split(":")[1].split("=")[1]).replace('"','') ?? 601 -le 600) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system terminates all network connections associated with a communications session at the end of the session or based on inactivity."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not terminate all network connections associated with a communications session at the end of the session or based on inactivity."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not terminate all network connections associated with a communications session at the end of the session or based on inactivity."
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

Function Get-V274143 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274143
        STIG ID    : AZLX-23-002400
        Rule ID    : SV-274143r1120417_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000075-GPOS-00043
        Rule Title : Amazon Linux 2023 must enforce 24 hours/1 day as the minimum password lifetime.
        DiscussMD5 : C2BA91E7DF2AFA3F2BA2D0D3960066F7
        CheckMD5   : BF584DAF81919DC09E04CCBE859F8152
        FixMD5     : 0CE706764FB6F655AA4F67A0187F2BC8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $option = "pass_min_days"

    $finding = $(grep -I -s -i ^[[:blank:]]*$option /etc/login.defs)

    if ($finding -and $finding -notmatch "none"){
        If ([int](($finding | awk '{$2=$2};1').split(" ")[1]).replace('"','') -ge 1) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not enforce 24 hours/1 day as the minimum password lifetime for new user accounts."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not enforce 24 hours/1 day as the minimum password lifetime for new user accounts."
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

Function Get-V274144 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274144
        STIG ID    : AZLX-23-002405
        Rule ID    : SV-274144r1120420_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00226
        Rule Title : Amazon Linux 2023 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.
        DiscussMD5 : 873AD0DBAC79558AD6A9B777F17645B5
        CheckMD5   : B25C34A9F8B70791EB12F70F556F21F4
        FixMD5     : C516099720B201CE977C543823174E60
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*fail_delay /etc/login.defs)

    if ($finding){
        If ([int](($finding | awk '{$2=$2};1').split(" ")[1]).replace('"','') -ge 4) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not enforce a delay of at least four seconds between console logon prompts following a failed logon attempt."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not enforce a delay of at least four seconds between console logon prompts following a failed logon attempt."
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

Function Get-V274145 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274145
        STIG ID    : AZLX-23-002410
        Rule ID    : SV-274145r1120423_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00228
        Rule Title : Amazon Linux 2023 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.
        DiscussMD5 : 6897B7142F5F665D27FDFF634DD9DC84
        CheckMD5   : AB65BBF8FBAA3DF904753D652E255172
        FixMD5     : 35FDBA719B709CC9DC8F01560168FDAC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*umask /etc/profile)
    $finding ??= "Check text: No results found."

    if (($finding | awk '{$2=$2};1').split(" ")[1] -eq "077") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
        if (($finding | awk '{$2=$2};1').split(" ")[1] -eq "000") {
            $SeverityOverride = "CAT_I"
            $Justification = "The 'UMASK' variable is set to '000, therefore this is a finding with the severity raised to a CAT I."
            $FindingMessage += "`r`n"
            $FindingMessage += $Justification
        }
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

Function Get-V274147 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274147
        STIG ID    : AZLX-23-002420
        Rule ID    : SV-274147r1120429_rule
        CCI ID     : CCI-000044
        Rule Name  : SRG-OS-000021-GPOS-00005
        Rule Title : Amazon Linux 2023 must automatically lock an account when three unsuccessful logon attempts occur.
        DiscussMD5 : 49A1E1A77966674222015F7AE1366925
        CheckMD5   : D61D2B8880482D3330346B0A14852C03
        FixMD5     : EF4E3DBEE3A9E0602599F2E2EF1B2F8F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s pam_faillock.so /etc/pam.d/password-auth)
    $finding ??= "Check text: No results found."

    $password_auth_preauth = $(grep -I -s -i "pam_faillock.so.*preauth" /etc/pam.d/password-auth)

    $FindingMessage = "Checking password-auth for correct settings:"
    $FindingMessage += "`r`n"

    if ($password_auth_preauth.startswith("auth")) {
        if ((($password_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "^deny" }).split("=")[1] -in 1..3) {
            $Status = "NotAFinding"
            $FindingMessage += "The system locks an account after three unsuccessful logon attempts."
        }
        else {
            $Status = "Open"
            $FindingMessage += "The system does not lock an account after three unsuccessful logon attempts."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage += "The system's password-auth preauth does not lock an account."
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

Function Get-V274148 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274148
        STIG ID    : AZLX-23-002425
        Rule ID    : SV-274148r1120432_rule
        CCI ID     : CCI-004066
        Rule Name  : SRG-OS-000076-GPOS-00044
        Rule Title : Amazon Linux 2023 must be able to enforce a 60-day maximum password lifetime restriction.
        DiscussMD5 : 9F3328BAC3B3823954B64C372BDE2011
        CheckMD5   : 8EC6E82D1A59CB9FE2F8B841CA6A519D
        FixMD5     : 9274E3ADF0FD002734ACF4EEBDAA718E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow
awk -F: '$5 <= 0 {print $1 " " $5}' /etc/shadow
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        if (!($userlist)){
            $userlist = "No users found in /etc/shadow to evaluate."
            $finding = $userlist
            $FindingDetails += $(FormatFinding $finding) | Out-String
        }
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process /etc/shadow."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $command = @'
awk -F: '($3 >= 1000 || $1 == "root") && $3!=65534 {print $1}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $localusers = $(sh $temp_file)
        if (!($localusers)){
            $localusers = "No users found in /etc/passwd to evaluate."
            $finding = $localusers
            $FindingDetails += $(FormatFinding $finding) | Out-String
        }
        Remove-Item $temp_file
    }
    else {
        $localusers = "Unable to create temp file to process /etc/passwd."
        $finding = $localusers
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    $found = 0

    $userlist | ForEach-Object {
        if ($_.split(" ")[0] -in $localusers) {
            $finding = $_
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "The operating system's maximum time period for existing passwords is not restricted to 60 days for non-system accounts."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system's maximum time period for existing passwords is restricted to 60 days for non-system accounts."
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

Function Get-V274149 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274149
        STIG ID    : AZLX-23-002430
        Rule ID    : SV-274149r1120435_rule
        CCI ID     : CCI-003627, CCI-003628
        Rule Name  : SRG-OS-000118-GPOS-00060
        Rule Title : Amazon Linux 2023 must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
        DiscussMD5 : FFE46F9DB56D04F7FBF1270A89F6378E
        CheckMD5   : E3B2353A6D9AE8BE7CADCA92BC7DA642
        FixMD5     : F33CFBDABDD8630FAAEFC447E66501D9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*inactive /etc/default/useradd)
    $finding ??= "Check text: No results found."

    If (($finding).split("=")[1] -in 0..35) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not disable account identifiers (individuals, groups, roles, and devices) after the password expires."
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

Function Get-V274151 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274151
        STIG ID    : AZLX-23-002440
        Rule ID    : SV-274151r1120441_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-OS-000312-GPOS-00123
        Rule Title : Amazon Linux 2023 must restrict the use of the "su" command.
        DiscussMD5 : ADD4D420D25FB17371C91C5231823E29
        CheckMD5   : 7909A51F167A7CC1B6781CA1B725F43B
        FixMD5     : DBBD056567CDF90DBF48A899AB691A41
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i pam_wheel /etc/pam.d/su | grep -I -v "^#")

    if ($finding){
        $Status = "NotAFinding"
        $FindingMessage = "Amazon Linux 2023 requires users to be members of the 'wheel' group."
    }
    else{
        $Status = "Open"
        $FindingMessage = "Amazon Linux 2023 does not require users to be members of the 'wheel' group."
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

Function Get-V274152 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274152
        STIG ID    : AZLX-23-002445
        Rule ID    : SV-274152r1120738_rule
        CCI ID     : CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : Amazon Linux 2023 must enable the SELinux targeted policy.
        DiscussMD5 : 28180823043013EC3E3BDF8C00580540
        CheckMD5   : 22441576499FCC7297F55AF840115242
        FixMD5     : 197978142847C827A6A3D878CF80BCF6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sestatus | grep "policy name")

    If (($finding | awk '{$2=$2};1') -match "Loaded policy name: targeted") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system verifies correct operation of all security functions."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "'SELinux' is not enforcing the targeted policy."
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

Function Get-V274153 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274153
        STIG ID    : AZLX-23-002450
        Rule ID    : SV-274153r1120713_rule
        CCI ID     : CCI-001084, CCI-002696
        Rule Name  : SRG-OS-000134-GPOS-00068
        Rule Title : Amazon Linux 2023 must use a Linux Security Module configured to enforce limits on system services.
        DiscussMD5 : F8A2BB0C24D8FA8F39E3E76792982ADE
        CheckMD5   : 0B216D3AFD6F508365B73013B56ABD75
        FixMD5     : 9AF32EAB9824DCB9A916C3872B5417EA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(getenforce)
    $finding_2 = $(grep -I "SELINUX=" /etc/selinux/config)
    $finding_2 ??= "Check text: No results found."
    $better_finding_2 = $(grep -I "^SELINUX=" /etc/selinux/config | grep -I -v "#")

    If (($finding -eq "Enforcing") -and $better_finding_2) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system verifies correct operation of all security functions."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not verify correct operation of all security functions."
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

Function Get-V274154 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274154
        STIG ID    : AZLX-23-002455
        Rule ID    : SV-274154r1120450_rule
        CCI ID     : CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : Amazon Linux 2023 must automatically lock an account when three unsuccessful logon attempts occur.
        DiscussMD5 : E62FD69391F2A982BA761018B37B8CB6
        CheckMD5   : 0FBFD72A902A14E4C46642BB22D30022
        FixMD5     : 4F3D2863527970373620FC2E2E53A993
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*deny /etc/security/faillock.conf)
    $finding ??= "Check text: No results found."

    If ((($finding | awk '{$2=$2};1').replace(" ","")).split("=")[1] -in 1..3) {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/security/faillock.conf' file is configured to lock an account after three unsuccessful logon attempts"
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '/etc/security/faillock.conf' file is not configured to lock an account after three unsuccessful logon attempts"
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

Function Get-V274155 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274155
        STIG ID    : AZLX-23-002460
        Rule ID    : SV-274155r1120453_rule
        CCI ID     : CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : Amazon Linux 2023 must automatically lock the root account until the root account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.
        DiscussMD5 : E62FD69391F2A982BA761018B37B8CB6
        CheckMD5   : 0CCA062FE18F9C9D921F8CB5A64FBA95
        FixMD5     : 6C82C3EFC8E4DD0155D84C37C6AD14FA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*even_deny_root /etc/security/faillock.conf)

    If ($finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/security/faillock.conf' file is configured to log user name information when unsuccessful logon attempts occur, including root."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '/etc/security/faillock.conf' file is not configured to log user name information when unsuccessful logon attempts occur, incuding root."
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

Function Get-V274156 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274156
        STIG ID    : AZLX-23-002465
        Rule ID    : SV-274156r1120456_rule
        CCI ID     : CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : Amazon Linux 2023 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes occur.
        DiscussMD5 : E62FD69391F2A982BA761018B37B8CB6
        CheckMD5   : 94EEF1F434249F7FE3FF1796491B08A7
        FixMD5     : 334E54072776F5477FCF9A50975E143F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*fail_interval /etc/security/faillock.conf)
    $finding ??= "Check text: No results found."

    If ((($finding | awk '{$2=$2};1').replace(" ","")).split("=")[1] ?? 901 -le 900) {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/security/faillock.conf' file is configured to lock an account after three unsuccessful logon attempts."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '/etc/security/faillock.conf' file is not configured to lock an account after three unsuccessful logon attempts."
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

Function Get-V274157 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274157
        STIG ID    : AZLX-23-002470
        Rule ID    : SV-274157r1120459_rule
        CCI ID     : CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : Amazon Linux 2023 must maintain an account lock until the locked account is released by an administrator.
        DiscussMD5 : E62FD69391F2A982BA761018B37B8CB6
        CheckMD5   : 53E165461F539525281D4253E0C44730
        FixMD5     : CAFB91780EAEC518D8766FE528B22BF9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*unlock_time /etc/security/faillock.conf)
    $finding ??= "Check text: No results found."

    If ((($finding | awk '{$2=$2};1').replace(" ","")).split("=")[1] -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/security/faillock.conf' file is configured to lock an account after three unsuccessful logon attempts"
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '/etc/security/faillock.conf' file is not configured to lock an account after three unsuccessful logon attempts"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note - 'unlock_time=' or 'unlock_time =' was used to check settings."

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

Function Get-V274158 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274158
        STIG ID    : AZLX-23-002475
        Rule ID    : SV-274158r1120727_rule
        CCI ID     : CCI-000382, CCI-002314
        Rule Name  : SRG-OS-000096-GPOS-00050
        Rule Title : Amazon Linux 2023 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) and vulnerability assessments.
        DiscussMD5 : 419543867847F4903E42DE0A010E0C9D
        CheckMD5   : 5DCF796CB79657954391FD2A53EB5584
        FixMD5     : 1C670BCD5169CB5CBF28A42F273E3E09
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa firewalld)

    if ($finding) {
        $finding = $(firewall-cmd --list-all-zones | grep -e "active" -e "services")

        $Status = "Not_Reviewed"
        $FindingMessage = "Inspect the firewall configuration and running services to verify it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have an enabled application firewall."
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

Function Get-V274160 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274160
        STIG ID    : AZLX-23-002485
        Rule ID    : SV-274160r1120663_rule
        CCI ID     : CCI-000135, CCI-000764, CCI-000804
        Rule Name  : SRG-OS-000104-GPOS-00051
        Rule Title : Amazon Linux 2023 must ensure all interactive users have unique User IDs (UIDs).
        DiscussMD5 : ACA1C2F3111804D9FC14FB4351BFF949
        CheckMD5   : AD276E29863DF78EFE9241DA458756BC
        FixMD5     : 90E2F4C0583A429EC9822086C71C256A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd
'@
    $temp_file = $(umask 0077;mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file){
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file

        If ($Finding) {
            $Status = "Open"
            $FindingMessage = "The operating system contains duplicate User IDs (UIDs) for interactive users."
        }
        Else {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system contains no duplicate User IDs (UIDs) for interactive users."
        }
    }
    else{
        $Status = "Not_Reviewed"
        $finding = "Unable to create temp file to process check."
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

Function Get-V274161 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274161
        STIG ID    : AZLX-23-002489
        Rule ID    : SV-274161r1120471_rule
        CCI ID     : CCI-000192, CCI-000193, CCI-004066
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : Amazon Linux 2023 must ensure the password complexity module is enabled in the password-auth file.
        DiscussMD5 : 8E199C45D1A23048FB64ACFC730BFCFC
        CheckMD5   : 0A8F89A0DDFCE799A47A0131D4B1F7ED
        FixMD5     : 0014BA7E60BF2DCBE469FF43751A13A7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s pam_pwquality /etc/pam.d/password-auth)
    $finding ??= "Check text: No results found."
    $found = 0

    $finding | Foreach-Object {
        If ((($_ | awk '{$2=$2};1').startswith("password required")) -and ($_ -match "pam_pwquality.so")) {
            $found++
        }
    }

    If ($found -gt 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system uses 'pwquality' to enforce the password complexity rules."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not use 'pwquality' to enforce the password complexity rules."
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

Function Get-V274162 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274162
        STIG ID    : AZLX-23-002490
        Rule ID    : SV-274162r1120474_rule
        CCI ID     : CCI-000803, CCI-004062
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : Amazon Linux 2023 password-auth must be configured to use a sufficient number of hashing rounds.
        DiscussMD5 : 8BAF1E733A6FA75401507A59B94F4B5F
        CheckMD5   : 70366A8C3F4B96DB64D6C7B53CD8CF02
        FixMD5     : 585F41AEA21EB79F198C99F62D26D968
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i rounds /etc/pam.d/password-auth)

    if ($finding){
        If ([int](((($finding | awk '{$2=$2};1').split(" ")) | Where-Object {$_ -match "rounds"}).split("=")[1]).replace('"','') -ge 100000) {
            $Status = "NotAFinding"
            $FindingMessage = "The number of rounds for the password hashing algorithm is configured."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The number of rounds for the password hashing algorithm is not configured."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The number of rounds for the password hashing algorithm is not configured."
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

Function Get-V274163 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274163
        STIG ID    : AZLX-23-002495
        Rule ID    : SV-274163r1120477_rule
        CCI ID     : CCI-000803, CCI-004062
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : Amazon Linux 2023 system-auth must be configured to use a sufficient number of hashing rounds.
        DiscussMD5 : 58BF57002E180CC18C02DAE32E82A48F
        CheckMD5   : 11BD349F3FB407CECD6B50164708FB45
        FixMD5     : 5A394FD6717225C1F8880D599AF2EA67
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i rounds /etc/pam.d/system-auth)

    if ($finding){
        If ([int](((($finding | awk '{$2=$2};1').split(" ")) | Where-Object {$_ -match "rounds"}).split("=")[1]).replace('"','') -ge 100000) {
            $Status = "NotAFinding"
            $FindingMessage = "The number of rounds for the password hashing algorithm is configured."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The number of rounds for the password hashing algorithm is not configured."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The number of rounds for the password hashing algorithm is not configured."
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

Function Get-V274164 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274164
        STIG ID    : AZLX-23-002500
        Rule ID    : SV-274164r1120480_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : Amazon Linux 2023 must ensure a sticky bit be set on all public directories.
        DiscussMD5 : 6A23F803D2B0B4E5F07FE79C52DE6294
        CheckMD5   : 822A36484CE3627A953DBFEA3750C204
        FixMD5     : E201D772E05F372325D1F62C75DCBF0B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        [array]$filelist = $(sh $temp_file)
        Remove-Item $temp_file
        $found = 0
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
        $found = 1
    }
    $found = 0

    $filelist | ForEach-Object {
        if (!($_.startswith("drwxrwxrwxt")) -and ($_ -notmatch "/tmp/.dotnet")){
            $finding = $_
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($Found -eq 0){
        $Status = "NotAFinding"
        $FindingMessage = "All world-writable directories have the sticky bit set."
    }
    else{
        $Status = "Open"
        $FindingMessage = "All world-writable directories do not have the sticky bit set."
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

Function Get-V274165 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274165
        STIG ID    : AZLX-23-002505
        Rule ID    : SV-274165r1120483_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : Amazon Linux 2023 must ensure all world-writable directories be owned by root, sys, bin, or an application user.
        DiscussMD5 : 6A23F803D2B0B4E5F07FE79C52DE6294
        CheckMD5   : C64191803D95100C8D80D91A357E584D
        FixMD5     : FC5A274F9047268062A33EEBD62B98E8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $partitions = $(lsblk -o MOUNTPOINT | awk '{if ($1) print $1;}' | grep -I -s -v MOUNTPOINT | grep -I -s -v "[SWAP]")

    $partitions | ForEach-Object {
        $finding = $(find $_ -xdev -type d -perm -0002 -uid +999 -print)
        if ($finding) {
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    If ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "All world-writable directories are not owned by a system account, given the assumption that only system accounts have a uid lower than 1000."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "All world-writable directories are owned by a system account, given the assumption that only system accounts have a uid lower than 1000."
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

Function Get-V274166 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274166
        STIG ID    : AZLX-23-002510
        Rule ID    : SV-274166r1120486_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : Amazon Linux 2023 must terminate idle user sessions.
        DiscussMD5 : 7244D89BD1F09FD68E7C62EAC72F0988
        CheckMD5   : 6A401832367C6537B5D9331B57435420
        FixMD5     : 3627FA68ED498209ECA6350B664D490C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*stopidlesessionsec /etc/systemd/logind.conf)

    If ($finding){
        If ((($finding | awk '{$2=$2};1').replace(" ","")).split("=")[1] -eq 900) {
            $Status = "NotAFinding"
            $FindingMessage = "Amazon Linux 2023 logs out sessions that are idle for 15 minutes."
        }
        else{
            $Status = "Open"
            $FindingMessage = "Amazon Linux 2023 does not log out sessions that are idle for 15 minutes."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "Amazon Linux 2023 does not log out sessions that are idle for 15 minutes."
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

Function Get-V274167 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274167
        STIG ID    : AZLX-23-002515
        Rule ID    : SV-274167r1120489_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-001464, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Amazon Linux 2023 must enable auditing of processes that start prior to the audit daemon.
        DiscussMD5 : 9202DF3B7F7E3904F68BCB2325A25740
        CheckMD5   : B4044539D6B3AA052AAEFFEF635E577B
        FixMD5     : E606A01B5004235699FA58588B1EDA31
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grubby --info=ALL | grep args | grep 'audit=1')

    if ($finding){
        $finding_2 = $(grep -I -s audit /etc/default/grub | grep -I -v "^#")
        $finding_2 ??= "Check text: No results found."

        if (($finding_2 | awk '{$2=$2};1').split(" ") | where-Object {$_ -match "audit=1"}){
            $Status = "NotAFinding"
            $FindingMessage = "GRUB 2 is configured to enable auditing of processes that start prior to the audit daemon and is enabled by default to persist in kernel updates."
        }
        else{
            $Status = "Open"
            $FindingMessage = "GRUB 2 is configured to enable auditing of processes that start prior to the audit daemon but is not enabled by default to persist in kernel updates."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "GRUB 2 is not configured to enable auditing of processes that start prior to the audit daemon."
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

Function Get-V274168 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274168
        STIG ID    : AZLX-23-002520
        Rule ID    : SV-274168r1120492_rule
        CCI ID     : CCI-001464, CCI-001849
        Rule Name  : SRG-OS-000254-GPOS-00095
        Rule Title : Amazon Linux 2023 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.
        DiscussMD5 : 29424EB88FEEB26DB90764AB7F781726
        CheckMD5   : A72EF7B738488CF1B89D4274CB7AA2D2
        FixMD5     : CC475DD2A91465DD09A0D493443D9FDD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grubby --info=ALL | grep -I args | grep -I 'audit_backlog_limit=')

    if ($finding){
        $correct_limit = 0
        $finding | Foreach-Object {
            if ($_ -match "audit_backlog_limit"){
                if ([int](((($_ | awk '{$2=$2};1').split(" ")).replace('"','') | Where-Object {$_ -match "audit_backlog_limit"}).split("=")[1]) -ge 8192){
                    $correct_limit++
                }
            }
        }

        if ($correct_limit -eq $Finding.count){
            $Status = "NotAFinding"
            $FindingMessage = "The operating system allocates a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system does not allocate a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon for at least one kernel."
        }
        }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The operating system allocates a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon."
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

Function Get-V274169 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274169
        STIG ID    : AZLX-23-002535
        Rule ID    : SV-274169r1120495_rule
        CCI ID     : CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000312-GPOS-00123
        Rule Title : Amazon Linux 2023 must enable discretionary access control on hardlinks.
        DiscussMD5 : 22664CF075C9C5185CFD7BE2E50041EA
        CheckMD5   : 617F775918C915F5C610A2E579FB3C9E
        FixMD5     : 755F43B9D5D3B63F4AD37F0E7EB14BEF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl fs.protected_hardlinks)
    $finding ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is configured to enable DAC on hardlinks."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to enable DAC on hardlinks."
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

Function Get-V274170 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274170
        STIG ID    : AZLX-23-002540
        Rule ID    : SV-274170r1120498_rule
        CCI ID     : CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000312-GPOS-00123
        Rule Title : Amazon Linux 2023 must enable kernel parameters to enforce discretionary access control on symlinks.
        DiscussMD5 : 02E2D8999FE69DA0158DDE3A7445488F
        CheckMD5   : D976121C0928ED3054AFF051255195B2
        FixMD5     : 2CCAB012F2AE13E30E2FAAA7BA3DE6C6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl fs.protected_symlinks)
    $finding ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is configured to enable DAC on hardlinks."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to enable DAC on hardlinks."
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

Function Get-V274173 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274173
        STIG ID    : AZLX-23-002555
        Rule ID    : SV-274173r1120507_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-OS-000324-GPOS-00125
        Rule Title : Amazon Linux 2023 debug-shell systemd service must be disabled.
        DiscussMD5 : EDC2817D2B3F8A32702DD07C6D9D49CC
        CheckMD5   : DD0BF58D6DB54E7C3FF1EC376E143E53
        FixMD5     : B744FF1BE38F81BAB83065DA510A9A02
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl status debug-shell.service)

    If ($finding -match "Loaded: masked") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is configured to mask the debug-shell systemd service."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to mask the debug-shell systemd service."
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

Function Get-V274174 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274174
        STIG ID    : AZLX-23-002560
        Rule ID    : SV-274174r1120510_rule
        CCI ID     : CCI-004923
        Rule Name  : SRG-OS-000355-GPOS-00143
        Rule Title : Amazon Linux 2023 chrony must be configured with a maximum interval of 24 hours between requests sent to a USNO server or a time server designated for the appropriate DOD network.
        DiscussMD5 : 12688CEFCCFA8CA66D026CA6D97642FC
        CheckMD5   : F1D0D43114E08FB837687BD92E40D02F
        FixMD5     : B4DB12FE8A4CBEA86BFB6C94A3839D96
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Get-Process | grep -I -s chronyd)
    $finding_2 = ""
    $found = 0

    if ($finding) {
        $finding = $(grep -I -s maxpoll /etc/chrony.conf | grep -I -v "^#")
        $finding ??= "Check text: No results found."

        $finding | Foreach-Object {
            $maxpoll = $($_ | grep -I -s -oP '(?<=maxpoll )[^ ]*')
            if (($_.ToLower()).startswith("server") -and ([int]$maxpoll -le 16)) {
                $found++
            }
        }

        $finding_2 = $(grep -I -s -i ^[[:blank:]]*server /etc/chrony.conf)
        $finding_2 ??= "Check text: No results found."

        if ($found -eq $finding.count){
            $Status = "Not_Reviewed"
            $FindingMessage = "The operating system is securely comparing internal information system clocks at least every 24 hours.  Verify the 'chrony.conf' file is configured to an authoritative DoD time source."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system is not securely comparing internal information system clocks at least every 24 hours."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system is not securely comparing internal information system clocks at least every 24 hours with an NTP server."
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

Function Get-V274175 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274175
        STIG ID    : AZLX-23-002565
        Rule ID    : SV-274175r1120659_rule
        CCI ID     : CCI-001890, CCI-004922, CCI-004926
        Rule Name  : SRG-OS-000356-GPOS-00144
        Rule Title : Amazon Linux 2023 must synchronize internal information system clocks to the authoritative time source at least every 24 hours.
        DiscussMD5 : ACAE0248C86D131270CDFAAD318110B0
        CheckMD5   : A01513BED7F5C227FBD9BB50F2E162E7
        FixMD5     : EF67CD3C1979E065380CD7D1F9F168AC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Get-Process | grep -I -s chronyd)
    $finding_2 = ""
    $found = 0

    if ($finding) {
        $finding = $(grep -I -s maxpoll /etc/chrony.conf | grep -I -v "^#")
        $finding ??= "Check text: No results found."

        $finding | Foreach-Object {
            $maxpoll = $($_ | grep -I -s -oP '(?<=maxpoll )[^ ]*')
            if (($_.ToLower()).startswith("server") -and ([int]$maxpoll -le 16)) {
                $found++
            }
        }

        $finding_2 = $(grep -I -s -i ^[[:blank:]]*server /etc/chrony.conf)
        $finding_2 ??= "Check text: No results found."

        if ($found -eq $finding.count){
            $Status = "Not_Reviewed"
            $FindingMessage = "The operating system is securely comparing internal information system clocks at least every 24 hours.  Verify the 'chrony.conf' file is configured to an authoritative DoD time source."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system is not securely comparing internal information system clocks at least every 24 hours."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system is not securely comparing internal information system clocks at least every 24 hours with an NTP server."
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

Function Get-V274176 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274176
        STIG ID    : AZLX-23-002570
        Rule ID    : SV-274176r1120655_rule
        CCI ID     : CCI-001744
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : Amazon Linux 2023 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.
        DiscussMD5 : 7721CEACF730B18F2B91AA2F369650BF
        CheckMD5   : F094F79B7BA741EC813EF85E846721F3
        FixMD5     : F823F870AC8C06932642519CFF00A590
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)
    $finding_2 = $(grep "aide --check" /etc/crontab /etc/cron.*/* /var/spool/cron/root)

    if ($Finding) {
        if ($finding_2) {
            $cron_daily = $(grep -H "aide --check" /etc/cron.daily/*)
            if ($cron_daily){
                $FindingMessage = "AIDE is installed and AIDE Check is executed from cron daily."
            }
            $cron_weekly = $(grep -H "aide --check" /etc/cron.weekly/*)
            if ($cron_weekly){
                $FindingMessage = "AIDE is installed and AIDE Check is executed from cron weekly."
            }
            $cron_monthly = $(grep -H "aide --check" /etc/cron.monthly/*)
            if ($cron_monthly) {
                $FindingMessage = "AIDE is installed; however, AIDE Check is executed from cron monthly."
            }
            if ($cron_daily -or $cron_weekly){
                $Status = "NotAFinding"
            }
            else{
                $cron_check = $(grep -H "aide --check" /etc/crontab /etc/cron.d/*)
                if ($cron_check) {
                    $cronrun = $($finding_2 | awk '{if($3$4=="**") print $5 ; else print "F"}')
                    if ($cronrun -eq "F") {
                        $Status = "Open"
                        $FindingMessage = "AIDE is installed; however, AIDE Check is NOT executed at least weekly."
                    }
                    elseif ($cronrun -eq '*') {
                        $Status = "NotAFinding"
                        $FindingMessage = "AIDE is installed and AIDE Check is executed from cron daily."
                    }
                    else {
                        $Status = "NotAFinding"
                        $FindingMessage = "AIDE is installed and AIDE Check is executed from cron weekly."
                    }
                }
            }

            if (($finding_2 | grep -I -s -i "mail") -and $(rpm -qa s-nail)) {
                $FindingMessage += "  The SA is notified via eMail."
            }
            else {
                $Status = "Open"
                $FindingMessage += "  The SA is NOT notified via eMail."
            }

       }
       else {
           $FindingMessage = "AIDE is installed; however, it is NOT executed from cron. Ask the SA how file integrity checks are performed on the system."
       }
    }
    else {
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
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

Function Get-V274177 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274177
        STIG ID    : AZLX-23-002575
        Rule ID    : SV-274177r1120519_rule
        CCI ID     : CCI-003992
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : Amazon Linux 2023 must prevent the loading of a new kernel for later execution.
        DiscussMD5 : 9B41462F96859266A065EAA0D5F1DC47
        CheckMD5   : 39F60614D06D9F733EC1ABF89795526F
        FixMD5     : 0D13F585D9AC1E67A01A1A103C6685BF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl kernel.kexec_load_disabled)
    $finding ??= "Check text: No results found."

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is not configured to disable kernel image loading."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to disable kernel image loading."
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

Function Get-V274178 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274178
        STIG ID    : AZLX-23-002580
        Rule ID    : SV-274178r1120522_rule
        CCI ID     : CCI-001764
        Rule Name  : SRG-OS-000368-GPOS-00154
        Rule Title : Amazon Linux 2023 must prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory.
        DiscussMD5 : EE5754F12B48143C3CC2A18D65ECD016
        CheckMD5   : 670629413D762B655C437AFC39F1449F
        FixMD5     : 4917182B6C994FE8BFDCD076C12D47EB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Test-Path /sys/firmware/efi)

    If ($finding) {
        $finding = $(mount | grep -I -s '\s/boot/efi\s')

        If ($Finding -match "nosuid") {
            $Status = "NotAFinding"
            $FindingMessage = "The /boot/efi directory is mounted with the 'nosuid' option."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The /boot/efi directory is not mounted with the 'nosuid' option."
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingMessage = "This is not applicable on systems that use a basic Input/Output System BIOS."
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

Function Get-V274179 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274179
        STIG ID    : AZLX-23-002585
        Rule ID    : SV-274179r1120525_rule
        CCI ID     : CCI-001764
        Rule Name  : SRG-OS-000368-GPOS-00154
        Rule Title : Amazon Linux 2023 must mount /dev/shm with the nodev option.
        DiscussMD5 : C66743147AAFFAAD0D7EC6DAB69C79E2
        CheckMD5   : 9749D00580AA77AA7980CDDDB5237881
        FixMD5     : 358947629A34E8D1FB0A706322072032
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $mountpoint = " /dev/shm "
    $option = "nodev"
    $finding = $(mount | grep -I $mountpoint)

    If ($Finding -match $option) {
        $Status = "NotAFinding"
        $FindingMessage = "'$mountpoint' is mounted with the $option option."
    }
    else {
        $Status = "Open"
        $FindingMessage = "'$mountpoint' is not mounted with the $option option."
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

Function Get-V274180 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274180
        STIG ID    : AZLX-23-002590
        Rule ID    : SV-274180r1120528_rule
        CCI ID     : CCI-001764
        Rule Name  : SRG-OS-000368-GPOS-00154
        Rule Title : Amazon Linux 2023 must mount /dev/shm with the nosuid option.
        DiscussMD5 : 0F45CABE74C9CD25A9264392E42FF97D
        CheckMD5   : 8A3161A3C7FDB55339D08AD3EFCF4D1E
        FixMD5     : C033D5084FAC623F1FEE19E7049D73D4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $mountpoint = " /dev/shm "
    $option = "nosuid"
    $finding = $(mount | grep -I $mountpoint)

    If ($Finding -match $option) {
        $Status = "NotAFinding"
        $FindingMessage = "'$mountpoint' is mounted with the $option option."
    }
    else {
        $Status = "Open"
        $FindingMessage = "'$mountpoint' is not mounted with the $option option."
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

Function Get-V274181 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274181
        STIG ID    : AZLX-23-002595
        Rule ID    : SV-274181r1120531_rule
        CCI ID     : CCI-004046
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : Amazon Linux 2023 must ensure the pcscd service is active.
        DiscussMD5 : 397D6AAB3231B5856ECE2CF2A974E039
        CheckMD5   : 31CC802CDC18C2D2188FF79E83B3327B
        FixMD5     : 46431AAB75812B045A7A64DB35E67951
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $service = "pcscd.socket"
    $finding = $(systemctl is-active $service)

    if ($finding -eq "active"){
        $Status = "NotAFinding"
        $FindingMessage = "The '$service' service is active."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The '$service' service is not active."
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

Function Get-V274182 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274182
        STIG ID    : AZLX-23-002600
        Rule ID    : SV-274182r1120729_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-OS-000378-GPOS-00163
        Rule Title : Amazon Linux 2023 file system automount function must be disabled unless required.
        DiscussMD5 : B550EC29A3BF0EF47BE665F3B6004911
        CheckMD5   : DD035B7832C6C5E69F4FEDFFAF8934AA
        FixMD5     : 2A24080A3C1744260F1710C11D5EE6D8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl | grep autofs)

    if ($finding){
        $finding = $(systemctl is-enabled autofs)

        If ($finding){
            if ($finding -in @("masked", "disabled","Failed to get unit file state for autofs.service for autofs")) {
                $Status = "NotAFinding"
                $FindingMessage = "The file system automount function has been disabled."
            }
            else{
                $Status = "Open"
                $FindingMessage = "The file system automount function has not been disabled."
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingMessage = "The file system automount function has been disabled."
        }
    }
    else{
        $Status = "Not_Applicable"
        $FindingMessage = "The file system automount service is not installed."
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

Function Get-V274184 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274184
        STIG ID    : AZLX-23-002610
        Rule ID    : SV-274184r1120540_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00192
        Rule Title : Amazon Linux 2023 must implement nonexecutable data to protect its memory from unauthorized code execution.
        DiscussMD5 : F48B5B755A02D94799959778CD5C059C
        CheckMD5   : 795BEE3AA34C35C4C063FD00CB542593
        FixMD5     : 4CAF32858726E3C63AAB698B8FE68876
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(dmesg | grep -I -s "[NX|DX]*protection")

    if ($finding -match "NX \(Execute Disable\) protection\: active") {
        $Status = "NotAFinding"
        $FindingMessage = "NX support is enabled."
    }
    else {
        $Status = "Open"
        $FindingMessage = "NX support is not enabled."
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

Function Get-V274185 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274185
        STIG ID    : AZLX-23-002615
        Rule ID    : SV-274185r1120543_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-OS-000437-GPOS-00194
        Rule Title : Amazon Linux 2023 must remove all software components after updated versions have been installed.
        DiscussMD5 : 7EA67A9B53646BB4DAFD6084676791EA
        CheckMD5   : D4466E192FF828F3D373911E80AC9B1A
        FixMD5     : 9A45F1B148B53BA4E59C1C73FAC9E296
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i ^[[:blank:]]*clean_requirements_on_remove /etc/dnf/dnf.conf)
    $finding ??= "Check text: No results found."

    if ((($finding | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -in @("1", "True", "yes")){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system removes all software components after updated versions have been installed."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not remove all software components after updated versions have been installed."
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

Function Get-V274186 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274186
        STIG ID    : AZLX-23-002620
        Rule ID    : SV-274186r1120546_rule
        CCI ID     : CCI-000044
        Rule Name  : SRG-OS-000021-GPOS-00005
        Rule Title : Amazon Linux 2023 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.
        DiscussMD5 : 1224BE4EBC4A784FFEDB83957122DADC
        CheckMD5   : AE704ADFCE4FDA1D8019B3446B20DB07
        FixMD5     : 3F3BB75463417638768E034C875F0D53
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s pam_faillock.so /etc/pam.d/system-auth)
    $finding ??= "Check text: No results found."

    $system_auth_preauth = $(grep -I -s -n "auth.*pam_faillock.so.*preauth" /etc/pam.d/system-auth | grep -I -s -v '^#')
    $system_auth_unix = $(grep -I -s -n "auth.*pam_unix.so" /etc/pam.d/system-auth)

    if ($finding -match "preauth"){
        if ([int]$system_auth_preauth.split(":")[0] -lt [int]$system_auth_unix.split(":")[0]) {
            $Status = "NotAFinding"
            $FindingMessage = "The pam_faillock.so module with the 'preauth' line is present in the '/etc/pam.d/system-auth' file and comes before pam_unix.so."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The pam_faillock.so module with the 'preauth' line is present in the '/etc/pam.d/system-auth' file but comes after pam_unix.so."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The pam_faillock.so module with the 'preauth' line is not present in the '/etc/pam.d/system-auth' file."
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

Function Get-V274187 {
    <#
    .DESCRIPTION
        Vuln ID    : V-274187
        STIG ID    : AZLX-23-005000
        Rule ID    : SV-274187r1120715_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164, CCI-000172
        Rule Name  : SRG-OS-000462-GPOS-00206
        Rule Title : Amazon Linux 2023 audit system must protect logon user identifiers (UIDs) from unauthorized change.
        DiscussMD5 : 57AE1F2144457E85A21C05D88A11BDF3
        CheckMD5   : 850407A078BE460A73A57909CA8A4EA8
        FixMD5     : DE29413D9832AE27E0D6455078CF40EC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -I -s -i immutable /etc/audit/audit.rules)
    $finding ??= "Check text: No results found."

    If ($Finding.ToLower() -eq "--loginuid-immutable") {
        $Status = "NotAFinding"
        $FindingMessage = "The audit system prevents unauthorized changes to logon UIDs."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit system does not prevent unauthorized changes to logon UIDs."
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

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAAhL6E8jqdeZh+
# l0s8IE18FQXmWa+x96jmALDj+G1XwqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCAfL3Zd6otEutFaV/pCfPYMmS1GkoUpAvgGftW7sXf2YjANBgkqhkiG9w0BAQEF
# AASCAQCbCSO+AP5Bt2ZV+6SP0tq6Lv7xpE1/aXvDqaZlPRexoVleJ+7buGMpQwMM
# 8ZC1AEmRR9KcTVoQbiUt+qaCs1k5YKmZqAkIgfYi2PynBTq38zRii4dCnGgDK+Ow
# inh5EKJRIOxT668hn7ql+ztj//50W+yCm7nxWyHFcHYeeH57bcjiYadKYcXPIVVh
# 5M7ukSODwsxAqukxEz8D5OdDBi2gMsmWlhQD6MCZtKLJCOA8gcf+ixNUOqNAG5e4
# EIt5L2BkY8DRpqPq8GNR9u2ZWuq42LhMPaaPxmmDfOrTZzjlIVl1ZAkYqvgHXHDq
# hLMFVfh9Sf4xxQ7rQ6/Py7lahYDroYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTAxMFowLwYJKoZIhvcNAQkEMSIEIIpCd0ulg4cwmeuznfuAL57oAisS
# w1397l8IguvKaLhwMA0GCSqGSIb3DQEBAQUABIICACgSyHRDnu09aj1jSsVVf3hw
# xTqECmY8L4cSh4yMahLLbNxoaL8PBnGhnzcL99fnrKSyW9cVN2KxWvNeqdAwFY5y
# PdpO9ZKygHCBA19giz0zfTkH7yQqRn0q84VDC0VjVnR01d/m/YD0oaZS0SP6BrOS
# QHCsiIR3OsNUJL/dhpz7EpqdySJ/ceGogxXvXduhMlnAhVnVflX5Bg1YCuj39kX3
# gkJbb7AfqA9uhwWL9zqeJ/BThIks98H5y4gEpibELzyLVkuGIDTPzkXlRbwYftwI
# 7IdinebqLPB2bQ9aR/fBNmXiwKi2eQKp/QaMLf4FjHdzXbPBjtkzLFXxfFRK6vIR
# /zECp4b/w5uJWinEjTkOycA6WeWyRiuxlvFAh+dP4Y+vOSu83huPrbmJ5UqYb6oI
# WdAxDpGYwT2PGMvV28DtG9hLdCtryXm+O4MBG4+uYh+ki+xucCbfPLaAz+gyK4iT
# 5NK7vCU7xvlu9SRW/3tMw0spXT40A612iFaSM00IPqG3GKSF/bGcWbiz6ATeM7KF
# L26n+X/lYP7SChQy67q0C9uCKKQH4lqgWaafJHTz81S08rswC+NabYFLj+30LRt6
# IIfzCK1v4cLyGm7sGcb5WTgoivznij1R61g1otmRTBrjHTsypd10vaY32A44onEc
# 7peaCUHUA3ydjin6rtdt
# SIG # End signature block
