##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft IIS 10.0 Site
# Version:  V2R12
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V218735 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218735
        STIG ID    : IIST-SI-000201
        Rule ID    : SV-218735r1022667_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The IIS 10.0 website session state must be enabled.
        DiscussMD5 : A367D4E03CAD617F0F64ADE69B4FD99B
        CheckMD5   : E67C706308397A47CD0AC75792034AF0
        FixMD5     : 1D95B1A4631DF06AE85D9E64F0380C28
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $EnabledFeature = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^Web-Asp-Net|^IIS-ASPNET)" -and $_.Enabled -eq $true}
    if (-not($EnabledFeature)) {
        $Status = "Not_Applicable"
        $FindingDetails += "ASP.NET is not installed so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.web/sessionState -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name mode
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Mode = Powershell.exe -NoProfile -Command $CommandSB

        if ($Mode -eq "InProc") {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }

        $FindingDetails += "Mode is set to '$($Mode)'" | Out-String
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

Function Get-V218736 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218736
        STIG ID    : IIST-SI-000202
        Rule ID    : SV-218736r1022669_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The IIS 10.0 website session state cookie settings must be configured to Use Cookies mode.
        DiscussMD5 : 7493CE4E76F9287B57D53453C311FCCF
        CheckMD5   : B8AD43C98220BA0EF98C4D4B59F54753
        FixMD5     : 96C449FEFBFB810D6426AB6C3035CA11
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $EnabledFeature = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^Web-Asp-Net|^IIS-ASPNET)" -and $_.Enabled -eq $true}
    if (-not($EnabledFeature)) {
        $Status = "Not_Applicable"
        $FindingDetails += "ASP.NET is not installed so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.web/sessionState -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name cookieless
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Cookieless = Powershell.exe -NoProfile -Command $CommandSB

        if ($Cookieless -eq "UseCookies") {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }

        $FindingDetails += "Cookie Settings is set to '$($Cookieless)'" | Out-String
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

Function Get-V218737 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218737
        STIG ID    : IIST-SI-000203
        Rule ID    : SV-218737r1022671_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : A private IIS 10.0 website must only accept Secure Socket Layer (SSL) connections.
        DiscussMD5 : AB956EF9C261E12C7144487ECCA022E4
        CheckMD5   : 1870060E977913011A1AAC3D3E99344E
        FixMD5     : 937BE8BC0B99CC320FD8E38BC46CCB5C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/access -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Access = Powershell.exe -NoProfile -Command $CommandSB
        $SslFlags = $Access.sslFlags -split ","

        if ("Ssl" -in $SslFlags) {
            $Status = "NotAFinding"
            $FindingDetails += "Require SSL is enabled"
        }
        else {
            $FindingDetails += "Require SSL is NOT enabled" | Out-String
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

Function Get-V218738 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218738
        STIG ID    : IIST-SI-000204
        Rule ID    : SV-218738r1022673_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : A public IIS 10.0 website must only accept Secure Socket Layer (SSL) connections when authentication is required.
        DiscussMD5 : AB956EF9C261E12C7144487ECCA022E4
        CheckMD5   : 00DF67D841104E461833FC5A8636F557
        FixMD5     : 5585A1F04DF8626629E869684618332D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/access -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Access = Powershell.exe -NoProfile -Command $CommandSB
        $SslFlags = $Access.sslFlags -split ","

        if ("Ssl" -in $SslFlags) {
            $Status = "NotAFinding"
            $FindingDetails += "Require SSL is enabled"
        }
        else {
            $FindingDetails += "Require SSL is NOT enabled" | Out-String
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

Function Get-V218739 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218739
        STIG ID    : IIST-SI-000206
        Rule ID    : SV-218739r1022675_rule
        CCI ID     : CCI-000139, CCI-001464
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : Both the log file and Event Tracing for Windows (ETW) for each IIS 10.0 website must be enabled.
        DiscussMD5 : DA633713224A0F4EC5CE9E20A8C2A373
        CheckMD5   : D1AE586493ACB8C08740E1E93889999D
        FixMD5     : A458689BBB16B3723E8FC0EA5B02FFA5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object logFile
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WebSite = Powershell.exe -NoProfile -Command $CommandSB

        if ($WebSite.logFile.logTargetW3C -like "*ETW*" -and $WebSite.logFile.logTargetW3C -like "*File*") {
            $FindingDetails += "Both ETW and Log file logging are enabled." | Out-String
            $Status = "NotAFinding"
        }
        else {
            $FindingDetails += "'$($WebSite.logFile.logTargetW3C)' is the only option selected." | Out-String
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

Function Get-V218741 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218741
        STIG ID    : IIST-SI-000209
        Rule ID    : SV-218741r1022677_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-WSR-000061
        Rule Title : The IIS 10.0 website must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 10.0 website events.
        DiscussMD5 : F6FB05D8D47A1330B0AC1AC6D7F130CB
        CheckMD5   : 98A00905A808A880DE5EF800F6211F31
        FixMD5     : 7B81715B746A5877C41EC9741847B0DA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object logFile
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WebSite = Powershell.exe -NoProfile -Command $CommandSB
        $customField1_logged = $false # the custom "Connection" field we're looking for
        $customField2_logged = $false # the custom "Warning" field we're looking for

        if ($WebSite.logFile.logFormat -ne "W3C") {
            $Status = "Open"
            $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)' [Expected 'W3C']" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)'" | Out-String
            $FindingDetails += "" | Out-String
        }

        foreach ($Item in $Website.logFile.customFields.Collection) {
            if ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Connection") {
                $customField1_logged = $true
            }
            elseif ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Warning") {
                $customField2_logged = $true
            }
        }

        if ($customField1_logged -eq $true) {
            $FindingDetails += "The 'Request Header >> Connection' custom field is configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $Status = "Open"
            $FindingDetails += "The 'Request Header >> Connection' custom field is NOT configured." | Out-String
            $FindingDetails += "" | Out-String
        }

        if ($customField2_logged -eq $true) {
            $FindingDetails += "The 'Request Header >> Warning' custom field is configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $Status = "Open"
            $FindingDetails += "The 'Request Header >> Warning' custom field is NOT configured." | Out-String
            $FindingDetails += "" | Out-String
        }

        if ($Status -ne "Open") {
            # if we never marked a site as failing, then we pass the whole check.
            $Status = 'NotAFinding'
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

Function Get-V218742 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218742
        STIG ID    : IIST-SI-000210
        Rule ID    : SV-218742r1022679_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-WSR-000064
        Rule Title : The IIS 10.0 website must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
        DiscussMD5 : EDA80E0B5A3CEB39B0D0A4342C615A1D
        CheckMD5   : 5D2F158476ABDE568F9A8F0A1B839889
        FixMD5     : E5FAA3E2A5B5EB76A2339B90E68328B9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object logFile
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WebSite = Powershell.exe -NoProfile -Command $CommandSB
        $LogFlags = $Website.logFile.logExtFileFlags -split ","
        $FlagsToCheck = ("UserAgent", "UserName", "Referer")
        $MissingFlags = ""
        $customField1_logged = $false # the custom "Authorization" field we're looking for
        $customField2_logged = $false # the custom "Content-Type" field we're looking for

        if ($Website.logFile.logFormat -ne "W3C") {
            $Status = "Open"
            $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)' [Expected 'W3C']" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)'" | Out-String
            $FindingDetails += "" | Out-String

            # check the standard fields first
            foreach ($Flag in $FlagsToCheck) {
                if ($Flag -notin $LogFlags) {
                    $MissingFlags += $Flag | Out-String
                }
            }

            if ($MissingFlags) {
                $Status = "Open"
                $FindingDetails += "The following minimum fields are not logged:" | Out-String
                $FindingDetails += $MissingFlags | Out-String
                $FindingDetails += "" | Out-String
            }
            else {
                $FindingDetails += "User Agent, User Name, and Referrer are all logged." | Out-String
                $FindingDetails += "" | Out-String
            }

            foreach ($Item in $Website.logFile.customFields.Collection) {
                if ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Authorization") {
                    $customField1_logged = $true
                }
                elseif ($Item.sourceType -eq "ResponseHeader" -and $Item.sourceName -eq "Content-Type") {
                    $customField2_logged = $true
                }
            }

            if ($customField1_logged -eq $true) {
                $FindingDetails += "The 'Request Header >> Authorization' custom field is configured." | Out-String
                $FindingDetails += "" | Out-String
            }
            else {
                $Status = "Open"
                $FindingDetails += "The 'Request Header >> Authorization' custom field is NOT configured." | Out-String
                $FindingDetails += "" | Out-String
            }

            if ($customField2_logged -eq $true) {
                $FindingDetails += "The 'Response Header >> Content-Type' custom field is configured." | Out-String
                $FindingDetails += "" | Out-String
            }
            else {
                $Status = "Open"
                $FindingDetails += "The 'Response Header >> Content-Type' custom field is NOT configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        if ($Status -ne "Open") {
            # if we never marked a site as failing, then we pass the whole check.
            $Status = 'NotAFinding'
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

Function Get-V218743 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218743
        STIG ID    : IIST-SI-000214
        Rule ID    : SV-218743r1111802_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The IIS 10.0 website must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
        DiscussMD5 : 8A8FED5376557EDF7AEBED6981A6C5F0
        CheckMD5   : 93AD8F128067689C5A1729EA0A2686B2
        FixMD5     : 2119EF09894990369ECEC6DDBB24DF35
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    else {
        $Compliant = $true
        $ExtensionFindings = ""

        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite "' + $($SiteName -replace "'" -replace '"') + '" | Where-Object applicationPool -match "Wsus"
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WsusCheck = Powershell.exe -NoProfile -Command $CommandSB
        if ($WsusCheck) {
            $IsWsus = $true
        }
        else {
            $IsWsus = $False
        }

        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            (Get-WebConfiguration /system.webServer/staticContent -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '").Collection
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Configuration = Powershell.exe -NoProfile -Command $CommandSB

        if ($IsWsus) {
            $FindingDetails += "WSUS Hosted: True" | Out-String
            $ExtensionsToCheck = @(".dll", ".com", ".bat", ".csh")
        }
        else {
            $FindingDetails += "WSUS Hosted: False" | Out-String
            $ExtensionsToCheck = @(".exe", ".dll", ".com", ".bat", ".csh")
        }
        $FindingDetails += "" | Out-String

        foreach ($Extension in $ExtensionsToCheck) {
            if ($Configuration | Where-Object fileExtension -EQ $Extension) {
                $Compliant = $false
                $ExtensionFindings += $Extension | Out-String
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "No invalid MIME types for OS shell program extensions found."
        }
        else {
            $Status = "Open"
            $FindingDetails += "The following invalid MIME types for OS shell program extensions are configured:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $ExtensionFindings | Out-String
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

Function Get-V218744 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218744
        STIG ID    : IIST-SI-000215
        Rule ID    : SV-218744r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000082
        Rule Title : Mappings to unused and vulnerable scripts on the IIS 10.0 website must be removed.
        DiscussMD5 : E7565BAD72E71FE7E1F5610BE90AC4C5
        CheckMD5   : DFCB0722D9F953593ABA5E8D9EE4EECF
        FixMD5     : DCE4C8EDE460A1681F706DE555355F1D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand1 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty -PSPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Filter "/system.webServer/handlers" -Name accessPolicy
        '
        $CommandSB1 = [scriptblock]::Create($PSCommand1)
        $PSCommand2 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebHandler -PSPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '"
        '
        $CommandSB2 = [scriptblock]::Create($PSCommand2)

        $AccessPolicy = Powershell.exe -NoProfile -Command $CommandSB1
        $ConfigHandlers = Powershell.exe -NoProfile -Command $CommandSB2
        $Handlers = New-Object System.Collections.Generic.List[System.Object]

        foreach ($Item in $ConfigHandlers) {
            if (($Item.requireAccess -eq "None") -or ($Item.requireAccess -in ($AccessPolicy -split ","))) {
                $State = "Enabled"
            }
            else {
                $State = "Disabled"
            }
            switch ($Item.resourceType) {
                "Either" {
                    $PathType = "File or Folder"
                }
                default {
                    $PathType = $Item.resourceType
                }
            }
            $NewObj = [PSCustomObject]@{
                Name          = $Item.name
                Path          = $Item.path
                State         = $State
                PathType      = $PathType
                Handler       = $Item.modules
                RequireAccess = $Item.requireAccess
            }
            $Handlers.Add($NewObj)
        }

        $FindingDetails += "Access Policy: $($AccessPolicy)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Enabled Handler Mappings:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        if (($Handlers | Where-Object State -EQ "Enabled" | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            foreach ($Item in ($Handlers | Where-Object State -EQ "Enabled")) {
                $FindingDetails += "Name:`t`t$($Item.Name)" | Out-String
                $FindingDetails += "Path:`t`t`t$($Item.Path)" | Out-String
                $FindingDetails += "State:`t`t$($Item.State)" | Out-String
                $FindingDetails += "PathType:`t`t$($Item.PathType)" | Out-String
                $FindingDetails += "Handler:`t`t$($Item.Handler)" | Out-String
                $FindingDetails += "ReqAccess:`t$($Item.RequireAccess)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += "Disabled Handler Mappings:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        if (($Handlers | Where-Object State -EQ "Disabled" | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            foreach ($Item in ($Handlers | Where-Object State -EQ "Disabled")) {
                $FindingDetails += "Name:`t`t$($Item.Name)" | Out-String
                $FindingDetails += "Path:`t`t`t$($Item.Path)" | Out-String
                $FindingDetails += "State:`t`t$($Item.State)" | Out-String
                $FindingDetails += "PathType:`t`t$($Item.PathType)" | Out-String
                $FindingDetails += "Handler:`t`t$($Item.Handler)" | Out-String
                $FindingDetails += "ReqAccess:`t$($Item.RequireAccess)" | Out-String
                $FindingDetails += "" | Out-String
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

Function Get-V218745 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218745
        STIG ID    : IIST-SI-000216
        Rule ID    : SV-218745r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000083
        Rule Title : The IIS 10.0 website must have resource mappings set to disable the serving of certain file types.
        DiscussMD5 : D1E10C845049BC0A79C9F7A981C1E53E
        CheckMD5   : FBCC5058EEE8A7E98B71C065ED7EFB13
        FixMD5     : 0322F43341B1DE9DB4436410B63BD71B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/requestFiltering -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name fileExtensions | Select-Object -expandproperty Collection
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $FileExtensions = Powershell.exe -NoProfile -Command $CommandSB

        $FindingDetails += "Denied file extensions:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        if (($FileExtensions | Where-Object allowed -EQ $false | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            foreach ($Item in ($FileExtensions | Where-Object allowed -EQ $false)) {
                $FindingDetails += "FileExtension:`t$($Item.fileExtension)" | Out-String
                $FindingDetails += "Allowed:`t`t$($Item.allowed)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        $FindingDetails += "Allowed file extensions:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        if (($FileExtensions | Where-Object allowed -EQ $true | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            foreach ($Item in ($FileExtensions | Where-Object allowed -EQ $true)) {
                $FindingDetails += "FileExtension:`t$($Item.fileExtension)" | Out-String
                $FindingDetails += "Allowed:`t`t$($Item.allowed)" | Out-String
                $FindingDetails += "" | Out-String
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

Function Get-V218748 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218748
        STIG ID    : IIST-SI-000219
        Rule ID    : SV-218748r1043177_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-WSR-000089
        Rule Title : Each IIS 10.0 website must be assigned a default host header.
        DiscussMD5 : E9C9524A4E0D5B719E837C9BD3529168
        CheckMD5   : 5723B66DC9D0A9017E842C78A1C2E67F
        FixMD5     : CFAEFAAC796A60065580FF54A46A8DE6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    elseif (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $Compliant = $true
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            $WebSite = Get-Website -Name "' + $($SiteName -replace "'" -replace '"') + '"

            $Bindings = [System.Collections.Generic.List[System.Object]]::new()
            ForEach ($Item in $WebSite.bindings.Collection) {
                $NewObj = [PSCustomObject]@{
                    Protocol           = $Item.protocol
                    BindingInformation = $Item.bindingInformation
                    CertificateHash    = $Item.certificateHash
                }
                $Bindings.Add($NewObj)
            }
            Return $Bindings
        '

        $CommandSB = [scriptblock]::Create($PSCommand)
        $PSResult = Powershell.exe -Command $CommandSB
        $BindingInfo = $PSResult.bindingInformation
        $SiteBound80or443 = $false

        foreach ($Binding in $BindingInfo) {
            $SingleBinding = $Binding.Split(':') # bindings are written as "<ipAddress>:<port>:<hostheader>".
            if ($SingleBinding[1] -eq '443' -or $SingleBinding[1] -eq '80') {
                #if the site is on port 443 or 80 (the only ports the STIGs calls out needing a host header on).
                if ($SingleBinding[2] -ne '') {
                    #check if the site has been bound to a host header
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The site is bound to $($SingleBinding[2]) on port $($SingleBinding[1])"
                    $siteBound80or443 = $true
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The site is NOT bound to a specific host header on port $($SingleBinding[1])"
                    $SiteBound80or443 = $true
                }
            }
        }

        if ($siteBound80or443 -eq $false) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The site '$($SiteName -replace "'" -replace '"')' is not using ports 80 or 443 and so this check is not applicable. There is no reason to turn on an unused port after all."
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
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

Function Get-V218749 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218749
        STIG ID    : IIST-SI-000220
        Rule ID    : SV-218749r1111805_rule
        CCI ID     : CCI-000197, CCI-001188, CCI-002470
        Rule Name  : SRG-APP-000172-WSR-000104
        Rule Title : A private IIS 10.0 website authentication mechanism must use client certificates to transmit session identifier to assure integrity.
        DiscussMD5 : E274AF40E42E394623340C58A66A9DF1
        CheckMD5   : FB1FD8D5271CC9059537BC6170E0C6A0
        FixMD5     : 629EF7B89D7F86C1BC47D5281C4756B6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "CertSvcOnlineResponder") {
        $FindingDetails += "This system is an OCSP Responder.  If it is hosting no other content, this requirement may be marked as NA." | Out-String
        $FindingDetails += "" | Out-String
    }
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/access -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Access = Powershell.exe -NoProfile -Command $CommandSB
        $SslFlags = $Access.sslFlags -split ","

        if ("SslRequireCert" -in $SslFlags) {
            $Status = "NotAFinding"
            $FindingDetails += "Client Certificates is set to 'Require'" | Out-String
        }
        else {
            $Status = "Open"
            $FindingDetails += "Client Certificates is NOT set to 'Require'" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Confirm if this this is a public server.  If so, mark this finding as Not Applicable."
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

Function Get-V218750 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218750
        STIG ID    : IIST-SI-000221
        Rule ID    : SV-218750r961095_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000031
        Rule Title : Anonymous IIS 10.0 website access accounts must be restricted.
        DiscussMD5 : A37F8B01EBF7825C3F09B703D1E4DE0A
        CheckMD5   : 9F4D1C4E939B17FFAC07C597D0B8E971
        FixMD5     : AE4AF08DCF7CE01B416F0570B348E68A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Server = ($env:COMPUTERNAME)
    $Computer = [ADSI]"WinNT://$Server,computer"
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebConfigurationProperty /system.webServer/security/authentication/anonymousAuthentication -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $AnonymousAuth = Powershell.exe -NoProfile -Command $CommandSB
    $GroupsToCheck = ("/Administrators", "/Backup Operators", "/Certificate Service", "/Distributed COM Users", "/Event Log Readers", "/Network Configuration Operators", "/Performance Log Users", "/Performance Monitor Users", "/Power Users", "/Print Operators", "/Remote Desktop Users", "/Replicator", "/Users")
    $group = $computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'group' } | Where-Object { $_.Path -like "*/Administrators*" }

    if ($AnonymousAuth.enabled -eq $true) {
        if (-not($AnonymousAuth.userName) -or $AnonymousAuth.userName -eq "") {
            $Status = "NotAFinding"
            $FindingDetails += "Anonymous Authentication is Enabled but is configured for Application Pool Identity." | Out-String
        }
        else {
            $FindingDetails += "Anonymous Authentication is Enabled and using the account '$($AnonymousAuth.userName)' for authentication." | Out-String
            $FindingDetails += "" | Out-String
            $PrivilegedMembership = ""
            foreach ($Group in $GroupsToCheck) {
                try {
                    $GroupInfo = $Computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'group' } | Where-Object { $_.Path -like "*$Group*" }
                    $Members = $GroupInfo.psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
                    $Members | ForEach-Object {
                        if ($_ -eq $AnonymousAuth.userName) {
                            $PrivilegedMembership += $GroupInfo.Name | Out-String
                        }
                    }
                }
                catch {
                    # Do Nothing
                }
            }
            if ($PrivilegedMembership -ne "") {
                $Status = "Open"
                $FindingDetails += "$($AnonymousAuth.userName) is a member of the following privileged groups:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PrivilegedMembership
            }
            else {
                $Status = "NotAFinding"
                $FindingDetails += "$($AnonymousAuth.userName) is not a member of any privileged groups." | Out-String
            }
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "Anonymous Authentication is Disabled" | Out-String
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

Function Get-V218751 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218751
        STIG ID    : IIST-SI-000223
        Rule ID    : SV-218751r1043181_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000136
        Rule Title : The IIS 10.0 website must generate unique session identifiers that cannot be reliably reproduced.
        DiscussMD5 : 2698FD87695BF5A47AB54F2926C18822
        CheckMD5   : 904500970D7C7552E8532F6FEE9CB710
        FixMD5     : C29D54B7420AE6FB8D01FE27BF3FFB1F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $EnabledFeature = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^Web-Asp-Net|^IIS-ASPNET)" -and $_.Enabled -eq $true}
    if (-not($EnabledFeature)) {
        $Status = "Not_Applicable"
        $FindingDetails += "ASP.NET is not installed so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.web/sessionState -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name mode
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Mode = Powershell.exe -NoProfile -Command $CommandSB

        if ($Mode -eq "InProc") {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }

        $FindingDetails += "Mode is set to '$($Mode)'" | Out-String
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

Function Get-V218752 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218752
        STIG ID    : IIST-SI-000224
        Rule ID    : SV-218752r1111807_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-WSR-000146
        Rule Title : The IIS 10.0 website document directory must be in a separate partition from the IIS 10.0 websites system files.
        DiscussMD5 : F179270B5E1E1F687E62A6631724ABBD
        CheckMD5   : F29640EB141ADB18710D97405470C610
        FixMD5     : F65D1730DBD270C0383A3C024D939F56
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    elseif (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object physicalPath
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WebSite = Powershell.exe -NoProfile -Command $CommandSB
        $WebSiteDrive = ($WebSite.physicalPath -replace "%SystemDrive%", $env:SYSTEMDRIVE).Split("\")[0]

        if ($WebSiteDrive -eq $env:SYSTEMDRIVE) {
            $Status = "Open"
            $FindingDetails += "Both the OS and the web site are installed on $($env:SYSTEMDRIVE)" | Out-String
        }
        else {
            $Status = "NotAFinding"
            $FindingDetails += "The OS is installed on $($env:SYSTEMDRIVE)" | Out-String
            $FindingDetails += "The web site is installed on $($WebSiteDrive)"
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

Function Get-V218753 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218753
        STIG ID    : IIST-SI-000225
        Rule ID    : SV-218753r961152_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 10.0 website must be configured to limit the maxURL.
        DiscussMD5 : 9E8371DE45CA8DB4EFC176731916D3E2
        CheckMD5   : 00CD5ED0EA7873542433789010F4CE9D
        FixMD5     : 903F8E87883DEB5F32DC51FAB124C91E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebConfigurationProperty /system.webServer/security/requestFiltering/requestLimits -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name maxURL
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $MaxURL = Powershell.exe -NoProfile -Command $CommandSB

    if ($MaxURL.Value -le 4096) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }

    $FindingDetails += "MaxURL is set to '$($MaxURL.Value)'"
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V218754 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218754
        STIG ID    : IIST-SI-000226
        Rule ID    : SV-218754r961152_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 10.0 website must be configured to limit the size of web requests.
        DiscussMD5 : 64D38AF43426ADD6D9E6344353143E1B
        CheckMD5   : EB585001152025B246B14CB6B84BA372
        FixMD5     : 35F33E51589A96A3ADAF5E9B5E76B6F4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebConfigurationProperty /system.webServer/security/requestFiltering/requestLimits -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name maxAllowedContentLength
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $MaxAllowedContentLength = Powershell.exe -NoProfile -Command $CommandSB

    if ($MaxAllowedContentLength.Value -le 30000000) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }

    $FindingDetails += "MaxAllowedContentLength is set to '$($MaxAllowedContentLength.Value)'"
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V218755 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218755
        STIG ID    : IIST-SI-000227
        Rule ID    : SV-218755r961152_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 10.0 websites Maximum Query String limit must be configured.
        DiscussMD5 : 6B15FE81398B334E1CBC9D2306A28F98
        CheckMD5   : 2194EF0D7B5A9AE22423D745B886D908
        FixMD5     : AF2823F2D3254D52706E98FAC1DA9857
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebConfigurationProperty /system.webServer/security/requestFiltering/requestLimits -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name maxQueryString
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $MaxQueryString = Powershell.exe -NoProfile -Command $CommandSB

    if ($MaxQueryString.Value -le 2048) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }

    $FindingDetails += "MaxQueryString is set to '$($MaxQueryString.Value)'"
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V218756 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218756
        STIG ID    : IIST-SI-000228
        Rule ID    : SV-218756r961152_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Non-ASCII characters in URLs must be prohibited by any IIS 10.0 website.
        DiscussMD5 : 447E0E82F59C7A2E645DCC5AE88C4173
        CheckMD5   : 96EE7AE92A562ED29EFD145F9B51F754
        FixMD5     : 83013A07B6AA61205317BCA223A0EC6A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/requestFiltering -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name allowHighBitCharacters
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $AllowHighBitCharacters = Powershell.exe -NoProfile -Command $CommandSB

        if ($AllowHighBitCharacters.Value -eq $false) {
            $Status = "NotAFinding"
            $FindingDetails += "AllowHighBitCharacters is Disabled"
        }
        else {
            $Status = "Open"
            $FindingDetails += "AllowHighBitCharacters is Enabled"
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

Function Get-V218757 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218757
        STIG ID    : IIST-SI-000229
        Rule ID    : SV-218757r961152_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Double encoded URL requests must be prohibited by any IIS 10.0 website.
        DiscussMD5 : 35E0F02F8A5ACE38B30B8753BE827B0E
        CheckMD5   : E92F3EC55B3EE709B51946116DECE83C
        FixMD5     : A81AD18DF3F10BEC78D66BF2CAA35C96
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/requestFiltering -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name allowDoubleEscaping
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $AllowDoubleEscaping = Powershell.exe -NoProfile -Command $CommandSB

        if ($AllowDoubleEscaping.Value -eq $false) {
            $Status = "NotAFinding"
            $FindingDetails += "AllowDoubleEscaping is Disabled"
        }
        else {
            $Status = "Open"
            $FindingDetails += "AllowDoubleEscaping is Enabled"
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

Function Get-V218758 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218758
        STIG ID    : IIST-SI-000230
        Rule ID    : SV-218758r1067598_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Unlisted file extensions in URL requests must be filtered by any IIS 10.0 website.
        DiscussMD5 : 01893C6162323B259170B22BDDBB794A
        CheckMD5   : 23B54A96B50AA5425A1945E8471FDF68
        FixMD5     : 071B2A1F17A4378E4D58453B65B3BAF2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/requestFiltering/fileExtensions -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name allowUnlisted
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $AllowUnlisted = Powershell.exe -NoProfile -Command $CommandSB

        if ($AllowUnlisted.Value -eq $false) {
            $Status = "NotAFinding"
            $FindingDetails += "AllowUnlisted is Disabled"
        }
        else {
            $Status = "Open"
            $FindingDetails += "AllowUnlisted is Enabled"
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

Function Get-V218759 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218759
        STIG ID    : IIST-SI-000231
        Rule ID    : SV-218759r961158_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-WSR-000157
        Rule Title : Directory Browsing on the IIS 10.0 website must be disabled.
        DiscussMD5 : 2A45AF472A723004D72E896EA986918E
        CheckMD5   : 609225B24935C8DAB707185B820A7750
        FixMD5     : 95DBD02F21BF33E99CB8E58A9C0986E9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebConfigurationProperty /system.webServer/directoryBrowse -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name enabled
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $DirectoryBrowse = Powershell.exe -NoProfile -Command $CommandSB

    if ($DirectoryBrowse.Value -eq $false) {
        $Status = "NotAFinding"
        $FindingDetails += "Directory Browsing is Disabled"
    }
    else {
        $Status = "Open"
        $FindingDetails += "Directory Browsing is Enabled"
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

Function Get-V218760 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218760
        STIG ID    : IIST-SI-000233
        Rule ID    : SV-218760r1022690_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 10.0 website, patches, loaded modules, and directory paths.
        DiscussMD5 : 9A79AA3CE4FFA04A7672C0126E751178
        CheckMD5   : AED44F9C33DFBD91B04D3C4518D48D84
        FixMD5     : 80DFC12EA4A13234EE454363239B669F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfiguration system.webServer/httpErrors | Select-Object *
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $HttpErrors = Powershell.exe -NoProfile -Command $CommandSB

        if ($HttpErrors.errorMode -eq "DetailedLocalOnly") {
            $Status = "NotAFinding"
            $FindingDetails += "Error Responses is configured to 'Detailed errors for local requests and custom error pages for remote requests'" | Out-String
        }
        elseif ($HttpErrors.errorMode -eq "Custom") {
            $Status = "NotAFinding"
            $FindingDetails += "Error Responses is configured to 'Custom error pages'" | Out-String
        }
        else {
            $Status = "Open"
            $FindingDetails += "Error Responses is NOT configured to 'Detailed errors for local requests and custom error pages for remote requests' or 'Custom error pages'" | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "errorMode:`t$($HttpErrors.errorMode)" | Out-String
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

Function Get-V218761 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218761
        STIG ID    : IIST-SI-000234
        Rule ID    : SV-218761r961167_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000160
        Rule Title : Debugging and trace information used to diagnose the IIS 10.0 website must be disabled.
        DiscussMD5 : CBF7B6F5E89A9CDAB75ADB6B81C49B75
        CheckMD5   : A43D82F70E443DA7A55BA87DFDF16494
        FixMD5     : A4438A2AEC24B6F45ADCC993622BB623
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand1 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object applicationPool
        '
        $CommandSB1 = [scriptblock]::Create($PSCommand1)
        $PSCommand2 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-ChildItem IIS:\AppPools
        '
        $CommandSB2 = [scriptblock]::Create($PSCommand2)

        $WebSite = Powershell.exe -NoProfile -Command $CommandSB1
        $AppPools = Powershell.exe -NoProfile -Command $CommandSB2

        foreach ($AppPool in $AppPools) {
            if ($AppPool.Name -in $WebSite.applicationPool) {
                if ($Apppool.managedRuntimeVersion -eq "") {
                    # "No Managed Code" (which means it's not using .NET) is an empty string and not a null
                    $Status = "Not_Applicable"
                    $FindingDetails += "The site is not using the .NET runtime so this check is Not Applicable." | Out-String
                }
                else {
                    $PSCommand = '
                        If (-Not(Get-Module -Name WebAdministration)) {
                            Import-Module WebAdministration
                        }
                        Get-WebConfigurationProperty system.web/compilation -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name debug
                    '
                    $CommandSB = [scriptblock]::Create($PSCommand)
                    $DebugCompilation = Powershell.exe -NoProfile -Command $CommandSB

                    if ($DebugCompilation.Value -eq $false) {
                        $Status = "NotAFinding"
                        $FindingDetails += "Debug is set to 'False'" | Out-String
                    }
                    else {
                        $Status = "Open"
                        $FindingDetails += "Debug is set NOT to 'False'" | Out-String
                    }
                }
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

Function Get-V218762 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218762
        STIG ID    : IIST-SI-000235
        Rule ID    : SV-218762r1043182_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000012
        Rule Title : The Idle Time-out monitor for each IIS 10.0 website must be enabled.
        DiscussMD5 : 9E963E502C01CDAF1301F1ADA842AE55
        CheckMD5   : A477EE500BCB6A1A794CB39985B4A1EF
        FixMD5     : EF05B39B7911D79A298FB5DD5FDBC137
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $PSCommand1 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object applicationPool
        '
        $CommandSB1 = [scriptblock]::Create($PSCommand1)
        $PSCommand2 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-ChildItem IIS:\AppPools
        '
        $CommandSB2 = [scriptblock]::Create($PSCommand2)

        $WebSite = Powershell.exe -NoProfile -Command $CommandSB1
        $AppPools = Powershell.exe -NoProfile -Command $CommandSB2

        foreach ($AppPool in $AppPools) {
            if ($AppPool.Name -in $WebSite.applicationPool) {
                $IdleTimeout = $AppPool.processModel.idleTimeout
                if ($IdleTimeout.TotalMinutes -eq 0) {
                    $Status = "Open"
                }
                elseif ($IdleTimeout.TotalMinutes -gt 0) {
                    $Status = "NotAFinding"
                }
                else {
                    $Status = "Open"
                }

                $FindingDetails += "Idle Time-out is configured to '$($AppPool.processModel.idleTimeout.TotalMinutes)' total minutes" | Out-String
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

Function Get-V218763 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218763
        STIG ID    : IIST-SI-000236
        Rule ID    : SV-218763r1043182_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000134
        Rule Title : The IIS 10.0 websites connectionTimeout setting must be explicitly configured to disconnect an idle session.
        DiscussMD5 : 1EE513CC1D31387CDF0BB25CDCC37DF1
        CheckMD5   : E9ED9B3E1893E074C8F834DAA26A4C95
        FixMD5     : 63852112EB0414D79DA76D0AE59E7C6E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebConfigurationProperty /system.web/sessionState -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $SessionState = Powershell.exe -NoProfile -Command $CommandSB
    $Span = New-TimeSpan -Hours 00 -Minutes 15 -Seconds 00

    if ($SessionState.timeout.CompareTo($Span) -le 0) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }

    $FindingDetails += "Time-out is configured to '$($SessionState.timeout)'" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V218764 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218764
        STIG ID    : IIST-SI-000237
        Rule ID    : SV-218764r961281_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-WSR-000170
        Rule Title : The IIS 10.0 website must provide the capability to immediately disconnect or disable remote access to the hosted applications.
        DiscussMD5 : 1F4D022C71BE8033FC1D287DC1865DAF
        CheckMD5   : A60EA7C6D71ADBD87EE5718CF0A929E9
        FixMD5     : 65E0EE9EA6C83AB56CC4A173F952D3AB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "There is nothing preventing an administrator from shutting down either the webservice or an individual IIS site in the event of an attack. Documentation exists describing how." | Out-String
    $Status = 'NotAFinding'
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V218765 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218765
        STIG ID    : IIST-SI-000238
        Rule ID    : SV-218765r961392_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-WSR-000150
        Rule Title : The IIS 10.0 website must use a logging mechanism configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 10.0 website.
        DiscussMD5 : C0CC578BF451A674EE2A268EDB2EBCFB
        CheckMD5   : 98214ED42544EC3F1548BA38958C1171
        FixMD5     : 02B4F800F662E5BDC1F6B97BDD9EB010
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object logFile
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $WebSite = Powershell.exe -NoProfile -Command $CommandSB
    $SchedulesToCheck = ("Hourly", "Daily", "Weekly", "Monthly")

    if ($WebSite.logFile.period -in $SchedulesToCheck) {
        $Status = "NotAFinding"
        $FindingDetails += "Logs are set to roll over $($WebSite.logFile.period)." | Out-String
    }
    else {
        $Status = "Open"
        $FindingDetails += "Logs are NOT set to roll over on a schedule." | Out-String
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

Function Get-V218766 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218766
        STIG ID    : IIST-SI-000239
        Rule ID    : SV-218766r1111809_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The IIS 10.0 websites must use ports, protocols, and services according to Ports, Protocols, and Services Management (PPSM) guidelines.
        DiscussMD5 : E52DB55DE5D43F39142FBCB03CAF8FBF
        CheckMD5   : 1BF72B3368E5978C3968D0D98465E523
        FixMD5     : D32D7D92628F72FAEF3D5B2E99564FA9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "CertSvcOnlineResponder") {
        $FindingDetails += "This system is an OCSP Responder.  If it is hosting no other content, this requirement may be marked as NA." | Out-String
        $FindingDetails += "" | Out-String
    }

    $NonPPSMPortFound = $false
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        $WebSite = Get-Website -Name "' + $($SiteName -replace "'" -replace '"') + '"

        $Bindings = [System.Collections.Generic.List[System.Object]]::new()
        ForEach ($Item in $WebSite.bindings.Collection) {
            $NewObj = [PSCustomObject]@{
                Protocol           = $Item.protocol
                BindingInformation = $Item.bindingInformation
                CertificateHash    = $Item.certificateHash
            }
            $Bindings.Add($NewObj)
        }
        Return $Bindings
    '

    $CommandSB = [scriptblock]::Create($PSCommand)
    $PSResult = Powershell.exe -Command $CommandSB
    $Bindings = $PSResult | Where-Object {$_.protocol -in @("http", "https")}
    $Ports = $Bindings.bindingInformation | ForEach-Object { ($_ -split ':')[1] }

    if ($Bindings) {
        foreach ($Port in $Ports) {
            if ($Port -notin @("80", "443")) {
                $NonPPSMPortFound = $true
            }
        }
        switch ($NonPPSMPortFound) {
            $true {
                $FindingDetails += "Non-standard port detected.  Confirm PPSM approval." | Out-String
                $FindingDetails += "" | Out-String
            }
            $false {
                $Status = "NotAFinding"
                $FindingDetails += "All ports are PPSM approved." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += "Below are the current HTTP and HTTPS bindings:" | Out-String
        $FindingDetails += "" | Out-String
        foreach ($Binding in $Bindings) {
            $FindingDetails += "$($Binding.protocol) ($($Binding.bindingInformation))" | Out-String
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "There are no HTTP or HTTPS bindings on this site."
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

Function Get-V218767 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218767
        STIG ID    : IIST-SI-000241
        Rule ID    : SV-218767r1111811_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-WSR-000186
        Rule Title : The IIS 10.0 website must only accept client certificates issued by DOD PKI or DOD-approved PKI Certification Authorities (CAs).
        DiscussMD5 : 033545ECFC56FDD7D50589AA7B4F0CE3
        CheckMD5   : 786226A61F64EFCD96A163CF725C3EF2
        FixMD5     : 5F4F14BDA7797CD1766550A2D9956492
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "CertSvcOnlineResponder") {
        $FindingDetails += "This system is an OCSP Responder.  If it is hosting no other content, this requirement may be marked as NA." | Out-String
        $FindingDetails += "" | Out-String
    }
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    else {
        $Compliant = $true
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            $WebSite = Get-Website -Name "' + $($SiteName -replace "'" -replace '"') + '"

            $Bindings = [System.Collections.Generic.List[System.Object]]::new()
            ForEach ($Item in $WebSite.bindings.Collection) {
                $NewObj = [PSCustomObject]@{
                    Protocol           = $Item.protocol
                    BindingInformation = $Item.bindingInformation
                    CertificateHash    = $Item.certificateHash
                }
                $Bindings.Add($NewObj)
            }
            Return $Bindings
        '

        $CommandSB = [scriptblock]::Create($PSCommand)
        $PSResult = Powershell.exe -Command $CommandSB
        $Bindings = $PSResult | Where-Object {$_.protocol -eq "https"}

        if ($Bindings) {
            foreach ($Binding in $Bindings) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Binding: $($Binding.protocol) ($($Binding.bindingInformation))" | Out-String
                $FindingDetails += "===========================" | Out-String
                if ($Binding.certificateHash) {
                    $CertList = New-Object System.Collections.Generic.List[System.Object]
                    $StoresToSearch = @("Cert:\LocalMachine\My", "Cert:\LocalMachine\WebHosting")
                    foreach ($Store in $StoresToSearch) {
                        $IISCerts = Get-ChildItem $Store -Recurse -ErrorAction SilentlyContinue | Where-Object Thumbprint -In $Binding.certificateHash
                        if ($IISCerts) {
                            foreach ($Cert in $IISCerts) {
                                $ApprovedChain = $false
                                $CertPath = @()
                                $Chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                                $null = $Chain.Build($Cert)
                                foreach ($Item in ($Chain.ChainElements.Certificate | Select-Object FriendlyName, Subject)) {
                                    if ($Item.Subject -match "(^CN=DOD Root|^CN=ECA Root|^CN=NSS Root)") {
                                        $ApprovedChain = $true
                                    }
                                    if (-not($Item.FriendlyName -eq "" -or $null -eq $Item.FriendlyName)) {
                                        $CertPath += $($Item.FriendlyName)
                                    }
                                    else {
                                        $CertPath += $(($Item.Subject -split ',')[0] -replace 'CN=', '')
                                    }
                                }
                                [Array]::Reverse($CertPath)

                                $NewObj = [PSCustomObject]@{
                                    BindingInfo   = $(($Binding | Where-Object certificateHash -EQ $Cert.Thumbprint).bindingInformation)
                                    Subject       = $Cert.Subject
                                    CertStore     = $Path
                                    Issuer        = $Cert.Issuer
                                    FriendlyName  = $Cert.FriendlyName
                                    NotAfter      = $Cert.NotAfter
                                    Thumbprint    = $Cert.Thumbprint
                                    CertPath      = $CertPath
                                    ApprovedChain = $ApprovedChain
                                }
                                $CertList.Add($NewObj)
                            }
                        }
                    }

                    if (($CertList | Where-Object ApprovedChain -EQ $false | Measure-Object).Count -gt 0) {
                        $Compliant = $false
                        $FindingDetails += "Non-Compliant Certificates:" | Out-String
                        $FindingDetails += "---------------------------" | Out-String
                        foreach ($Cert in $CertList | Where-Object ApprovedChain -EQ $false) {
                            $FindingDetails += "Subject:`t`t`t$($Cert.Subject)" | Out-String
                            $FindingDetails += "CertStore:`t`t`t$($Cert.CertStore)" | Out-String
                            $FindingDetails += "Issuer:`t`t`t$($Cert.Issuer)" | Out-String
                            $FindingDetails += "FriendlyName:`t`t$($Cert.FriendlyName)" | Out-String
                            $FindingDetails += "NotAfter:`t`t`t$($Cert.NotAfter)" | Out-String
                            $FindingDetails += "Thumbprint:`t`t$($Cert.Thumbprint)" | Out-String
                            $FindingDetails += "ApprovedChain:`t$($Cert.ApprovedChain) [finding]" | Out-String
                            $FindingDetails += "CertificationPath..." | Out-String
                            $i = 0
                            foreach ($Item in $Cert.CertPath) {
                                $FindingDetails += "($i) - $($Item)" | Out-String
                                $i++
                            }
                            $FindingDetails += "" | Out-String
                        }
                    }

                    $FindingDetails += "" | Out-String
                    if (($CertList | Where-Object ApprovedChain -EQ $true | Measure-Object).Count -gt 0) {
                        $Status = "Open"
                        $FindingDetails += "Compliant Certificates:" | Out-String
                        $FindingDetails += "---------------------------" | Out-String
                        foreach ($Cert in $CertList | Where-Object ApprovedChain -EQ $true) {
                            $FindingDetails += "Subject:`t`t`t$($Cert.Subject)" | Out-String
                            $FindingDetails += "CertStore:`t`t`t$($Cert.CertStore)" | Out-String
                            $FindingDetails += "Issuer:`t`t`t$($Cert.Issuer)" | Out-String
                            $FindingDetails += "FriendlyName:`t`t$($Cert.FriendlyName)" | Out-String
                            $FindingDetails += "NotAfter:`t`t`t$($Cert.NotAfter)" | Out-String
                            $FindingDetails += "Thumbprint:`t`t$($Cert.Thumbprint)" | Out-String
                            $FindingDetails += "ApprovedChain:`t$($Cert.ApprovedChain)" | Out-String
                            $FindingDetails += "CertificationPath..." | Out-String
                            $i = 0
                            foreach ($Item in $Cert.CertPath) {
                                $FindingDetails += "($i) - $($Item)" | Out-String
                                $i++
                            }
                            $FindingDetails += "" | Out-String
                        }
                    }
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "No certificate selected for HTTPS binding." | Out-String
                }
            }
        }

        else {
            $Compliant = $false
            $FindingDetails = "There are no HTTPS bindings on this site."
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
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

Function Get-V218768 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218768
        STIG ID    : IIST-SI-000242
        Rule ID    : SV-218768r1111814_rule
        CCI ID     : CCI-002476
        Rule Name  : SRG-APP-000429-WSR-000113
        Rule Title : The IIS 10.0 private website must employ cryptographic mechanisms (TLS) and require client certificates.
        DiscussMD5 : CA400469361F3E2D54A4FB7586699F02
        CheckMD5   : D2DC39BC8B1C12FE523E7A03DABD7A6C
        FixMD5     : B153A25DE5BC0A3BB8118C057171541D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "CertSvcOnlineResponder") {
        $FindingDetails += "This system is an OCSP Responder.  If it is hosting no other content, this requirement may be marked as NA." | Out-String
        $FindingDetails += "" | Out-String
    }
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $Compliant = $true
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.webServer/security/access -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Access = Powershell.exe -NoProfile -Command $CommandSB
        $FlagsToCheck = ("Ssl", "SslRequireCert", "Ssl128")
        $SslFlags = $Access.sslFlags -split ","
        $MissingFlags = ""

        foreach ($Flag in $FlagsToCheck) {
            if ($Flag -notin $SslFlags) {
                $Compliant = $false
                $MissingFlags += $Flag | Out-String
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "Ssl, SslRequireCert, and Ssl128 are all set."
        }
        else {
            $Status = "Open"
            $FindingDetails += "The following SSL flags are missing:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $MissingFlags | Out-String
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

Function Get-V218769 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218769
        STIG ID    : IIST-SI-000244
        Rule ID    : SV-218769r961632_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000152
        Rule Title : IIS 10.0 website session IDs must be sent to the client using TLS.
        DiscussMD5 : 000CD73AF14A0386716C66AE794D8F4C
        CheckMD5   : B3EF033C495F47093F774FD74220515F
        FixMD5     : C6FB287D7B40BC4D58697C9CD41E262D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PSCommand = '
        If (-Not(Get-Module -Name WebAdministration)) {
            Import-Module WebAdministration
        }
        Get-WebConfigurationProperty /system.webServer/asp/session -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
    '
    $CommandSB = [scriptblock]::Create($PSCommand)
    $Session = Powershell.exe -NoProfile -Command $CommandSB

    if ($Session.keepSessionIdSecure -eq $true) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }

    $FindingDetails += "KeepSessionIdSecure is set to '$($Session.keepSessionIdSecure)'" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V218770 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218770
        STIG ID    : IIST-SI-000246
        Rule ID    : SV-218770r1111816_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000154
        Rule Title : Cookies exchanged between the IIS 10.0 website and the client must have cookie properties set to prohibit client-side scripts from reading the cookie data.
        DiscussMD5 : B100D929843B6E467354E3DFF639990D
        CheckMD5   : 4DFB7262C62A56B349F1E0D58A4BA664
        FixMD5     : B5A422277971B58276E77C621F6B520F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "CertSvcOnlineResponder") {
        $FindingDetails += "This system is an OCSP Responder.  If it is hosting no other content, this requirement may be marked as NA." | Out-String
        $FindingDetails += "" | Out-String
    }
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    else {
        $PSCommand1 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.web/httpCookies -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
        '
        $CommandSB1 = [scriptblock]::Create($PSCommand1)
        $PSCommand2 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.web/sessionState -PsPath "IIS:\Sites\' + $($SiteName -replace "'" -replace '"') + '" -Name *
        '
        $CommandSB2 = [scriptblock]::Create($PSCommand2)

        $HttpCookies = Powershell.exe -NoProfile -Command $CommandSB1
        $SessionState = Powershell.exe -NoProfile -Command $CommandSB2

        if (($HttpCookies.requireSSL -eq $true) -and ($SessionState.compressionEnabled -eq $false)) {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }

        $FindingDetails += "RequireSSL is set to '$($HttpCookies.requireSSL)'" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "CompressionEnabled is set to '$($SessionState.compressionEnabled)'" | Out-String
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

Function Get-V218771 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218771
        STIG ID    : IIST-SI-000251
        Rule ID    : SV-218771r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 10.0 website must have a unique application pool.
        DiscussMD5 : 5106D2ED477928763694548B850C877F
        CheckMD5   : D4A88CCC5516FBA7191FE77CD8511FD3
        FixMD5     : 52332CEC0A27072970F53C688A27D320
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    elseif (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $Compliant = $true
        $PSCommand1 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite | Select-Object Name
        '
        $CommandSB1 = [scriptblock]::Create($PSCommand1)
        $PSCommand2 = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebConfigurationProperty /system.applicationHost/sites/site/application -name applicationPool
        '
        $CommandSB2 = [scriptblock]::Create($PSCommand2)

        $AllSites = Powershell.exe -NoProfile -Command $CommandSB1
        $AllAppPools = Powershell.exe -NoProfile -Command $CommandSB2
        $AppPoolNames = $AllAppPools.Value | Select-Object -Unique
        $AppPoolUsage = New-Object System.Collections.Generic.List[System.Object]

        foreach ($AppPool in $AppPoolNames) {
            $SiteUsage = @()
            foreach ($Item in ($AllAppPools | Where-Object Value -EQ $AppPool)) {
                foreach ($WebSite in $AllSites) {
                    if ($Item.ItemXPath -match "@name='$($WebSite.Name)'") {
                        if ($WebSite.Name -notin $SiteUsage) {
                            $SiteUsage += $WebSite.Name
                        }
                    }
                }
            }
            $NewObj = [PSCustomObject]@{
                ApplicationPool = $AppPool
                WebSiteUsage    = $SiteUsage
            }
            $AppPoolUsage.Add($NewObj)
        }

        foreach ($Item in ($AppPoolUsage | Where-Object WebSiteUsage -Contains $($SiteName -replace "'" -replace '"'))) {
            $FindingDetails += "ApplicationPool:`t$($Item.ApplicationPool)" | Out-String
            if (($Item.WebSiteUsage | Measure-Object).Count -gt 1) {
                $Compliant = $false
                $FindingDetails += "WebSiteUsage:`t$($Item.WebSiteUsage -Join ', ') [Multiple websites. Finding.]" | Out-String
            }
            else {
                $FindingDetails += "WebSiteUsage:`t$($Item.WebSiteUsage)" | Out-String
            }
            $FindingDetails += "" | Out-String
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
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

Function Get-V218772 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218772
        STIG ID    : IIST-SI-000252
        Rule ID    : SV-218772r1022694_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The maximum number of requests an application pool can process for each IIS 10.0 website must be explicitly set.
        DiscussMD5 : BC308B4474DA3E9E8DC3BC21EB332F69
        CheckMD5   : 7DD006A2ADB0722E20E9151BE0D27AF5
        FixMD5     : 9CE43C4163D7736041E2041601D485AF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    elseif (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $Compliant = $true
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-ChildItem IIS:\AppPools
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $AppPools = Powershell.exe -NoProfile -Command $CommandSB

        foreach ($AppPool in $AppPools) {
            $FindingDetails += "Application Pool:`t$($AppPool.Name)" | Out-String
            $FindingDetails += "Request Limit:`t`t$($AppPool.recycling.periodicRestart.requests)" | Out-String
            $FindingDetails += "" | Out-String
            if ($AppPool.recycling.periodicRestart.requests -eq 0) {
                $Compliant = $false
            }
        }

        if ($Compliant -eq $true) {
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

Function Get-V218775 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218775
        STIG ID    : IIST-SI-000255
        Rule ID    : SV-218775r1022696_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pool for each IIS 10.0 website must have a recycle time explicitly set.
        DiscussMD5 : 85F41E23F947B3FFBF7BFE277197A2B1
        CheckMD5   : 6A6BB21D7C0EB1F593B3747810EE9B1F
        FixMD5     : 71B9490734F036C9913D36A6EB45CBEA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    elseif (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    elseif (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-ChildItem IIS:\AppPools
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $AppPools = Powershell.exe -NoProfile -Command $CommandSB
        $AppPoolRecycling = New-Object System.Collections.Generic.List[System.Object]

        foreach ($AppPool in $AppPools) {
            $Conditions = New-Object System.Collections.Generic.List[System.Object]
            # Get 'memory', 'privateMemory', 'requests', and 'time'
            foreach ($Attribute in $AppPool.recycling.periodicRestart.Attributes) {
                $NewObj = [PSCustomObject]@{
                    Name       = $Attribute.Name
                    Enabled    = $(if ($Attribute.Value -ne 0) {
                            $true
                        }
                        else {
                            $false
                        })
                    LogEnabled = $(if ($Attribute.name -in @($AppPool.recycling.logEventOnRecycle -split ",")) {
                            $true
                        }
                        else {
                            $false
                        })
                }
                $Conditions.Add($NewObj)
            }

            # Get 'schedule'
            $NewObj = [PSCustomObject]@{
                Name       = "schedule"
                Enabled    = $(if ($AppPool.recycling.periodicRestart.schedule.Collection) {
                        $true
                    }
                    else {
                        $false
                    })
                LogEnabled = $(if ("Schedule" -in @($AppPool.recycling.logEventOnRecycle -split ",")) {
                        $true
                    }
                    else {
                        $false
                    })
            }
            $Conditions.Add($NewObj)

            # Build AppPoolRecycling list
            $NewObj = [PSCustomObject]@{
                AppPoolName = $AppPool.name
                Conditions  = $Conditions
            }
            $AppPoolRecycling.Add($NewObj)
        }

        # Evaluate application pool recycling
        $Compliant = $true
        $CompliantAppPools = New-Object System.Collections.Generic.List[System.Object]
        $BadAppPools = New-Object System.Collections.Generic.List[System.Object]
        foreach ($AppPool in $AppPoolRecycling) {
            if (-not($AppPool.Conditions | Where-Object Enabled -EQ $true)) {
                $NewObj = [PSCustomObject]@{
                    AppPoolName = $AppPool.AppPoolName
                    Reason      = "No Recycling Conditions are enabled."
                }
                $BadAppPools.Add($NewObj)
            }
            else {
                if ($AppPool.Conditions | Where-Object {($_.Enabled -eq $true -and $_.LogEnabled -ne $true)}) {
                    $NewObj = [PSCustomObject]@{
                        AppPoolName = $AppPool.AppPoolName
                        Reason      = "Logging not enabled for selected Recycling Conditions."
                        Conditions  = $($AppPool.Conditions | Where-Object {($_.Enabled -eq $true -and $_.LogEnabled -ne $true)})
                    }
                    $BadAppPools.Add($NewObj)
                }
                else {
                    $NewObj = [PSCustomObject]@{
                        AppPoolName = $AppPool.AppPoolName
                        Conditions  = $($AppPool.Conditions | Where-Object {($_.Enabled -eq $true -and $_.LogEnabled -eq $true)})
                    }
                    $CompliantAppPools.Add($NewObj)
                }
            }
        }

        if ($BadAppPools) {
            $Compliant = $false
            $FindingDetails += "Non-Compliant AppPools:" | Out-String
            $FindingDetails += "-----------------------------------" | Out-String
            foreach ($AppPool in $BadAppPools) {
                $FindingDetails += "AppPool:`t$($AppPool.AppPoolName)" | Out-String
                $FindingDetails += "Reason:`t$($AppPool.Reason)" | Out-String
                foreach ($Condition in $AppPool.Conditions) {
                    $FindingDetails += "Condition:`t$($Condition.Name) [Enabled=$($Condition.Enabled); LogEnabled=$($Condition.LogEnabled)]" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
            $FindingDetails += "" | Out-String
        }

        if ($CompliantAppPools) {
            $FindingDetails += "Compliant AppPools:" | Out-String
            $FindingDetails += "-----------------------------------" | Out-String
            foreach ($AppPool in $CompliantAppPools) {
                $FindingDetails += "AppPool:`t$($AppPool.AppPoolName)" | Out-String
                foreach ($Condition in $AppPool.Conditions) {
                    $FindingDetails += "Condition:`t$($Condition.Name) [Enabled=$($Condition.Enabled); LogEnabled=$($Condition.LogEnabled)]" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }

        if ($Compliant -eq $true) {
            $Status = "NotAFinding"
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

Function Get-V218777 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218777
        STIG ID    : IIST-SI-000258
        Rule ID    : SV-218777r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pools rapid fail protection for each IIS 10.0 website must be enabled.
        DiscussMD5 : FD664C89A13E2B030E2BFB132FA3CDD1
        CheckMD5   : 826D768371BB96F4142D8A5F30873CC8
        FixMD5     : B782F14ABF48B2E7B7D84D90A5E942AA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    elseif (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-ChildItem IIS:\AppPools
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $AppPools = Powershell.exe -NoProfile -Command $CommandSB

        foreach ($AppPool in $AppPools) {
            $FindingDetails += "Application Pool:`t`t$($AppPool.Name)" | Out-String
            $FindingDetails += "Rapid Fail Protection:`t$($AppPool.failure.rapidFailProtection)" | Out-String
            $FindingDetails += "" | Out-String
            if ($AppPool.failure.rapidFailProtection -ne $true) {
                $Status = "Open"
            }
        }

        if ($Status -ne "Open") {
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

Function Get-V218778 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218778
        STIG ID    : IIST-SI-000259
        Rule ID    : SV-218778r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pools rapid fail protection settings for each IIS 10.0 website must be managed.
        DiscussMD5 : 7FEAC86403939EC9526508634BC69459
        CheckMD5   : 72C9529F65E28D8FC7EA6E23ACA4C3AB
        FixMD5     : FDA669BD6DBC46CD0C785707F09B2695
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    elseif (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-ChildItem IIS:\AppPools
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $AppPools = Powershell.exe -NoProfile -Command $CommandSB
        $Span = New-TimeSpan -Hours 00 -Minutes 05 -Seconds 00

        foreach ($AppPool in $AppPools) {
            $FindingDetails += "Application Pool:`t$($AppPool.Name)" | Out-String
            $FindingDetails += "Failure Interval:`t$($AppPool.failure.rapidFailProtectionInterval.Minutes)" | Out-String
            $FindingDetails += "" | Out-String
            if ($AppPool.failure.rapidFailProtectionInterval.CompareTo($Span) -gt 0) {
                $Status = "Open"
            }
        }

        if ($Status -ne "Open") {
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

Function Get-V218779 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218779
        STIG ID    : IIST-SI-000261
        Rule ID    : SV-218779r1022698_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Interactive scripts on the IIS 10.0 web server must be located in unique and designated folders.
        DiscussMD5 : 0572B5B1F6FA193BA557D59469552114
        CheckMD5   : 9F5F2A5AC77570EAD7C265812A42E386
        FixMD5     : 09A7C09CA7713C590AE849BB588E8751
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $EnabledFeature = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^Web-CGI$|^IIS-CGI$)" -and $_.Enabled -eq $true}
    if (-not($EnabledFeature)) {
        $Status = "Not_Applicable"
        $FindingDetails += "CGI is not installed so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object Name,physicalPath
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WebSite = Powershell.exe -NoProfile -Command $CommandSB
        $WebDirectories = @()
        $ListOfScripts = @()

        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        # Required mechanism to leverage the extended attribute to be able to grab the name handle of hosted applications
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebApplication -Site "' + $WebSite.Name + '" | Select-Object @{n = "Site"; e = {$_.GetParentElement().Attributes["name"].value + $_.path }}, @{n = "PhysicalPath"; e = {$_.PhysicalPath}}
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Applications = Powershell.exe -NoProfile -Command $CommandSB
        $Applications | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive

            # Remove website name and trailing / from variable to allow for application name reference
            $ApplicationName = $_.Site.substring($_.Site.IndexOf('/') + 1)
            $PSCommand = '
                If (-Not(Get-Module -Name WebAdministration)) {
                    Import-Module WebAdministration
                }
                Get-WebVirtualDirectory -Site "' + $WebSite.Name + '" -Application "' + $ApplicationName + '"
            '
            $CommandSB = [scriptblock]::Create($PSCommand)
            $VDirectories = Powershell.exe -NoProfile -Command $CommandSB
            $VDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebVirtualDirectory -site "' + $WebSite.name + '"
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $VirtualDirectories = Powershell.exe -NoProfile -Command $CommandSB
        $VirtualDirectories | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        }

        $DirectoriesToScan = $WebDirectories | Select-Object -Unique
        foreach ($Directory in $DirectoriesToScan) {
            if (Test-Path $Directory) {
                $ListOfScripts += Search-Files -Path $Directory -File @("*.cgi", "*.pl", "*.vb", "*.class", "*.c", "*.php", "*.asp")
            }
        }

        if (-not($ListOfScripts) -or ($ListOfScripts -eq "") -or ($ListOfScripts.Count -le 0)) {
            $Status = "NotAFinding"
            $FindingDetails += "There are no interactive scripts detected for this site."
        }
        else {
            $FindingDetails += "The following scripts were found:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $ListOfScripts | Out-String
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

Function Get-V218780 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218780
        STIG ID    : IIST-SI-000262
        Rule ID    : SV-218780r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Interactive scripts on the IIS 10.0 web server must have restrictive access controls.
        DiscussMD5 : 6007F8A21ABC8D716FFC4FBE87251AE3
        CheckMD5   : 99697C6341E4650278436928D54299B5
        FixMD5     : 9C30E9911BDED4DB74CF7C21238112C0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $EnabledFeature = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^Web-CGI$|^IIS-CGI$)" -and $_.Enabled -eq $true}
    if (-not($EnabledFeature)) {
        $Status = "Not_Applicable"
        $FindingDetails += "CGI is not installed so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object Name,physicalPath
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WebSite = Powershell.exe -NoProfile -Command $CommandSB
        $WebDirectories = @()
        $ListOfScripts = @()

        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        # Required mechanism to leverage the extended attribute to be able to grab the name handle of hosted applications
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebApplication -Site "' + $WebSite.Name + '" | Select-Object @{n = "Site"; e = {$_.GetParentElement().Attributes["name"].value + $_.path }}, @{n = "PhysicalPath"; e = {$_.PhysicalPath}}
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Applications = Powershell.exe -NoProfile -Command $CommandSB
        $Applications | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive

            # Remove website name and trailing / from variable to allow for application name reference
            $ApplicationName = $_.Site.substring($_.Site.IndexOf('/') + 1)
            $PSCommand = '
                If (-Not(Get-Module -Name WebAdministration)) {
                    Import-Module WebAdministration
                }
                Get-WebVirtualDirectory -Site "' + $WebSite.Name + '" -Application "' + $ApplicationName + '"
            '
            $CommandSB = [scriptblock]::Create($PSCommand)
            $VDirectories = Powershell.exe -NoProfile -Command $CommandSB
            $VDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebVirtualDirectory -site "' + $WebSite.name + '"
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $VirtualDirectories = Powershell.exe -NoProfile -Command $CommandSB
        $VirtualDirectories | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        }

        $DirectoriesToScan = $WebDirectories | Select-Object -Unique
        foreach ($Directory in $DirectoriesToScan) {
            if (Test-Path $Directory) {
                $ListOfScripts += Search-Files -Path $Directory -File @("*.cgi", "*.pl", "*.vb", "*.class", "*.c", "*.php", "*.asp", "*.aspx")
            }
        }

        if (-not($ListOfScripts) -or ($ListOfScripts -eq "")) {
            $Status = "NotAFinding"
            $FindingDetails += "There are no interactive scripts detected for this site."
        }
        else {
            $FindingDetails += "The following scripts were found:" | Out-String
            $FindingDetails += "" | Out-String
            foreach ($Script in $ListOfScripts) {
                $FindingDetails += $Script | Out-String
                $Acl = Get-Acl $Script
                $FindingDetails += $Acl.Access | Select-Object IdentityReference, AccessControlType, FileSystemRights | Format-List | Out-String
                $FindingDetails += "------------------------------------------" | Out-String
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

Function Get-V218781 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218781
        STIG ID    : IIST-SI-000263
        Rule ID    : SV-218781r1022700_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Backup interactive scripts on the IIS 10.0 server must be removed.
        DiscussMD5 : 16FE195BE4C481B86B358480769EC41A
        CheckMD5   : 8FF50D44A1978EBA4FBFA09AE2A1F5C8
        FixMD5     : ACD210A8BEF16A595452C35B9F13DCB1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $EnabledFeature = Get-WindowsFeatureState | Where-Object {$_.Name -match "(^Web-CGI$|^IIS-CGI$)" -and $_.Enabled -eq $true}
    if (-not($EnabledFeature)) {
        $Status = "Not_Applicable"
        $FindingDetails += "CGI is not installed so this requirement is NA."
    }
    else {
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebSite -Name "' + $($SiteName -replace "'" -replace '"') + '" | Select-Object Name,physicalPath
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $WebSite = Powershell.exe -NoProfile -Command $CommandSB
        $WebDirectories = @()
        $ListOfBackups = ""

        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebApplication -site "' + $WebSite.name + '"
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $Applications = Powershell.exe -NoProfile -Command $CommandSB
        $Applications | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        }
        $PSCommand = '
            If (-Not(Get-Module -Name WebAdministration)) {
                Import-Module WebAdministration
            }
            Get-WebVirtualDirectory -site "' + $WebSite.name + '"
        '
        $CommandSB = [scriptblock]::Create($PSCommand)
        $VirtualDirectories = Powershell.exe -NoProfile -Command $CommandSB
        $VirtualDirectories | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        }

        $DirectoriesToScan = $WebDirectories | Select-Object -Unique
        foreach ($Directory in $DirectoriesToScan) {
            if (Test-Path $Directory) {
                Get-ChildItem $Directory -Recurse -Include *.bak, *.old, *.temp, *.tmp, *.backup, "*copy of*" | Select-Object FullName | ForEach-Object {
                    $ListOfBackups += $_.FullName | Out-String
                }
            }
        }

        if (-not($ListOfBackups) -or ($ListOfBackups -eq "")) {
            $Status = "NotAFinding"
            $FindingDetails += "There are no backup scripts on any of the websites."
        }
        else {
            $FindingDetails += "The following backup files were found:" | Out-String
            $FindingDetails += "" | Out-String
            foreach ($File in $ListOfBackups) {
                $FindingDetails += $File | Out-String
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

Function Get-V218782 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218782
        STIG ID    : IIST-SI-000264
        Rule ID    : SV-218782r1111818_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The required DoD banner page must be displayed to authenticated users accessing a DoD private website.
        DiscussMD5 : 9C2E2539C76D03A5178FAD17C94C9912
        CheckMD5   : 07F23AD9B30B9910E543A4331591AC68
        FixMD5     : 6E6A70D82DBDD28415684C854E85B346
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDx+EFobNQm6Kjo
# RjHdaIp/UocQWQuNztcaTdTw9WFW+6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCCpb9kQUC5bxzfl6f1LtzbwfkNnffb8wLaLEOWUzJXQ6DANBgkqhkiG9w0BAQEF
# AASCAQCvV7quP9fW0JbLgGMrMIADUchNIRTIaj1D6omK83LtDXt0ooDpHbsV4BGy
# Spd0y+n18o1jT+2smCbjCLllPkXrC0TMPINkALquN7fKxcBWzrwQ0Bj1lPXVUbjX
# nmxs2x0shrpJy6eIkP+Z+xG2ICGj53RNuADR0K7Qx5sCb96QmNqD6FHqbw0FlPIP
# V4vPxcSC+3vJKRFpt6/i73kJkY2CTxff62XfYCazroBT6Mgqz0MtmZlw8DQWa+NS
# 1nostG6DN8rBVUl2wOLDWGu7np5z2InI/5BNYOlJx5o2Y6WsL3UUTLIn/x5cbMJU
# eg7ayJ4N/j53OlHWWTmZ9fBVM7KZoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkyMjEzNTkwN1owLwYJKoZIhvcNAQkEMSIEIMcJYYYAkMpfznER3qMSbJ5Ef9l3
# pRyvs++oWEX/c2svMA0GCSqGSIb3DQEBAQUABIICALEWVjsubsGXasaD0dc3zq2R
# z5IVt8ZO9zmFZ2Gf4qkwY1MEDUeV5AEzqqq8qarFgDrGvelbiMBmVmHWK4miQbk8
# IC6IOhrv9UVa7SXP+ETN9JvP4H4zXI7QNfQ3MS3BFpw4eDUZ5y0F4RJhKwYgZ16m
# jWBvCR9rD5RyZQGH/G3ccCuYa2JD6V5ye2ZTVgMuZfFQ24wAyXqHMi2+avcnxNiH
# fyjofgD9lqpVmkN1dRxA8QjYne0xSyf6UYzghBfvMOECtwJdNxN3nvUbrXrj+thb
# Du5u7IWwtkDGDi2dbg02eEhLqfeT8PPukHC/w3ehlv8TABxQwuw9ADyYGWY5lTh3
# /Ek/eVdnUQUgCnRhOUvHtEJK9mikp/lTQewa0oHpk5mHgknY0NuUrKZgyVh1X5s8
# /kWuJFZiNFnqQMnc8vQA/6QFHlwbW9NUsj/z9OP+kZUrMjvExUe2n3vcj4l3rh/Y
# jxoaGjrkECyPnHK9wHT5b6F5UuQWgXpnDTssy0tDv/ppsf71PiDSW4peyUPpFEx1
# zMHYHoOXCuBffFykICqSjeVkaAM/mQNvEfXROji7Hu20KLkLojykMBe0/f7BD10Q
# sH3E3CWcAKK8BAHpMOf+Q2ethr0Qacxi8FbjXPgqKpLXLC2C2Eqe1JOtvQsEb+ii
# 9l79aJU4ZKSbQhwt6Aum
# SIG # End signature block
