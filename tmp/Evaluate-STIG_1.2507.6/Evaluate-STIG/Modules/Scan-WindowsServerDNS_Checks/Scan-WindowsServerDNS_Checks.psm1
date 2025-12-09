##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Windows Server Domain Name System (DNS)
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Format-TimeSpanToHours {
    param($Span)

    If ($Span -is [TimeSpan]) {
        [int]$Hours = $Span.Days * 24 + $Span.Hours
    }
    Else {
        $Hours = "Unable to convert '$($Span)' to hours"
    }
    Return $Hours
}

Function Test-IsDNSCachingOnly {
    If (Get-DnsServerZone -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}) {
        Return $false
    }
    Else {
        Return $true
    }
}

Function Get-V259334 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259334
        STIG ID    : WDNS-22-000001
        Rule ID    : SV-259334r960735_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-DNS-000115
        Rule Title : The Windows DNS Server must restrict incoming dynamic update requests to known clients.
        DiscussMD5 : 3C3681B6D9E4908EE51C356D13B80DE9
        CheckMD5   : 4AE3200C2140F7B7E6DBF7FACFB2690C
        FixMD5     : 6863F7FBA62B5D139F39691F9439887E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.IsDsIntegrated -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If ($Zones | Where-Object DynamicUpdate -NE "Secure") {
                $Compliant = $false
                $FindingDetails += "The following Active Directory-Integrated Forward Lookup Zones do not have Dynamic Updates configured to 'Secure Only':" | Out-String
                $FindingDetails += "---------------------------" | Out-String
                ForEach ($Zone in ($Zones | Where-Object DynamicUpdate -NE "Secure")) {
                    $FindingDetails += "ZoneName:`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "DynamicUpdate:`t$($Zone.DynamicUpdate)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $FindingDetails += "All Active Directory-Integrated Forward Lookup Zones have Dynamic Updates configured to 'Secure Only'." | Out-String
            }
        }
        Else {
            $FindingDetails += "No Active Directory-Integrated Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259335 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259335
        STIG ID    : WDNS-22-000002
        Rule ID    : SV-259335r987677_rule
        CCI ID     : CCI-000366, CCI-001902
        Rule Name  : SRG-APP-000348-DNS-000042
        Rule Title : The Windows DNS Server must be configured to record who added/modified/deleted DNS zone information.
        DiscussMD5 : D2CE047773E4C18642F588F1C7CBCDE0
        CheckMD5   : D00C4667AE2ED15FB60E50E6C41B98F2
        FixMD5     : 504DAB81E84EE077C3F91E45A4BB8C26
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverdiagnostics?view=windowsserver2022-ps#-eventloglevel
    $Compliant = $true

    $EventLogLevel = (Get-DnsServerDiagnostics -ComputerName $env:COMPUTERNAME).EventLogLevel
    Switch ($EventLogLevel) {
        "0" {
            $Compliant = $false
            $EventLogLevel = "$_ - No events"
        }
        "1" {
            $Compliant = $false
            $EventLogLevel = "$_ - Errors only"
        }
        "2" {
            $EventLogLevel = "$_ - Errors and warnings"
        }
        {$_ -in 3..7} {
            $EventLogLevel = "$_ - All events"
        }
    }
    $FindingDetails += "EventLogLevel:`t`t$EventLogLevel" | Out-String

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

Function Get-V259336 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259336
        STIG ID    : WDNS-22-000003
        Rule ID    : SV-259336r987679_rule
        CCI ID     : CCI-000366, CCI-001906
        Rule Name  : SRG-APP-000350-DNS-000044
        Rule Title : The Windows DNS Server must notify the DNS administrator in the event of an error validating another DNS server's identity.
        DiscussMD5 : 64DB0711810D54FC26260D8B25F0A222
        CheckMD5   : D141E7183574469B131DBAA7B0B72341
        FixMD5     : 78B5631DAB9418457FEC5AE404D63F76
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {($_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated)))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $AllDCs = $true
                ForEach ($Zone in $Zones) {
                    $NameServers = ((Get-DnsServerResourceRecord -ZoneName $Zone.ZoneName -RRType Ns).RecordData.NameServer | Select-Object -Unique)
                    ForEach ($NameServer in $NameServers) {
                        Try {
                            $null = Get-ADDomainController -Identity $($NameServer -replace "\.$") -ErrorAction Stop
                        }
                        Catch {
                            $AllDCs = $false
                            Break
                        }
                    }

                    If ($AllDCs = $false) {
                        Break
                    }
                }
                If ($AllDCs) {
                    $Status = "Not_Applicable"
                    $FindingDetails += "All Zones hosted on this server are Active Directory-integrated and all name servers for the hosted zones are domain controllers so this requirement is NA." | Out-String
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No zones are hosted on this server." | Out-String
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

Function Get-V259337 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259337
        STIG ID    : WDNS-22-000004
        Rule ID    : SV-259337r960879_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-DNS-000004
        Rule Title : The Windows DNS Server log must be enabled.
        DiscussMD5 : 11746CE2903E25E7E9761EFB998E293E
        CheckMD5   : D00C4667AE2ED15FB60E50E6C41B98F2
        FixMD5     : D7F26C1DEEF1F2734BFFC4458E6DDD11
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverdiagnostics?view=windowsserver2022-ps#-eventloglevel
    $Compliant = $true

    $EventLogLevel = (Get-DnsServerDiagnostics -ComputerName $env:COMPUTERNAME).EventLogLevel
    Switch ($EventLogLevel) {
        "0" {
            $Compliant = $false
            $EventLogLevel = "$_ - No events"
        }
        "1" {
            $Compliant = $false
            $EventLogLevel = "$_ - Errors only"
        }
        "2" {
            $EventLogLevel = "$_ - Errors and warnings"
        }
        {$_ -in 3..7} {
            $EventLogLevel = "$_ - All events"
        }
    }
    $FindingDetails += "EventLogLevel:`t`t$EventLogLevel" | Out-String

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

Function Get-V259338 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259338
        STIG ID    : WDNS-22-000006
        Rule ID    : SV-259338r1028386_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000500
        Rule Title : The "Manage auditing and security log" user right must be assigned only to authorized personnel.
        DiscussMD5 : C73C916B1726DAC6AEFA83633061DA53
        CheckMD5   : E003C971EDA99BB7A0F99F3D5878DC9D
        FixMD5     : 9386218102514B16D51565D609C94E72
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $UserRight = "SeSecurityPrivilege"
    $UserRightDisplayName = "Manage auditing and security log"
    $ExpectedObjects = @("BUILTIN\Administrators") #As specified in the STIG
    $EmptyAllowed = $true
    $SecPolIni = Get-IniContent $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_SecPol.ini
    $ResolvedObjects = @()
    $Compliant = $true

    If ($SecPolIni.'Privilege Rights'.$UserRight) {
        $AssignedRights = ($SecPolIni.'Privilege Rights'.$UserRight).Replace("*", "") -split ","
        ForEach ($Object in $AssignedRights) {
            If ($Object -match "S-1-") {
                $objSID = New-Object System.Security.Principal.SecurityIdentifier($Object)
                Try {
                    $ResolvedItem = $objSID.Translate([System.Security.Principal.NTAccount]).Value
                    $ResolvedObjects += $ResolvedItem
                    If ($ResolvedItem -notin $ExpectedObjects) {
                        $Compliant = $false
                    }
                }
                Catch {
                    $Compliant = $false
                    $ResolvedObjects += $Object
                }
            }
            Else {
                $Compliant = $false
                $ResolvedObjects += $Object
            }
        }
    }
    Else {
        If ($EmptyAllowed -ne $true) {
            $Compliant = $false
        }
        $ResolvedObjects += "No objects assigned to this right."
    }

    $FindingDetails += "$($UserRightDisplayName):" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $ResolvedObjects | Sort-Object | Out-String
    $FindingDetails += "" | Out-String

    $LogName = "DNS Server"
    $Path = [Environment]::ExpandEnvironmentVariables((Get-WinEvent -ListLog $LogName).LogFilePath)
    If (Test-Path $Path) {
        $AclToEval = @("NT SERVICE\EventLog:(I)(F)", "NT AUTHORITY\SYSTEM:(I)(F)", "BUILTIN\Administrators:(I)(F)") # These are true OS default permissions
        $AclCheck = Confirm-DefaultAcl -Type FileSystem -Path $Path -DefaultAcl $AclToEval

        $FindingDetails += $Path | Out-String
        $FindingDetails += "---------------------" | Out-String
        If ($AclCheck.IsDefault -ne $true) {
            $Compliant = $false
            $FindingDetails += "ACL findings:" | Out-String
            ForEach ($Acl in $AclCheck.AclFindings) {
                $FindingDetails += $Acl | Out-String
            }
        }
        Else {
            $FindingDetails += "Default permissions are in place." | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "Current ACL:" | Out-String
        ForEach ($Acl in $AclCheck.Acl) {
            $FindingDetails += $Acl | Out-String
        }
        $FindingDetails += "---------------------" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += $Path | Out-String
        $FindingDetails += "---------------------" | Out-String
        $FindingDetails += "Log file not found." | Out-String
    }

    If ($Compliant -eq $true) {
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

Function Get-V259339 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259339
        STIG ID    : WDNS-22-000007
        Rule ID    : SV-259339r961104_rule
        CCI ID     : CCI-001179
        Rule Name  : SRG-APP-000214-DNS-000079
        Rule Title : The validity period for the Resource Record Signatures (RRSIGs) covering the Delegation Signer (DS) Resource Record (RR) for a zone's delegated children must be no less than two days and no more than one week.
        DiscussMD5 : 6D661BB49B63A2B8B683F12F75261572
        CheckMD5   : 9C86A6C4D1B82DBD1EE6C5541C273D52
        FixMD5     : C6A0AEE4735777524EDBDCA9E8B4CB71
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsReverseLookupZone:`t$($Zone.IsReverseLookupZone)" | Out-String
                    If ($Zone.IsSigned) {
                        $FindingDetails += "IsSigned:`t`t`t`t$($Zone.IsSigned)" | Out-String
                        $ZSK = Get-DnsServerSigningKey -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName | Where-Object KeyType -EQ "ZoneSigningKey"
                        If ($ZSK) {
                            ForEach ($Item in $ZSK) {
                                $FindingDetails += "ZSK_KeyId:`t`t`t$($Item.KeyId)" | Out-String
                                $ZSKDSRRValidity = Format-TimeSpanToHours -Span ($Item).DSSignatureValidityPeriod
                                If ($ZSKDSRRValidity -is [Int]) {
                                    If ($ZSKDSRRValidity -ge 48 -and $ZSKDSRRValidity -le 168) {
                                        $FindingDetails += "ZSK_DS_RR_Period:`t`t$($ZSKDSRRValidity) hours" | Out-String
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "ZSK_DS_RR_Period:`t`t$($ZSKDSRRValidity) hours [expected between 48 and 168]" | Out-String
                                    }
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "ZSK_DS_RR_Period:`t`t$($ZSKDSRRValidity) [finding]" | Out-String
                                }
                            }
                        }
                        Else {
                            $FindingDetails += "No ZSK data returned [finding]" | Out-String
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "IsSigned:`t`t`t`t$($false) [finding]" | Out-String
                    }

                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259340 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259340
        STIG ID    : WDNS-22-000008
        Rule ID    : SV-259340r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000218-DNS-000027
        Rule Title : The Windows DNS name servers for a zone must be geographically dispersed.
        DiscussMD5 : AD53D455801025E6237C659CD1F6F668
        CheckMD5   : 54044B1A4DEC9EC82C32770DF777036D
        FixMD5     : 1280F1D66C78FD1682857F2D79957721
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {($_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated)))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $AllDCs = $true
                ForEach ($Zone in $Zones) {
                    $NameServers = ((Get-DnsServerResourceRecord -ZoneName $Zone.ZoneName -RRType Ns).RecordData.NameServer | Select-Object -Unique)
                    ForEach ($NameServer in $NameServers) {
                        Try {
                            $null = Get-ADDomainController -Identity $($NameServer -replace "\.$") -ErrorAction Stop
                        }
                        Catch {
                            $AllDCs = $false
                            Break
                        }
                    }

                    If ($AllDCs = $false) {
                        Break
                    }
                }
                If ($AllDCs) {
                    $Status = "Not_Applicable"
                    $FindingDetails += "All Zones hosted on this server are Active Directory-integrated and all name servers for the hosted zones are domain controllers so this requirement is NA." | Out-String
                }
            }
        }
        Else {
            $FindingDetails += "No zones are hosted on this server." | Out-String
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

Function Get-V259341 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259341
        STIG ID    : WDNS-22-000009
        Rule ID    : SV-259341r1081088_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000383-DNS-000047
        Rule Title : The Windows DNS Server must prohibit recursion on authoritative name servers for which forwarders have not been configured for external queries.
        DiscussMD5 : A7F9FCEA20BD1556D526AD9CAD262026
        CheckMD5   : 1D9211DB31431E7F3EB30AA8499EDE2A
        FixMD5     : 4155FFA25D602048F4C23705D5B42455
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -in @("Classified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA." | Out-String
    }
    Else {
        $DnsForwarder = Get-DnsServerForwarder -ComputerName $env:COMPUTERNAME
        $DnsRecursion = Get-DnsServerRecursion -ComputerName $env:COMPUTERNAME
        If (($DnsForwarder.IPAddress | Measure-Object).Count -ge 1) {
            If ($DnsRecursion.Enable -eq $true) {
                $Status = "Not_Applicable"
                $FindingDetails += "Forwarders are configured and enabled so this requirement is NA." | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Status = "NotAFinding"
                $FindingDetails += "Forwarders are configured but not enabled (due to disabled recursion).  NOT A FINDING." | Out-String
                $FindingDetails += "" | Out-String
            }
            $FindingDetails += "RecursionEnable:`t$($DnsRecursion.Enable)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Forwarders:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            ForEach ($Forwarder in $DnsForwarder.IPAddress) {
                Try {
                    $FindingDetails += "$($Forwarder.IPAddressToString) : $((Resolve-DnsName -Name $Forwarder.IPAddressToString -ErrorAction Stop).NameHost)" | Out-String
                }
                Catch {
                    $FindingDetails += "$($Forwarder.IPAddressToString) : Unable to resolve" | Out-String
                }
            }
        }
        Else {
            $FindingDetails += "Forwarders are not configured." | Out-String
            $FindingDetails += "" | Out-String
            If ($DnsRecursion.Enable -eq $false) {
                $Status = "NotAFinding"
                $FindingDetails += "RecursionEnable:`t$($DnsRecursion.Enable)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "RecursionEnable:`t$($DnsRecursion.Enable) [finding]" | Out-String
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

Function Get-V259342 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259342
        STIG ID    : WDNS-22-000010
        Rule ID    : SV-259342r961470_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000383-DNS-000047
        Rule Title : Forwarders on an authoritative Windows DNS Server, if enabled for external resolution, must forward only to an internal, non-Active Directory (AD)-integrated DNS server or to the DOD Enterprise Recursive Services (ERS).
        DiscussMD5 : A7F9FCEA20BD1556D526AD9CAD262026
        CheckMD5   : F28BF703185695039CF09C23977E5C9A
        FixMD5     : 5322458A10702C496F5E38C8B04AA852
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    Else {
        $DnsForwarder = Get-DnsServerForwarder -ComputerName $env:COMPUTERNAME
        $DnsRecursion = Get-DnsServerRecursion -ComputerName $env:COMPUTERNAME
        If (($DnsForwarder.IPAddress | Measure-Object).Count -eq 0) {
            If ($DnsForwarder.UseRootHint -eq $false) {
                $Status = "Not_Applicable"
                $FindingDetails += "Forwarders are not configured and root hints are disabled so this requirement is NA." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "UseRootHint:`t`t$($DnsForwarder.UseRootHint)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "Forwarders are not configured and root hints are NOT disabled." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "UseRootHint:`t`t$($DnsForwarder.UseRootHint) [finding]" | Out-String
            }
        }
        Else {
            If ($DnsRecursion.Enable -eq $false) {
                If ($DnsForwarder.UseRootHint -eq $false) {
                    $Status = "Not_Applicable"
                    $FindingDetails += "Forwarders are configured but not enabled (due to disabled recursion) and root hints are disabled so this requirement is NA." | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "RecursionEnable:`t$($DnsRecursion.Enable)" | Out-String
                    $FindingDetails += "UseRootHint:`t`t$($DnsForwarder.UseRootHint)" | Out-String
                    $FindingDetails += "" | Out-String

                }
                Else {
                    $Status = "Open"
                    $FindingDetails += "Forwarders are configured but not enabled (due to disabled recursion) and root hints are NOT disabled." | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "RecursionEnable:`t$($DnsRecursion.Enable)" | Out-String
                    $FindingDetails += "UseRootHint:`t`t$($DnsForwarder.UseRootHint) [finding]" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                If ($DnsForwarder.UseRootHint -eq $false) {
                    $FindingDetails += "Forwarders are in use." | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "RecursionEnable:`t$($DnsRecursion.Enable)" | Out-String
                    $FindingDetails += "UseRootHint:`t`t$($DnsForwarder.UseRootHint)" | Out-String
                    $FindingDetails += "" | Out-String

                }
                Else {
                    $Status = "Open"
                    $FindingDetails += "Forwarders in use and root hints are NOT disabled." | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "RecursionEnable:`t$($DnsRecursion.Enable)" | Out-String
                    $FindingDetails += "UseRootHint:`t`t$($DnsForwarder.UseRootHint) [finding]" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            $FindingDetails += "Forwarders:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            ForEach ($Forwarder in $DnsForwarder.IPAddress) {
                Try {
                    $FindingDetails += "$($Forwarder.IPAddressToString) : $((Resolve-DnsName -Name $Forwarder.IPAddressToString -ErrorAction Stop).NameHost)" | Out-String
                }
                Catch {
                    $FindingDetails += "$($Forwarder.IPAddressToString) : Unable to resolve" | Out-String
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

Function Get-V259344 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259344
        STIG ID    : WDNS-22-000013
        Rule ID    : SV-259344r961635_rule
        CCI ID     : CCI-002421
        Rule Name  : SRG-APP-000440-DNS-000065
        Rule Title : The Windows DNS Server must implement cryptographic mechanisms to detect changes to information during transmission.
        DiscussMD5 : 4908577721BBB5AD5663DFF1F1C25A63
        CheckMD5   : CEFADECA7D1FF2EEA5D4A49BCEE6E176
        FixMD5     : 07331E28169223333393323B04AF98A0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259345 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259345
        STIG ID    : WDNS-22-000014
        Rule ID    : SV-259345r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000078
        Rule Title : The validity period for the Resource Record Signatures (RRSIGs) covering a zone's DNSKEY RRSet must be no less than two days and no more than one week.
        DiscussMD5 : BC36AA7824BBEC5E80166E44E8DB8FC2
        CheckMD5   : F4B52472228BCC496CD4139B24819228
        FixMD5     : 92CA72DD5059DF1B56D68E8A98D834FA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t`t`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsReverseLookupZone:`t`t$($Zone.IsReverseLookupZone)" | Out-String
                    If ($Zone.IsSigned) {
                        $FindingDetails += "IsSigned:`t`t`t`t`t$($Zone.IsSigned)" | Out-String
                        $KSK = Get-DnsServerSigningKey -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName | Where-Object KeyType -EQ "KeySigningKey"
                        $ZSK = Get-DnsServerSigningKey -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName | Where-Object KeyType -EQ "ZoneSigningKey"
                        If ($KSK) {
                            ForEach ($Item in $KSK) {
                                $FindingDetails += "KSK_KeyId:`t`t`t`t$($Item.KeyId)" | Out-String
                                $KSKDNSKEYValidity = Format-TimeSpanToHours -Span ($Item).DnsKeySignatureValidityPeriod
                                If ($KSKDNSKEYValidity -is [Int]) {
                                    If ($KSKDNSKEYValidity -ge 48 -and $KSKDNSKEYValidity -le 168) {
                                        $FindingDetails += "KSK_DNSKEY_RRSET_Period:`t$($KSKDNSKEYValidity) hours" | Out-String
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "KSK_DNSKEY_RRSET_Period:`t$($KSKDNSKEYValidity) hours [expected between 48 and 168]" | Out-String
                                    }
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "KSK_DNSKEY_RRSET_Period:`t$($KSKDNSKEYValidity) [finding]" | Out-String
                                }
                            }
                        }
                        Else {
                            $FindingDetails += "No KSK data returned [finding]" | Out-String
                        }

                        If ($ZSK) {
                            ForEach ($Item in $ZSK) {
                                $FindingDetails += "ZSK_KeyId:`t`t`t`t$($Item.KeyId)" | Out-String
                                $ZSKDNSKEYValidity = Format-TimeSpanToHours -Span ($Item).DnsKeySignatureValidityPeriod
                                If ($ZSKDNSKEYValidity -is [Int]) {
                                    If ($ZSKDNSKEYValidity -ge 48 -and $ZSKDNSKEYValidity -le 168) {
                                        $FindingDetails += "ZSK_DNSKEY_Period:`t`t$($ZSKDNSKEYValidity) hours" | Out-String
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "ZSK_DNSKEY_Period:`t`t$($ZSKDNSKEYValidity) hours [expected between 48 and 168]" | Out-String
                                    }
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "ZSK_DNSKEY_Period:`t`t$($ZSKDNSKEYValidity) [finding]" | Out-String
                                }
                            }
                        }
                        Else {
                            $FindingDetails += "No ZSK data returned [finding]" | Out-String
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "IsSigned:`t`t`t`t`t$($false) [finding]" | Out-String
                    }

                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259346 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259346
        STIG ID    : WDNS-22-000015
        Rule ID    : SV-259346r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000084
        Rule Title : NSEC3 must be used for all internal DNS zones.
        DiscussMD5 : A172EAEECE86E44BA0374A5142C5781E
        CheckMD5   : 32BEC416A871670323D24B167C8529D8
        FixMD5     : 01F8019C747593E799AB2B4B4192A431
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsReverseLookupZone:`t$($Zone.IsReverseLookupZone)" | Out-String
                    If ($Zone.IsSigned) {
                        $FindingDetails += "IsSigned:`t`t`t`t$($Zone.IsSigned)" | Out-String
                        $NSEC3RR = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType NSec3
                        $FindingDetails += "NSEC3 RRs:" | Out-String
                        $FindingDetails += "---------------------------" | Out-String
                        If (($NSEC3RR | Measure-Object).Count -ge 1) {
                            ForEach ($Item in ($NSEC3RR | Select-Object -First 2)) {
                                $FindingDetails += "HostName:`t$($Item.HostName)" | Out-String
                                $FindingDetails += "RecordType:`t$($Item.RecordType)" | Out-String
                                $FindingDetails += "RecordData:`t[$($Item.RecordData.HashAlgorithm)][$($Item.RecordData.OptOut)][$($Item.RecordData.Iterations)][$($Item.RecordData.Salt)]" | Out-String
                            }
                            If (($NSEC3RR | Measure-Object).Count -gt 2) {
                                $FindingDetails += "...and $(($NSEC3RR | Measure-Object).Count - 2) more" | Out-String
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "No NSEC3 RRs returned [finding]" | Out-String
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "IsSigned:`t`t`t`t$($false) [finding]" | Out-String
                    }

                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259347 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259347
        STIG ID    : WDNS-22-000016
        Rule ID    : SV-259347r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000085
        Rule Title : The Windows DNS Server's zone files must have NS records that point to active name servers authoritative for the domain specified in that record.
        DiscussMD5 : 3819370C05A901B0EE6C9457EADFAB3E
        CheckMD5   : C91DED47462CE8C852E3339AE00D05C6
        FixMD5     : 3F635673540E7BC82D5571542E2B9DFE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "Not_Applicable"
        $FindingDetails += "Server is caching only so this requirement is NA." | Out-String
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

Function Get-V259348 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259348
        STIG ID    : WDNS-22-000017
        Rule ID    : SV-259348r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000087
        Rule Title : All authoritative name servers for a zone must be located on different network segments.
        DiscussMD5 : 77FD353CF1BDB34B24B98A5AC103E63C
        CheckMD5   : 25A39C90926B00EC8634FC50912AA2A5
        FixMD5     : 48D73A08284DF58415D45E357479B30C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {($_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated)))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $AllDCs = $true
                ForEach ($Zone in $Zones) {
                    $NameServers = ((Get-DnsServerResourceRecord -ZoneName $Zone.ZoneName -RRType Ns).RecordData.NameServer | Select-Object -Unique)
                    ForEach ($NameServer in $NameServers) {
                        Try {
                            $null = Get-ADDomainController -Identity $($NameServer -replace "\.$") -ErrorAction Stop
                        }
                        Catch {
                            $AllDCs = $false
                            Break
                        }
                    }

                    If ($AllDCs = $false) {
                        Break
                    }
                }
                If ($AllDCs) {
                    $Status = "Not_Applicable"
                    $FindingDetails += "All Zones hosted on this server are Active Directory-integrated and all name servers for the hosted zones are domain controllers so this requirement is NA." | Out-String
                }
            }
        }
        Else {
            $FindingDetails += "No zones are hosted on this server." | Out-String
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

Function Get-V259349 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259349
        STIG ID    : WDNS-22-000018
        Rule ID    : SV-259349r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000088
        Rule Title : All authoritative name servers for a zone must have the same version of zone information.
        DiscussMD5 : 6731F9576233C1AC2549C1A2E25BA489
        CheckMD5   : 40C886093B3CE9F51EA01D37C44AD893
        FixMD5     : 70B299EFB154CB4985DD4049DB8D01AC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259350 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259350
        STIG ID    : WDNS-22-000019
        Rule ID    : SV-259350r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000089
        Rule Title : The Windows DNS Server must be configured to enable DNSSEC Resource Records (RRs).
        DiscussMD5 : 1B27D6D44737814CA56ECF23513F3C22
        CheckMD5   : 4F9325304E128A680FFA0130DC94F9FF
        FixMD5     : 5F6EBC2D429341D2939A806500AD2B4C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsReverseLookupZone:`t$($Zone.IsReverseLookupZone)" | Out-String
                    If ($Zone.IsSigned) {
                        $FindingDetails += "IsSigned:`t`t`t`t$($Zone.IsSigned)" | Out-String
                        $RRSIGRR = (Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType RRSig | Measure-Object).Count
                        $DNSKEYRR = (Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType DnsKey | Measure-Object).Count
                        $NSEC3RR = (Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType NSec3 | Measure-Object).Count
                        If ($RRSIGRR -ge 1) {
                            $FindingDetails += "RRSIG_RR_Count:`t`t$($RRSIGRR)" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "RRSIG_RR_Count:`t`t0 [finding]" | Out-String
                        }
                        If ($DNSKEYRR -ge 1) {
                            $FindingDetails += "DNSKEY_RR_Count:`t`t$($DNSKEYRR)" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "DNSKEY_RR_Count:`t`t0 [finding]" | Out-String
                        }
                        If ($NSEC3RR -ge 1) {
                            $FindingDetails += "NSEC3_RR_Count:`t`t$($NSEC3RR)" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "NSEC3_RR_Count:`t`t0 [finding]" | Out-String
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "IsSigned:`t`t`t`t$($false) [finding]" | Out-String
                    }

                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259351 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259351
        STIG ID    : WDNS-22-000020
        Rule ID    : SV-259351r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000090
        Rule Title : The digital signature algorithm used for DNSSEC-enabled zones must be FIPS-compatible.
        DiscussMD5 : 4EBE795128D71D3CEC94C5CBDEB2AD16
        CheckMD5   : 3DA25CE82A692D5C4B6003E14439A68A
        FixMD5     : 4B29873233E72382C6D6A40434E8D873
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsReverseLookupZone:`t$($Zone.IsReverseLookupZone)" | Out-String
                    If ($Zone.IsSigned) {
                        $FindingDetails += "IsSigned:`t`t`t`t$($Zone.IsSigned)" | Out-String
                        $DNSKEYRR = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType DnsKey
                        $FindingDetails += "DNSKEY RRs:" | Out-String
                        $FindingDetails += "---------------------------" | Out-String
                        If (($DNSKEYRR | Measure-Object).Count -ge 1) {
                            ForEach ($Item in $DNSKEYRR) {
                                $FindingDetails += "HostName:`t$($Item.HostName)" | Out-String
                                $FindingDetails += "RecordType:`t$($Item.RecordType)" | Out-String
                                $RecordData = ""
                                If ($Item.RecordData.SecureEntryPoint) {
                                    $RecordData = "$($RecordData)[SEP]"
                                }
                                If ($Item.RecordData.ZoneKey) {
                                    $RecordData = "$($RecordData)[ZoneKey]"
                                }
                                If ($Item.RecordData.CryptoAlgorithm) {
                                    $RecordData = "$($RecordData)[$($Item.RecordData.CryptoAlgorithm)]"
                                }
                                If ($Item.RecordData.KeyTag) {
                                    $RecordData = "$($RecordData)[$($Item.RecordData.KeyTag)]"
                                }
                                If ($Item.RecordData.CryptoAlgorithm -notmatch "^RsaSha\d") {
                                    $Compliant = $false
                                    $RecordData = "$($RecordData) [finding]"
                                }
                                $FindingDetails += "RecordData:`t$($RecordData)" | Out-String
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "No NSEC3 RRs returned [finding]" | Out-String
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "IsSigned:`t`t`t`t$($false) [expected True]" | Out-String
                    }

                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259352 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259352
        STIG ID    : WDNS-22-000021
        Rule ID    : SV-259352r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000091
        Rule Title : For zones split between the external and internal sides of a network, the resource records (RRs) for the external hosts must be separate from the RRs for the internal hosts.
        DiscussMD5 : 769220826ADA854CC893D341DC64CDA0
        CheckMD5   : EBF0EBE3FEAE5149D01C89A9261A76A8
        FixMD5     : 4E88DD0A3BD2E46146F0A6B840850716
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259354 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259354
        STIG ID    : WDNS-22-000024
        Rule ID    : SV-259354r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000095
        Rule Title : Primary authoritative name servers must be configured to only receive zone transfer requests from specified secondary name servers.
        DiscussMD5 : B16A63B79A8F0E87DEB21AA801FB6FFD
        CheckMD5   : A38A7D20ACBBA992058058C543313731
        FixMD5     : D4906C6804974292F103C79F37BB6106
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259355 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259355
        STIG ID    : WDNS-22-000025
        Rule ID    : SV-259355r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000099
        Rule Title : The Windows DNS Servers zone database files must not be accessible for edit/write by users and/or processes other than the Windows DNS Server service account and/or the DNS database administrator.
        DiscussMD5 : 1AE112E6FD42E8C4FBC6F912672580C2
        CheckMD5   : 56F1A251764E794EA583EC6CDD32FE90
        FixMD5     : 7E9A0CA725657E4C8DCA5DE8790331BD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259356 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259356
        STIG ID    : WDNS-22-000026
        Rule ID    : SV-259356r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000101
        Rule Title : The Windows DNS Server must implement internal/external role separation.
        DiscussMD5 : 38E795B46447B7D2621F98D894DD2567
        CheckMD5   : A23F82C24FD5F45E7BFC69F83D78984F
        FixMD5     : D7C1E200BE69F8783EF4522FD86F1B2E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259357 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259357
        STIG ID    : WDNS-22-000027
        Rule ID    : SV-259357r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000102
        Rule Title : The Windows DNS Server authoritative for local zones must only point root hints to the DNS servers that host the internal root domain.
        DiscussMD5 : 3CAAB581C7BA2A9B3CF6BA65E0A7940C
        CheckMD5   : 37A167A2BBDF21B45AFED7FDE295F77D
        FixMD5     : 2D61AAA1F2A850F09533C9B63977934D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    Else {
        $RootHints = Get-DnsServerRootHint -ComputerName $env:COMPUTERNAME
        If (($RootHints | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No root hints are configured." | Out-String
        }
        Else {
            $FindingDetails += "Configured root hints:" | Out-String
            $FindingDetails += "----------------------" | Out-String
            ForEach ($Item in $RootHints) {
                $FindingDetails += "NameServer:`t$($Item.NameServer.RecordData.NameServer)" | Out-String
                $FindingDetails += "IPv4Address:`t$($Item.IPAddress.RecordData.IPv4Address.IPAddressToString -join ', ')" | Out-String
                $FindingDetails += "IPv6Address:`t$($Item.IPAddress.RecordData.IPv6Address.IPAddressToString -join ', ')" | Out-String
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

Function Get-V259358 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259358
        STIG ID    : WDNS-22-000029
        Rule ID    : SV-259358r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000113
        Rule Title : The Windows DNS Servers zone files must not include resource records that resolve to a fully qualified domain name residing in another zone.
        DiscussMD5 : E09526DA384C9B9B07F5D8EF094FC784
        CheckMD5   : 80369CCF919305DA093DFF3BA2F9E80A
        FixMD5     : 53417881FC59B0E7FF0E34148C771AD2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259359 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259359
        STIG ID    : WDNS-22-000030
        Rule ID    : SV-259359r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000114
        Rule Title : The Windows DNS Server's zone files must not include CNAME records pointing to a zone with lesser security for more than six months.
        DiscussMD5 : 008E801A112F6598FC9E23C274784E02
        CheckMD5   : 4389570C72C6DB494E50ABD8530E8642
        FixMD5     : 4801885ACEA0AD76E494E8D926E5F010
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259360 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259360
        STIG ID    : WDNS-22-000031
        Rule ID    : SV-259360r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000500
        Rule Title : Nonroutable IPv6 link-local scope addresses must not be configured in any zone.
        DiscussMD5 : F0C36BF45190E1DF6390A584293B25DB
        CheckMD5   : C7AF6B44EDA34D32DF24D7F848EF7969
        FixMD5     : C7A0515FCA84A61B12CF38C77084BEEA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            ForEach ($Zone in $Zones) {
                $IPv6LinkLocal = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName | Where-Object {$_.RecordData.IPv6Address.IPAddressToString -match "(^FE8|^FE9|^FEA|^FEB)"}
                If (($IPv6LinkLocal | Measure-Object).Count -ne 0) {
                    $Compliant = $false
                    $FindingDetails += "Zone: $($Zone.ZoneName)" | Out-String
                    $FindingDetails += "-----------------------" | Out-String
                    ForEach ($Item in $IPv6LinkLocal) {
                        $FindingDetails += "HostName:`t$($IPv6LinkLocal.HostName)" | Out-String
                        $FindingDetails += "IPv6Address:`t$($IPv6LinkLocal.RecordData.IPv6Address.IPAddressToString)" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }
            }

            If ($Compliant -eq $true) {
                $Status = "NotAFinding"
                $FindingDetails += "No Forward Lookup Zones contain IPv6 link-local IP addresses." | Out-String
            }
            Else {
                $Status = "Open"
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259361 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259361
        STIG ID    : WDNS-22-000032
        Rule ID    : SV-259361r1018796_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000500
        Rule Title : AAAA addresses must not be configured in a zone for hosts that are not dual stack.
        DiscussMD5 : 4558A05C1CC8D7845B232169C832CCB1
        CheckMD5   : 2A763B5D3B54A5232FA87940F26065C7
        FixMD5     : A821C1F2205DDC9FD319DADAF8333CDC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259363 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259363
        STIG ID    : WDNS-22-000035
        Rule ID    : SV-259363r960999_rule
        CCI ID     : CCI-000778
        Rule Name  : SRG-APP-000158-DNS-000015
        Rule Title : The Windows DNS Server must uniquely identify the other DNS server before responding to a server-to-server transaction.
        DiscussMD5 : EF6C47E80F06F792D7756F78260B38B8
        CheckMD5   : 9E716A9871A85BBD1688FDEF77A5909E
        FixMD5     : FC9DB2AB8629DD4046B1BCA944C46DA8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "Not_Applicable"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "Not_Applicable"
            $FindingDetails += "No zones are hosted on this server." | Out-String
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

Function Get-V259364 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259364
        STIG ID    : WDNS-22-000036
        Rule ID    : SV-259364r961503_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-APP-000394-DNS-000049
        Rule Title : The secondary Windows DNS name servers must cryptographically authenticate zone transfers from primary name servers.
        DiscussMD5 : E93324F03C354C44D53AE9649A8CA1F3
        CheckMD5   : 9C27F8C4D0E10E74F5E428F8F47E205B
        FixMD5     : D452054897D03F7296220D1DD42ECBBF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "NotAFinding"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259365 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259365
        STIG ID    : WDNS-22-000037
        Rule ID    : SV-259365r960735_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-DNS-000001
        Rule Title : The Windows DNS primary server must only send zone transfers to a specific list of secondary name servers.
        DiscussMD5 : 3CC46278ED69F4370642FA5E99BCB291
        CheckMD5   : 834D6F37A1B4143EAF051E10C785E847
        FixMD5     : 2AD32E3AFF0EB3F074B18AD469A47E2F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259366 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259366
        STIG ID    : WDNS-22-000038
        Rule ID    : SV-259366r987676_rule
        CCI ID     : CCI-000366, CCI-001901
        Rule Name  : SRG-APP-000347-DNS-000041
        Rule Title : The Windows DNS Server must provide its identity with returned DNS information by enabling DNSSEC and TSIG/SIG(0).
        DiscussMD5 : E86F8145966B529D0712119756814F96
        CheckMD5   : 6D3DD7FB523AEEFCBEC44AEAB19DA81E
        FixMD5     : 5104A4EF77B30AB4268437834F377F41
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259367 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259367
        STIG ID    : WDNS-22-000039
        Rule ID    : SV-259367r1081079_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DNS-000017
        Rule Title : The Windows DNS Server must be configured to enforce authorized access to the corresponding private key.
        DiscussMD5 : 3CDC1E5C7718CE6A388E42F10CA17044
        CheckMD5   : C330DB5E8CDDB338BD59B04836A27D1B
        FixMD5     : BEB6D55E85C864726BFE4BDF9ADEF097
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys"
    If (-Not(Test-Path $Path)) {
        $Status = "Not_Applicable"
        $FindingDetails += "'$Path' does not exist so this requirement is NA." | Out-String
    }
    Else {
        $Compliant = $true

        # --- Begin: Build expected ACL ---
        $ExpectedAcl = New-Object System.Collections.Generic.List[System.Object]

        # Add Administrators
        $NewObj = [PSCustomObject]@{
            Principal = "BUILTIN\Administrators"
            Access    = "FullControl"
        }
        $ExpectedAcl.Add($NewObj)

        # Add SYSTEM
        $NewObj = [PSCustomObject]@{
            Principal = "NT AUTHORITY\SYSTEM"
            Access    = "FullControl"
        }
        $ExpectedAcl.Add($NewObj)

        # Add Domain Admins for DCs
        If ((Get-DomainRoleStatus).RoleFriendlyName -in @("Backup Domain Controller", "Primary Domain Controller")) {
            $NewObj = [PSCustomObject]@{
                Principal = "$((Get-ADDomain -Server $env:COMPUTERNAME).NetBIOSName)\Domain Admins"
                Access    = "FullControl"
            }
            $ExpectedAcl.Add($NewObj)
        }
        # --- End: Build expected ACL ---

        # Check for ACL compliance with the above
        $NonCompliantAcls = New-Object System.Collections.Generic.List[System.Object]
        # Check folder permissions
        $CompliantAcl = Confirm-CompliantAcl -Type FileSystem -Path $Path -ExpectedAcl $ExpectedAcl -OthersMaxPermission "Read" -ErrorAction SilentlyContinue
        If ($CompliantAcl.Compliant -eq $false) {
            $Compliant = $false
            $NewObj = [PSCustomObject]@{
                Path       = $Path
                AclFinding = ($CompliantAcl | Where-Object Compliant -EQ $false)
            }
            $NonCompliantAcls.Add($NewObj)
        }

        # Check child item permissions
        ForEach ($Child in (Get-ChildItem -Path $Path -Recurse)) {
            $CompliantAcl = Confirm-CompliantAcl -Type FileSystem -Path $Child.FullName -ExpectedAcl $ExpectedAcl -OthersMaxPermission "Read" -ErrorAction SilentlyContinue
            If ($CompliantAcl.Compliant -eq $false) {
                $Compliant = $false
                $NewObj = [PSCustomObject]@{
                    Path       = $Child.FullName
                    AclFinding = ($CompliantAcl | Where-Object Compliant -EQ $false)
                }
                $NonCompliantAcls.Add($NewObj)
            }
        }

        If ($Compliant) {
            $Status = "NotAFinding"
            $FindingDetails += "Permissions on '$Path' and all subfolders and files are configured appropriately to the STIG." | Out-String
        }
        Else {
            # Leave as NR due to exception text in STIG
            $FindingDetails += "The following do not have appropriate permissions:" | Out-String
            $FindingDetails += "" | Out-String
            ForEach ($Item in $NonCompliantAcls) {
                $FindingDetails += $Item.Path | Out-String
                $FindingDetails += "" | Out-String
                ForEach ($Acl in $Item.AclFinding) {
                    $FindingDetails += "Principal:`t`t$($Acl.Principal)" | Out-String
                    $FindingDetails += "Access:`t`t$($Acl.Access -join ", ")" | Out-String
                    $FindingDetails += "Compliant:`t$($Acl.Compliant)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                $FindingDetails += "------------------------------------------------------------------------" | Out-String
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

Function Get-V259368 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259368
        STIG ID    : WDNS-22-000040
        Rule ID    : SV-259368r961041_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DNS-000018
        Rule Title : The Windows DNS Server key file must be owned by the account under which the Windows DNS Server service is run.
        DiscussMD5 : 183862472D4EF34646B4210EA28E6AA5
        CheckMD5   : 67F49C929AE5FB3BCCB8889A167D13E9
        FixMD5     : EBD3CEFBDAC7D15BE64B6BBBEE7A5903
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Path = "$env:ALLUSERSPROFILE\Microsoft\Crypto"
    If (-Not(Test-Path $Path)) {
        $Status = "Not_Applicable"
        $FindingDetails += "'$Path' does not exist so this requirement is NA." | Out-String
    }
    Else {
        $Compliant = $true

        $DNSService = Get-CimInstance Win32_Service | Where-Object Name -EQ DNS
        If ($DNSService.StartName -eq "LocalSystem") {
            $ServiceAccount = "NT AUTHORITY\SYSTEM"
        }
        Else {
            $ServiceAccount = $DNSService.StartName
        }

        $OwnerMismatch = New-Object System.Collections.Generic.List[System.Object]

        # Check folder owner
        $Owner = (Get-Acl $Path -ErrorAction SilentlyContinue).Owner
        If ($Owner -ne $ServiceAccount) {
            $Compliant = $false
            $NewObj = [PSCustomObject]@{
                Path  = $Path
                Owner = $Owner
            }
            $OwnerMismatch.Add($NewObj)
        }

        # Check child item owner
        ForEach ($Child in (Get-ChildItem -Path $Path -Recurse)) {
            $Owner = (Get-Acl $Path -ErrorAction SilentlyContinue).Owner
            If ($Owner -ne $ServiceAccount) {
                $Compliant = $false
                $NewObj = [PSCustomObject]@{
                    Path  = $Child.FullName
                    Owner = $Owner
                }
                $OwnerMismatch.Add($NewObj)
            }
        }

        $FindingDetails += "DNS Service Account:`t$($DNSService.StartName)" | Out-String
        $FindingDetails += "" | Out-String
        If ($Compliant) {
            $Status = "NotAFinding"
            $FindingDetails += "'$Path' and all subfolders and files are owned by the DNS service account." | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "The following are not owned by the DNS service account:" | Out-String
            $FindingDetails += "" | Out-String
            ForEach ($Item in $OwnerMismatch) {
                $FindingDetails += $Item.Path | Out-String
                $FindingDetails += "Owner:`t$($Item.Owner)" | Out-String
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

Function Get-V259369 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259369
        STIG ID    : WDNS-22-000041
        Rule ID    : SV-259369r1081081_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DNS-000019
        Rule Title : The Windows DNS Server permissions must be set so the key file can only be read or modified by the account that runs the name server software.
        DiscussMD5 : 183862472D4EF34646B4210EA28E6AA5
        CheckMD5   : 0247757C397EFFF541AC31491B9B62A3
        FixMD5     : 6783BEF2CF25653B9F05E61F703ABDBB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Path = "$env:ALLUSERSPROFILE\Microsoft\Crypto"
    If (-Not(Test-Path $Path)) {
        $Status = "Not_Applicable"
        $FindingDetails += "'$Path' does not exist so this requirement is NA." | Out-String
    }
    Else {
        $Compliant = $true

        # --- Begin: Build expected ACL ---
        $ExpectedAcl = New-Object System.Collections.Generic.List[System.Object]

        # Add Administrators
        $NewObj = [PSCustomObject]@{
            Principal = "BUILTIN\Administrators"
            Access    = "FullControl"
        }
        $ExpectedAcl.Add($NewObj)

        # Add SYSTEM
        $NewObj = [PSCustomObject]@{
            Principal = "NT AUTHORITY\SYSTEM"
            Access    = "FullControl"
        }
        $ExpectedAcl.Add($NewObj)

        # Add Domain Admins for DCs
        If ((Get-DomainRoleStatus).RoleFriendlyName -in @("Backup Domain Controller", "Primary Domain Controller")) {
            $NewObj = [PSCustomObject]@{
                Principal = "$((Get-ADDomain -Server $env:COMPUTERNAME).NetBIOSName)\Domain Admins"
                Access    = "FullControl"
            }
            $ExpectedAcl.Add($NewObj)
        }
        # --- End: Build expected ACL ---

        # Check for ACL compliance with the above
        $NonCompliantAcls = New-Object System.Collections.Generic.List[System.Object]
        # Check folder permissions
        $CompliantAcl = Confirm-CompliantAcl -Type FileSystem -Path $Path -ExpectedAcl $ExpectedAcl -OthersMaxPermission "Read" -ErrorAction SilentlyContinue
        If ($CompliantAcl.Compliant -eq $false) {
            $Compliant = $false
            $NewObj = [PSCustomObject]@{
                Path       = $Path
                AclFinding = ($CompliantAcl | Where-Object Compliant -EQ $false)
            }
            $NonCompliantAcls.Add($NewObj)
        }

        # Check child item permissions
        ForEach ($Child in (Get-ChildItem -Path $Path -Recurse)) {
            $CompliantAcl = Confirm-CompliantAcl -Type FileSystem -Path $Child.FullName -ExpectedAcl $ExpectedAcl -OthersMaxPermission "Read" -ErrorAction SilentlyContinue
            If ($CompliantAcl.Compliant -eq $false) {
                $Compliant = $false
                $NewObj = [PSCustomObject]@{
                    Path       = $Child.FullName
                    AclFinding = ($CompliantAcl | Where-Object Compliant -EQ $false)
                }
                $NonCompliantAcls.Add($NewObj)
            }
        }

        If ($Compliant) {
            $Status = "NotAFinding"
            $FindingDetails += "Permissions on '$Path' and all subfolders and files are configured appropriately to the STIG." | Out-String
        }
        Else {
            # Leave as NR due to exception text in STIG
            $FindingDetails += "The following do not have appropriate permissions:" | Out-String
            $FindingDetails += "" | Out-String
            ForEach ($Item in $NonCompliantAcls) {
                $FindingDetails += $Item.Path | Out-String
                $FindingDetails += "" | Out-String
                ForEach ($Acl in $Item.AclFinding) {
                    $FindingDetails += "Principal:`t`t$($Acl.Principal)" | Out-String
                    $FindingDetails += "Access:`t`t$($Acl.Access -join ", ")" | Out-String
                    $FindingDetails += "Compliant:`t$($Acl.Compliant)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                $FindingDetails += "------------------------------------------------------------------------" | Out-String
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

Function Get-V259370 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259370
        STIG ID    : WDNS-22-000042
        Rule ID    : SV-259370r961041_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DNS-000094
        Rule Title : The private key corresponding to the zone signing key (ZSK) must only be stored on the name server that does support dynamic updates.
        DiscussMD5 : AC25F5BCF596E6A1A23079DA8829C451
        CheckMD5   : 48C1ECC8BFA01D83DA2A0A18E955B296
        FixMD5     : 8E7DD9D420D6D89268DB046950E295CB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "Not_Applicable"
        $FindingDetails += "Server is caching only so this requirement is NA." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259372 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259372
        STIG ID    : WDNS-22-000044
        Rule ID    : SV-259372r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000077
        Rule Title : The salt value for zones signed using NSEC3 resource records (RRs) must be changed every time the zone is completely re-signed.
        DiscussMD5 : D2521B65236BD3C7E0B4D5482647AC7A
        CheckMD5   : 51400A2DDA35CC4339A9FC07CB7F2EFC
        FixMD5     : 6BEDE12DF393250DC67DEE8CCCDE7A98
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t`t$($Zone.ZoneName)" | Out-String
                    $NSEC3Param = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType RRSig | Where-Object {$_.RecordData.TypeCovered -eq "NSEC3PARAM"}
                    $DNSKEY = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType RRSig | Where-Object {$_.RecordData.TypeCovered -eq "DNSKEY" -and $_.RecordData.KeyTag -eq $NSEC3Param.RecordData.KeyTag}
                    If ($NSEC3Param.RecordData.SignatureInception -and $DNSKEY.RecordData.SignatureInception) {
                        $FindingDetails += "DNSKEY_Inception:`t`t`t$((Get-Date $DNSKEY.RecordData.SignatureInception).ToString())" | Out-String
                        If ($NSEC3Param.RecordData.SignatureInception -ne $DNSKEY.RecordData.SignatureInception) {
                            $Compliant = $false
                            $FindingDetails += "NSEC3PARAM_Inception:`t$((Get-Date $NSEC3Param.RecordData.SignatureInception).ToString()) [finding]" | Out-String
                        }
                        Else {
                            $FindingDetails += "NSEC3PARAM_Inception:`t$((Get-Date $NSEC3Param.RecordData.SignatureInception).ToString())" | Out-String
                        }
                    }
                    Else {
                        If ($DNSKEY.RecordData.SignatureInception) {
                            $FindingDetails += "DNSKEY_Inception:`t`t`t$((Get-Date $DNSKEY.RecordData.SignatureInception).ToString())" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "DNSKEY_Inception:`t`t`tNo inception date returned [finding]" | Out-String
                        }
                        If ($NSEC3Param.RecordData.SignatureInception) {
                            $FindingDetails += "NSEC3PARAM_Inception:`t$((Get-Date $NSEC3Param.RecordData.SignatureInception).ToString())" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "NSEC3PARAM_Inception:`tNo inception date returned [finding]" | Out-String
                        }

                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259373 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259373
        STIG ID    : WDNS-22-000045
        Rule ID    : SV-259373r961101_rule
        CCI ID     : CCI-001178
        Rule Name  : SRG-APP-000213-DNS-000024
        Rule Title : The Windows DNS Server must include data origin with authoritative data the system returns in response to external name/address resolution queries.
        DiscussMD5 : 4F35B222FAAD626ABFF12EAF4DAD9737
        CheckMD5   : A5FC6D89E677ED0D1A770D100F63CB4F
        FixMD5     : D452054897D03F7296220D1DD42ECBBF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259374 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259374
        STIG ID    : WDNS-22-000046
        Rule ID    : SV-259374r1081084_rule
        CCI ID     : CCI-000366, CCI-002463
        Rule Name  : SRG-APP-000420-DNS-000053
        Rule Title : The Windows DNS Server's IP address must be statically defined and configured locally on the server.
        DiscussMD5 : 26D0CF861FA5E059ACC362D8951AF155
        CheckMD5   : 0F3E13CF3EF96C1E7C2CC7608F966461
        FixMD5     : 1EEAA1A1F60C38A6973B22D208AED5F2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $Adapters = Get-NetAdapter | Where-Object Status -EQ "Up"
    ForEach ($Adapter in $Adapters) {
        $AdapterCfg = Get-NetIPConfiguration -InterfaceIndex $Adapter.ifIndex
        $FindingDetails += "InterfaceAlias:`t`t`t$($AdapterCfg.InterfaceAlias)" | Out-String
        $FindingDetails += "InterfaceIndex:`t`t`t$($AdapterCfg.InterfaceIndex)" | Out-String
        $FindingDetails += "InterfaceDescription:`t$($AdapterCfg.InterfaceDescription)" | Out-String
        # Check IPv4 Address
        If ($AdapterCfg.IPv4Address.IPAddress) {
            $FindingDetails += "IPv4Address:`t`t`t$($AdapterCfg.IPv4Address.IPAddress)" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "IPv4Address:`t`t`tNot Configured [finding]" | Out-String
        }
        # Check Subnet Mask
        If ($AdapterCfg.IPv4Address.PrefixLength) {
            $FindingDetails += "SubnetMask:`t`t`t$((Convert-SubnetMask -CIDR $Adaptercfg.IPv4Address.PrefixLength).Mask)" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "SubnetMask:`t`t`tNot Configured [finding]" | Out-String
        }
        # Check Default Gateway
        If ($AdapterCfg.IPv4DefaultGateway.NextHop) {
            $FindingDetails += "DefaultGateway:`t`t$($AdapterCfg.IPv4DefaultGateway.NextHop)" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "DefaultGateway:`t`tNot Configured [finding]" | Out-String
        }
        # Check SuffixOrigin
        If ($AdapterCfg.IPv4Address.SuffixOrigin -eq "Manual") {
            $FindingDetails += "SuffixOrigin:`t`t`t$($AdapterCfg.IPv4Address.SuffixOrigin)" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "SuffixOrigin:`t`t`t$($AdapterCfg.IPv4Address.SuffixOrigin) [finding]" | Out-String
        }
        $FindingDetails += "" | Out-String
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

Function Get-V259375 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259375
        STIG ID    : WDNS-22-000047
        Rule ID    : SV-259375r987695_rule
        CCI ID     : CCI-000366, CCI-002463
        Rule Name  : SRG-APP-000420-DNS-000053
        Rule Title : The Windows DNS Server must return data information in response to internal name/address resolution queries.
        DiscussMD5 : 7042364E22BDC1F87AD6C59A5651E286
        CheckMD5   : D767418BD5ABC6E6D5B4D8AED9175F2C
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259376 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259376
        STIG ID    : WDNS-22-000048
        Rule ID    : SV-259376r987696_rule
        CCI ID     : CCI-000366, CCI-002464
        Rule Name  : SRG-APP-000421-DNS-000054
        Rule Title : The Windows DNS Server must use DNSSEC data within queries to confirm data origin to DNS resolvers.
        DiscussMD5 : CFF683AD19507D5A0A58B97669D0BCC4
        CheckMD5   : 6D3DD7FB523AEEFCBEC44AEAB19DA81E
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259377 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259377
        STIG ID    : WDNS-22-000049
        Rule ID    : SV-259377r961581_rule
        CCI ID     : CCI-002462
        Rule Name  : SRG-APP-000422-DNS-000055
        Rule Title : WINS lookups must be disabled on the Windows DNS Server.
        DiscussMD5 : 120800AB61B2F4B2603A7C612B7F6569
        CheckMD5   : 795A556FD8B9C2211DD9BD4AC90907DB
        FixMD5     : 18F6614D41836F2445EC7734F7E1535B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If ($Zones | Where-Object IsWinsEnabled -EQ $true) {
                $Compliant = $false
                $FindingDetails += "The following Forward Lookup Zones have 'Use WINS forward lookup' enabled:" | Out-String
                $FindingDetails += "---------------------------" | Out-String
                ForEach ($Zone in ($Zones | Where-Object IsWinsEnabled -EQ $true)) {
                    $FindingDetails += "ZoneName:`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsWinsEnabled:`t$($Zone.IsWinsEnabled)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $FindingDetails += "All Forward Lookup Zones have 'Use WINS forward lookup' disabled." | Out-String
            }

            If ($Compliant -eq $true) {
                $Status = "NotAFinding"
            }
            Else {
                $Status = "Open"
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259378 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259378
        STIG ID    : WDNS-22-000050
        Rule ID    : SV-259378r961581_rule
        CCI ID     : CCI-002462
        Rule Name  : SRG-APP-000422-DNS-000055
        Rule Title : The Windows DNS Server must use DNSSEC data within queries to confirm data integrity to DNS resolvers.
        DiscussMD5 : 44B559B68BC575AB04FF88ED30BD11EA
        CheckMD5   : 6D3DD7FB523AEEFCBEC44AEAB19DA81E
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259379 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259379
        STIG ID    : WDNS-22-000051
        Rule ID    : SV-259379r961104_rule
        CCI ID     : CCI-001179
        Rule Name  : SRG-APP-000214-DNS-000025
        Rule Title : The Windows DNS Server must be configured with the Delegation Signer (DS) Resource Records (RR) carrying the signature for the RR that contains the public key of the child zone.
        DiscussMD5 : CB314C4C1222F4F673F6AF8AB08157A9
        CheckMD5   : 6D3DD7FB523AEEFCBEC44AEAB19DA81E
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259380 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259380
        STIG ID    : WDNS-22-000052
        Rule ID    : SV-259380r961107_rule
        CCI ID     : CCI-001663
        Rule Name  : SRG-APP-000215-DNS-000003
        Rule Title : The Windows DNS Server must enforce approved authorizations between DNS servers using digital signatures in the Resource Record Set (RRSet).
        DiscussMD5 : AEBE00326D6663EB7FFF14826156C5BE
        CheckMD5   : 8AF339297F28E5E5C84DB132F7FF5327
        FixMD5     : 3751A00E40B159B30A99591D393A92BE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsReverseLookupZone:`t$($Zone.IsReverseLookupZone)" | Out-String
                    If ($Zone.IsSigned) {
                        $FindingDetails += "IsSigned:`t`t`t`t$($Zone.IsSigned)" | Out-String
                        $RRSIGRR = (Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType RRSig | Measure-Object).Count
                        $DNSKEYRR = (Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType DnsKey | Measure-Object).Count
                        $NSEC3RR = (Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType NSec3 | Measure-Object).Count
                        If ($RRSIGRR -ge 1) {
                            $FindingDetails += "RRSIG_RR_Count:`t`t$($RRSIGRR)" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "RRSIG_RR_Count:`t`t0 [finding]" | Out-String
                        }
                        If ($DNSKEYRR -ge 1) {
                            $FindingDetails += "DNSKEY_RR_Count:`t`t$($DNSKEYRR)" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "DNSKEY_RR_Count:`t`t0 [finding]" | Out-String
                        }
                        If ($NSEC3RR -ge 1) {
                            $FindingDetails += "NSEC3_RR_Count:`t`t$($NSEC3RR)" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "NSEC3_RR_Count:`t`t0 [finding]" | Out-String
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "IsSigned:`t`t`t`t$($false) [finding]" | Out-String
                    }

                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259381 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259381
        STIG ID    : WDNS-22-000053
        Rule ID    : SV-259381r961107_rule
        CCI ID     : CCI-001663
        Rule Name  : SRG-APP-000215-DNS-000003
        Rule Title : The Name Resolution Policy Table (NRPT) must be configured in Group Policy to enforce clients to request DNSSEC validation for a domain.
        DiscussMD5 : 8B11543B78284130BDEBB38BD8A0D330
        CheckMD5   : 9172569DAC396DBA8B9AEBAB9298FD90
        FixMD5     : 3527910245A79F13CD071F919A7BFCD5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones -and (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0)) {
            $Status = "Not_Applicable"
            $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
        }
        Else {
            Try {
                $ClientNrptPolicy = Get-DnsClientNrptPolicy
                If ($ClientNrptPolicy) {
                    $FindingDetails += "DnsSecValidationRequired:`t$($ClientNrptPolicy.DnsSecValidationRequired)" | Out-String
                    If ($ClientNrptPolicy.DnsSecValidationRequired -eq $true) {
                        $Status = "NotAFinding"
                    }
                    Else {
                        $Status = "Open"
                    }
                }
                Else {
                    $Status = "Open"
                    $FindingDetails += "Get-DnsClientNrptPolicy returned no results. [finding]" | Out-String
                }
            }
            Catch {
                $Status = "Open"
                $FindingDetails += "$($_.Exception.Message)" | Out-String
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

Function Get-V259382 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259382
        STIG ID    : WDNS-22-000054
        Rule ID    : SV-259382r961107_rule
        CCI ID     : CCI-001663
        Rule Name  : SRG-APP-000215-DNS-000026
        Rule Title : The Windows DNS Server must be configured to validate an authentication chain of parent and child domains via response data.
        DiscussMD5 : 24D5446E39E7901E33969DC2FE58F651
        CheckMD5   : 26E29ECE6FAD400FAAE3D253B6245C8D
        FixMD5     : D922584FE05DF23560220C2E8763AF07
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No zones are hosted on this server." | Out-String
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

Function Get-V259383 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259383
        STIG ID    : WDNS-22-000055
        Rule ID    : SV-259383r961107_rule
        CCI ID     : CCI-001663
        Rule Name  : SRG-APP-000215-DNS-000026
        Rule Title : Trust anchors must be exported from authoritative Windows DNS Servers and distributed to validating Windows DNS Servers.
        DiscussMD5 : 3BBD4EAC0969FA46662FF2BBB8D7269F
        CheckMD5   : 5F4E1169DDEF6C57BAB3EED041A679D9
        FixMD5     : 613AFF8CDEDB5C054C1B8C418913A0B5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No zones are hosted on this server." | Out-String
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

Function Get-V259384 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259384
        STIG ID    : WDNS-22-000056
        Rule ID    : SV-259384r961107_rule
        CCI ID     : CCI-001663
        Rule Name  : SRG-APP-000215-DNS-000026
        Rule Title : Automatic Update of Trust Anchors must be enabled on key rollover.
        DiscussMD5 : 01726050760D427C9FBC1B306AE9B4FD
        CheckMD5   : C90191583F1D44C2E7913ADDC5EDFAAF
        FixMD5     : 38301A03829DEC0C60F45F35DD2CF9C7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $FindingDetails += "ZoneName:`t`t`t`t$($Zone.ZoneName)" | Out-String
                    $FindingDetails += "ZoneType:`t`t`t`t$($Zone.ZoneType)" | Out-String
                    $FindingDetails += "IsDsIntegrated:`t`t`t$($Zone.IsDsIntegrated)" | Out-String
                    $FindingDetails += "IsReverseLookupZone:`t`t$($Zone.IsReverseLookupZone)" | Out-String
                    If ($Zone.IsSigned) {
                        $FindingDetails += "IsSigned:`t`t`t`t`t$($Zone.IsSigned)" | Out-String
                        $KSK = Get-DnsServerSigningKey -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName | Where-Object KeyType -EQ "KeySigningKey"
                        If ($KSK) {
                            ForEach ($Item in $KSK) {
                                $FindingDetails += "KSK_KeyId:`t`t`t`t$($Item.KeyId)" | Out-String
                                If ($Item.IsRolloverEnabled) {
                                    $FindingDetails += "IsRolloverEnabled:`t`t`t$($Item.IsRolloverEnabled)" | Out-String
                                }
                                Else {
                                    $FindingDetails += "IsRolloverEnabled:`t`t`t$($Item.IsRolloverEnabled) [finding]" | Out-String
                                }
                            }
                        }

                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "IsSigned:`t`t`t`t`t$($false) [finding]" | Out-String
                    }

                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259385 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259385
        STIG ID    : WDNS-22-000057
        Rule ID    : SV-259385r961584_rule
        CCI ID     : CCI-002465
        Rule Name  : SRG-APP-000423-DNS-000056
        Rule Title : The Windows DNS secondary servers must request data origin authentication verification from the primary server when requesting name/address resolution.
        DiscussMD5 : 4E106D990ED563515A9EFA511091F630
        CheckMD5   : 2E12A973628D070593E8833AA2412EF1
        FixMD5     : 4B29873233E72382C6D6A40434E8D873
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259386 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259386
        STIG ID    : WDNS-22-000058
        Rule ID    : SV-259386r961587_rule
        CCI ID     : CCI-002466
        Rule Name  : SRG-APP-000424-DNS-000057
        Rule Title : The Windows DNS secondary server must request data integrity verification from the primary server when requesting name/address resolution.
        DiscussMD5 : AFBE8DE8A4CCD76A58965C37EAC38F5B
        CheckMD5   : F336DA351D182293456726AFC7E8F22D
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259387 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259387
        STIG ID    : WDNS-22-000059
        Rule ID    : SV-259387r961590_rule
        CCI ID     : CCI-002467
        Rule Name  : SRG-APP-000425-DNS-000058
        Rule Title : The Windows DNS secondary server must validate data integrity verification on the name/address resolution responses received from primary name servers.
        DiscussMD5 : AFBE8DE8A4CCD76A58965C37EAC38F5B
        CheckMD5   : 6D3DD7FB523AEEFCBEC44AEAB19DA81E
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259388 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259388
        STIG ID    : WDNS-22-000060
        Rule ID    : SV-259388r961593_rule
        CCI ID     : CCI-002468
        Rule Name  : SRG-APP-000426-DNS-000059
        Rule Title : The Windows DNS secondary server must validate data origin verification authentication on the name/address resolution responses received from primary name servers.
        DiscussMD5 : 8A656EBF94DA35FE808E3D716E1E65BD
        CheckMD5   : F336DA351D182293456726AFC7E8F22D
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259389 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259389
        STIG ID    : WDNS-22-000061
        Rule ID    : SV-259389r1043178_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219-DNS-000028
        Rule Title : The Windows DNS Server must protect the authenticity of zone transfers via transaction signing.
        DiscussMD5 : EB765D42BF9DF24168488FA1A800D75D
        CheckMD5   : 85BCFDBE07E7B758E4206C61B52DD17D
        FixMD5     : 3E1504FCFA9AFCE092B181826ADF717D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259390 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259390
        STIG ID    : WDNS-22-000062
        Rule ID    : SV-259390r1043178_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219-DNS-000029
        Rule Title : The Windows DNS Server must protect the authenticity of dynamic updates via transaction signing.
        DiscussMD5 : 65C4B6FE25407EB05FE8DD09FF7F68BC
        CheckMD5   : F22044E5589B40C1C8603ADDFBEDA8C7
        FixMD5     : B65A9277084A949DBE70C6CA1A287533
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259391 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259391
        STIG ID    : WDNS-22-000063
        Rule ID    : SV-259391r1043178_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219-DNS-000030
        Rule Title : The Windows DNS Server must protect the authenticity of query responses via DNSSEC.
        DiscussMD5 : 012FF218364341406427E691D4E25641
        CheckMD5   : 8175AA97C513E7F0AD6A9CA4E74AC849
        FixMD5     : 9BC419BE3589F8ED12A93BEB17F89C83
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259392 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259392
        STIG ID    : WDNS-22-000064
        Rule ID    : SV-259392r961596_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-DNS-000060
        Rule Title : The Windows DNS Server must use an approved DOD PKI certificate authority.
        DiscussMD5 : AE1105BE02AA1ED57FDB403434C00E7C
        CheckMD5   : 7CA3C68FD1C449F7F9C2AE5C75B67B6F
        FixMD5     : C1E626CA9BFA0E89E0B8B51EE62D1547
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "Not_Applicable"
        $FindingDetails += "Server is caching only so this requirement is NA." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
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

Function Get-V259393 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259393
        STIG ID    : WDNS-22-000065
        Rule ID    : SV-259393r1028387_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DNS-000033
        Rule Title : The Windows DNS Server must protect secret/private cryptographic keys while at rest.
        DiscussMD5 : 942244D721F3C16FE11D5192ED0EDC98
        CheckMD5   : 48458C3AFC95CA0B3F6E4B33F1A9A227
        FixMD5     : 83BF58D462A9167297D7D79D7C9CA698
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
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

Function Get-V259394 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259394
        STIG ID    : WDNS-22-000066
        Rule ID    : SV-259394r961599_rule
        CCI ID     : CCI-002475
        Rule Name  : SRG-APP-000428-DNS-000061
        Rule Title : The Windows DNS Server must only contain zone records that have been validated annually.
        DiscussMD5 : F4F674C506E03B0C7A21589A44FD1B01
        CheckMD5   : 701D0470842D8C2073C025EF24ABEDE9
        FixMD5     : E8BE4342FC3065D22D370E6673D34954
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259395 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259395
        STIG ID    : WDNS-22-000067
        Rule ID    : SV-259395r961152_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-DNS-000035
        Rule Title : The Windows DNS Server must restrict individuals from using it for launching denial-of-service (DoS) attacks against other information systems.
        DiscussMD5 : F1ADACFFD29ED65CA9283B080140DD32
        CheckMD5   : 505463F3347E7504034EE8B7C2690E3E
        FixMD5     : 08778D930DA55461B388819F49B28434
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Build list of URAs
    $URAtoCheck = New-Object System.Collections.Generic.List[System.Object]
    $NewObj = [PSCustomObject]@{
        UserRight            = "SeRemoteInteractiveLogonRight"
        UserRightDisplayName = "Allow log on through Remote Desktop Services"
        ExpectedObjects      = @("BUILTIN\Administrators")
        EmptyAllowed         = $true
    }
    $URAtoCheck.Add($NewObj)
    $NewObj = [PSCustomObject]@{
        UserRight            = "SeDenyNetworkLogonRight"
        UserRightDisplayName = "Deny access to this computer from the network"
        ExpectedObjects      = @("BUILTIN\Guests")
        EmptyAllowed         = $false
    }
    $URAtoCheck.Add($NewObj)
    $NewObj = [PSCustomObject]@{
        UserRight            = "SeDenyInteractiveLogonRight"
        UserRightDisplayName = "Deny log on locally"
        ExpectedObjects      = @("BUILTIN\Guests")
        EmptyAllowed         = $false
    }
    $URAtoCheck.Add($NewObj)

    $SecPolIni = Get-IniContent $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_SecPol.ini
    ForEach ($Item in $URAtoCheck) {
        $ResolvedObjects = @()
        $FindingDetails += "$($Item.UserRightDisplayName):" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        If ($SecPolIni.'Privilege Rights'.$($Item.UserRight)) {
            $AssignedRights = ($SecPolIni.'Privilege Rights'.$($Item.UserRight)).Replace("*", "") -split ","
            ForEach ($Object in $AssignedRights) {
                If ($Object -match "S-1-") {
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($Object)
                    Try {
                        $ResolvedObjects += $objSID.Translate([System.Security.Principal.NTAccount]).Value
                    }
                    Catch {
                        $ResolvedObjects += "$Object [Failed to translate SID]"
                    }
                }
                Else {
                    $ResolvedObjects += $Object
                }
            }
            Switch ($Item.UserRight) {
                "SeRemoteInteractiveLogonRight" {
                    ForEach ($Obj in $ResolvedObjects) {
                        If ($Obj -notin $Item.ExpectedObjects) {
                            $Compliant = $false
                            $FindingDetails += "$($Obj) [finding]" | Out-String
                        }
                        Else {
                            $FindingDetails += $Obj | Out-String
                        }
                    }
                }
                DEFAULT {
                    ForEach ($Obj in $Item.ExpectedObjects) {
                        If ($Obj -match "\*") {
                            If (-Not($ResolvedObjects -like $Obj)) {
                                $Compliant = $false
                                $FindingDetails += "* $($Obj) [missing assignment - finding]" | Out-String
                            }
                        }
                        ElseIf ($Obj -notin $ResolvedObjects) {
                            $Compliant = $false
                            $FindingDetails += "* $($Obj) [missing assignment - finding]" | Out-String
                        }
                    }
                    ForEach ($Obj in $ResolvedObjects) {
                        $FindingDetails += $Obj | Out-String
                    }
                }
            }
        }
        Else {
            If ($Item.EmptyAllowed -ne $true) {
                $Compliant = $false
                $FindingDetails += "No objects assigned to this right [finding]" | Out-String
            }
            Else {
                $FindingDetails += "No objects assigned to this right" | Out-String
            }
        }
        $FindingDetails += "" | Out-String
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

Function Get-V259396 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259396
        STIG ID    : WDNS-22-000068
        Rule ID    : SV-259396r961155_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247-DNS-000036
        Rule Title : The Windows DNS Server must use DNS Notify to prevent denial of service (DoS) through increase in workload.
        DiscussMD5 : 843E7531EB536D6129BDFD68CF260A4B
        CheckMD5   : 46F6ABFE376DB60A64C6700DBBC66964
        FixMD5     : AB11B6B954F27581F526F76CF56B4F95
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259397 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259397
        STIG ID    : WDNS-22-000069
        Rule ID    : SV-259397r961632_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-DNS-000063
        Rule Title : The Windows DNS Server must protect the integrity of transmitted information.
        DiscussMD5 : F6A57759AF98E384F1EAD395880B1EC9
        CheckMD5   : 458A25F99A29C768FE6FB82348B59F08
        FixMD5     : 6A8618F76196ACEE67296DEF8345D6DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259398 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259398
        STIG ID    : WDNS-22-000070
        Rule ID    : SV-259398r961638_rule
        CCI ID     : CCI-002420
        Rule Name  : SRG-APP-000441-DNS-000066
        Rule Title : The Windows DNS Server must maintain the integrity of information during preparation for transmission.
        DiscussMD5 : 6C6BAEE23F695BD39DAE29616AF4FFD6
        CheckMD5   : 6D3DD7FB523AEEFCBEC44AEAB19DA81E
        FixMD5     : 578500BE011D19FF8344DF24C8502339
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259399 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259399
        STIG ID    : WDNS-22-000071
        Rule ID    : SV-259399r961641_rule
        CCI ID     : CCI-002422
        Rule Name  : SRG-APP-000442-DNS-000067
        Rule Title : The Windows DNS Server must maintain the integrity of information during reception.
        DiscussMD5 : 6C6BAEE23F695BD39DAE29616AF4FFD6
        CheckMD5   : F336DA351D182293456726AFC7E8F22D
        FixMD5     : 43665B0FAA2FFA65C57720D0DB12CCCA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259400 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259400
        STIG ID    : WDNS-22-000072
        Rule ID    : SV-259400r961857_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000514-DNS-000075
        Rule Title : The Windows DNS Server must implement NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.
        DiscussMD5 : B1EA7872669609819FF765BA45534547
        CheckMD5   : C48EC5D4060D5E248508929FB7EB3521
        FixMD5     : 51F86BE18471AEA79DF8D58E3BF9CC8A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259401 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259401
        STIG ID    : WDNS-22-000073
        Rule ID    : SV-259401r961158_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-DNS-000037
        Rule Title : The Windows DNS Server must be configured to only allow zone information that reflects the environment for which it is authoritative, including IP ranges and IP versions.
        DiscussMD5 : 5C5B97CAA9616712DA1B4EB489AC98F8
        CheckMD5   : CEE38102CD813FBFA2B4BBD3039315FD
        FixMD5     : FBA95E07CA5076EC3A477C5F4C6164A2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
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

Function Get-V259402 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259402
        STIG ID    : WDNS-22-000074
        Rule ID    : SV-259402r987708_rule
        CCI ID     : CCI-000366, CCI-002775
        Rule Name  : SRG-APP-000451-DNS-000069
        Rule Title : The Windows DNS Server must follow procedures to re-role a secondary name server as the primary name server if the primary name server permanently loses functionality.
        DiscussMD5 : 73671625DE9A7A2A88DD9840CC608EC3
        CheckMD5   : 9D1BF9B3C8E5F993304AD2DC232BEDE1
        FixMD5     : 3340559999B62D1526B0F2B4045870B9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "NotAFinding"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated." | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No zones are hosted on this server." | Out-String
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

Function Get-V259403 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259403
        STIG ID    : WDNS-22-000075
        Rule ID    : SV-259403r1001264_rule
        CCI ID     : CCI-002201
        Rule Name  : SRG-APP-000333-DNS-000104
        Rule Title : The DNS Name Server software must be configured to refuse queries for its version information.
        DiscussMD5 : E9F0AF731E45C55B7C4D09D3E6EF419D
        CheckMD5   : DD0F0DD794E44934E961AA4662189E0E
        FixMD5     : 1BF8FCC145D05748CC61885FD20677FA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $EnableVersionQuery = (Get-DnsServer -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).ServerSetting.EnableVersionQuery
    $FindingDetails += "EnableVersionQuery:`t$($EnableVersionQuery)" | Out-String
    If ($EnableVersionQuery -eq 0) {
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

Function Get-V259404 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259404
        STIG ID    : WDNS-22-000076
        Rule ID    : SV-259404r1001265_rule
        CCI ID     : CCI-002201
        Rule Name  : SRG-APP-000333-DNS-000107
        Rule Title : The HINFO, RP, TXT, and LOC RR types must not be used in the zone SOA.
        DiscussMD5 : A6F2DF8165E049D93EB8FED36C17E7C4
        CheckMD5   : 71FA685416698794237EBF2664BF3369
        FixMD5     : AC23FC724D93B8EC15B869EB0F933181
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -in @("Primary") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If (-Not($Zones)) {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup Zones exist on this server." | Out-String
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

Function Get-V259406 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259406
        STIG ID    : WDNS-22-000078
        Rule ID    : SV-259406r961734_rule
        CCI ID     : CCI-002699
        Rule Name  : SRG-APP-000473-DNS-000072
        Rule Title : The Windows DNS Server must verify the correct operation of security functions upon startup and/or restart, upon command by a user with privileged access, and/or every 30 days.
        DiscussMD5 : 82D87177F4859042AB812A21C79456C1
        CheckMD5   : 3DF209723529A3CD3F21AB0BE0A89085
        FixMD5     : B190E16D58A07C583EF7D1A6B3289511
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {(-Not($_.IsReverseLookupZone)) -and $_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All Forward Lookup Zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
            }
            Else {
                $Compliant = $true
                ForEach ($Zone in $Zones) {
                    $ZoneCompliant = $false
                    $FindingDetails += "ZoneName:`t$($Zone.ZoneName)" | Out-String
                    $A_Records = Get-DnsServerResourceRecord -ComputerName $env:COMPUTERNAME -ZoneName $Zone.ZoneName -RRType A | Where-Object HostName -NotMatch "(DnsZones)" | Select-Object -First 20
                    If ($A_Records | Where-Object HostName -notin @("@", "*")) {
                        ForEach ($Item in ($A_Records | Where-Object HostName -notin @("@", "*"))) {
                            Try {
                                $RRSIG = Resolve-DnsName -Name "$($Item.HostName).$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                                If ($RRSIG) {
                                    Break
                                }
                            }
                            Catch {
                                # Do Nothing
                            }
                        }
                    }
                    Else {
                        Try {
                            $RRSIG = Resolve-DnsName -Name "$($Zone.ZoneName)" -Server $env:COMPUTERNAME -DnssecOk -ErrorAction Stop | Where-Object QueryType -EQ "RRSIG" -ErrorAction Stop | Select-Object -First 1
                        }
                        Catch {
                            # Do Nothing
                        }
                    }

                    If ($RRSIG) {
                        $ZoneCompliant = $true
                        $FindingDetails += "Name:`t`t$($RRSIG.Name)" | Out-String
                        $FindingDetails += "QueryType:`t$($RRSIG.Type)" | Out-String
                        $FindingDetails += "TTL:`t`t`t$($RRSIG.TTL)" | Out-String
                        $FindingDetails += "Section:`t`t$($RRSIG.Section)" | Out-String
                        $FindingDetails += "TypeCovered:`t$($RRSIG.TypeCovered)" | Out-String
                        $FindingDetails += "Algorithm:`t$($RRSIG.Algorithm)" | Out-String
                        $FindingDetails += "LabelCount:`t$($RRSIG.LabelCount)" | Out-String
                        $FindingDetails += "OriginalTtl:`t$($RRSIG.OriginalTtl)" | Out-String
                        $FindingDetails += "Expiration:`t$($RRSIG.Expiration)" | Out-String
                        $FindingDetails += "Signed:`t`t$($RRSIG.Signed)" | Out-String
                        $FindingDetails += "Signer:`t`t$($RRSIG.Signer)" | Out-String
                        $FindingDetails += "Signature:`t{$(($RRSIG.Signature | Select-Object -First 4) -join ', ')...}" | Out-String
                    }

                    If (-Not($ZoneCompliant)) {
                        $Compliant = $false
                        $FindingDetails += "No RRSIG records returned [finding]" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "No Forward Lookup zones are hosted on this server." | Out-String
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

Function Get-V259408 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259408
        STIG ID    : WDNS-22-000080
        Rule ID    : SV-259408r961737_rule
        CCI ID     : CCI-002702
        Rule Name  : SRG-APP-000474-DNS-000073
        Rule Title : The Windows DNS Server must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.
        DiscussMD5 : 1DC048B62DCD28B8C30326516B909AF8
        CheckMD5   : AD1FF2433F71E428267CB1EF296BBE09
        FixMD5     : 0D145635871470D26553B70683788604
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
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

Function Get-V259409 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259409
        STIG ID    : WDNS-22-000081
        Rule ID    : SV-259409r961185_rule
        CCI ID     : CCI-001294
        Rule Name  : SRG-APP-000275-DNS-000040
        Rule Title : The Windows DNS Server must be configured to notify the information system security officer (ISSO), information system security manager (ISSM), or DNS administrator when functionality of DNSSEC/TSIG has been removed or broken.
        DiscussMD5 : 26C7EF652096627E2DA700B72E18AA12
        CheckMD5   : D8775150AFB9BF9FBB89968DC8A6EEEA
        FixMD5     : FFB06A3DA362B6D6BBFAB41B4CF9D6E9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
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

Function Get-V259410 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259410
        STIG ID    : WDNS-22-000090
        Rule ID    : SV-259410r1081086_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DNS-000076
        Rule Title : A unique Transaction Signature (TSIG) key must be generated for each pair of communicating hosts.
        DiscussMD5 : DEBAA8149E1EED939E287E970FD05B5B
        CheckMD5   : 47EFD1128134FCEF853A20BE23977AD6
        FixMD5     : 6AE71B5486415879338587F7FBDA9420
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DnsServerSetting = Get-DnsServerSetting -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue

    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    ElseIf (($DnsServerSetting).EnableDnsSec) {
        $Status = "Not_Applicable"
        $FindingDetails += "DNSSEC is used so this requirement is NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "ComputerName:`t$($DnsServerSetting.ComputerName)" | Out-String
        $FindingDetails += "EnableDnsSec:`t$($DnsServerSetting.EnableDnsSec)" | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
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

Function Get-V259412 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259412
        STIG ID    : WDNS-22-000094
        Rule ID    : SV-259412r961125_rule
        CCI ID     : CCI-001665
        Rule Name  : SRG-APP-000226-DNS-000032
        Rule Title : In the event of a system failure, the Windows DNS Server must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.
        DiscussMD5 : 7E9BE3C197A3D3F6B7C374A247174975
        CheckMD5   : FF588EC393F06DA9978864EF68AD7FE6
        FixMD5     : D1BD0ED7B6FA3876B8F77AEA457FBEFB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $AuditSubcat = "File System"
    $AuditIncSet = "Failure"
    $AuditPol = AuditPol /Get /Category:* /r | ConvertFrom-Csv | Where-Object {$_.Subcategory -eq $AuditSubcat}

    If ($AuditPol) {
        If ($AuditPol.'Inclusion Setting' -match $AuditIncSet) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }

        $FindingDetails += "$($AuditSubcat):`t$($AuditPol.'Inclusion Setting')" | Out-String
    }
    Else {
        $FindingDetails += "'$($AuditSubcat)' not found as an audit subcategory.  Please manually review." | Out-String
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

Function Get-V259413 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259413
        STIG ID    : WDNS-22-000102
        Rule ID    : SV-259413r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000105
        Rule Title : The DNS Name Server software must run with restricted privileges.
        DiscussMD5 : ECEC242D2A891EDB8ACD8DE981988075
        CheckMD5   : 3A6F3864B1868CDE8EFFB057AE22ECD1
        FixMD5     : 7AC6B1A8C9825ED4124128310E6D4EB8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Service = Get-CimInstance Win32_Service -Filter "Name='DNS'"

    $FindingDetails += "Service Name:`t$($Service.DisplayName)" | Out-String
    $FindingDetails += "Log on as:`t$($Service.StartName)" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V259414 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259414
        STIG ID    : WDNS-22-000107
        Rule ID    : SV-259414r1028388_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DNS-000112
        Rule Title : The private keys corresponding to both the zone signing key (ZSK) and the key signing key (KSK) must not be kept on the DNSSEC-aware primary authoritative name server when the name server does not support dynamic updates.
        DiscussMD5 : 2A8730A5306CE5AD33100FD2A4F615F5
        CheckMD5   : E12ADBA6971D47EB040976011AEC3015
        FixMD5     : B26E8E4AC446317AB6ABAE7E3ADE0D43
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -notin @("Unclassified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is not an unclassified system so this requirement is NA." | Out-String
    }
    ElseIf (Test-IsDNSCachingOnly) {
        $Status = "NotAFinding"
        $FindingDetails += "Server is caching only and thus hosts no DNS zones." | Out-String
    }
    Else {
        $Zones = Get-DnsServerZone -ComputerName $env:COMPUTERNAME | Where-Object {$_.ZoneType -notin @("Forwarder") -and $_.ZoneName -notin @("TrustAnchors") -and (-Not($_.IsAutoCreated))}
        If ($Zones) {
            If (($Zones | Where-Object {-Not($_.IsDsIntegrated)} | Measure-Object).Count -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All zones hosted on this server are Active Directory-integrated so this requirement is NA." | Out-String
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

Function Get-V259417 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259417
        STIG ID    : WDNS-22-000120
        Rule ID    : SV-259417r961155_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247-DNS-000036
        Rule Title : Windows DNS response rate limiting (RRL) must be enabled.
        DiscussMD5 : A856004154D5076F745D3EC0120B986D
        CheckMD5   : C59787A8FDC939130FC9ACDB7B11BE10
        FixMD5     : E9832FC8EFD1741AE4F1347A447FA9F9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RRLimiting = Get-DnsServerResponseRateLimiting -ComputerName $env:COMPUTERNAME
    $FindingDetails += "Mode:`t$($RRLimiting.Mode)" | Out-String

    If ($RRLimiting.Mode -eq "Enable") {
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

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBxpYj55gfwNTf
# 5hU/0bcZqbSSBG5CUaD2cxpdwAMzOaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCATw9TNG9iNKBNlvVtaog5AOGz9fpxv/gAVbjm1roMfBjANBgkqhkiG9w0BAQEF
# AASCAQCqwqqAp1AJBiciumoAJvegDHh2Z8LgiviwL2ZrAb5lqZZdXDxkmmpR1Nb6
# Yf8ERiVRbfGkpKaQRVw575ynjGaLBLL5BE531EBvExNSSLhdNCbh2qYNBJkViakj
# wOO9c6Q4SVdMVaeCs/4OsLjXLbzkly0O5Zdiqa/JFLUV+LQNryTl1L3XLP530CU+
# wTA+BsF4kDCy1skx7meLGuKVEEvws1TnCiV6dao5brZsydyBfeeajTj20ViXMzKp
# TxCjP1tVnCjrkMQKk0I+k0ghQx5F8Da0sEcwtUYiOFm0BbORBxZlv0HgX7ApJmS6
# TqBAZuRefzbm3L8ArRLC1TYpcwwJoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAwMTE2NTg0OVowLwYJKoZIhvcNAQkEMSIEILlyt64p1tsFb3CaiB4P3YbLOOSZ
# tH1BHZKV/1SgCpUCMA0GCSqGSIb3DQEBAQUABIICAImni2U5tBegaWHhvpgtR4Fo
# Q7HtmBm7k3sB+RKyjAckbP1MzJilKtDau2ZENHp7dUZHkRc0aS+cRLTlNjEWFS2O
# fUyULxWtuWFmSaHI5ps5pR8RvO3fRIbYPA/vEc0EMe0q+3DgD72gM6Ii+gLV7YGa
# OI+UxUWxo/OJzABIx4gUTJojPhL2J23BX4A/Rsn9LO0d3sfI15lN/ITcq177Q/a5
# m1ghq1DIjNDKqwFCsZEriUzi6KZfSrd1UUgoQh2VKF8mb2SwsbXy+heDp1aqalbj
# 8wcnrXmDOHgOIHb1ZtJ3m35izhvxTzjMDRLCPrkxkAQSGQ89opnRDCIjmpDHs6+Y
# Wiano/rFescW8e0ccA8SZzWeSaApSRRxsnulWekPBegAJzLj/faIBv1mmSJl0vho
# S+H+uWNiDko/FQOSejDk4HtiJZGBFxnw1FLENsZoQAt859F4znA8TLxp34RxbIZy
# osVEcL2NVzzJGRzIO+KxcDOTRKDK/DNoGVluUNEhYBTNgOfrA/Eq5MdrnQTK+H4V
# pRB/XgdxzjGEydCH8nFL8aV4f1chDupkpn5vjnaZhcfRoPdfGDE8T9ePJiR6A85D
# lhWJBISg3ledVwSsiy20l8Asc5L4Ij7idD+mfODTOlTehjPMpJFTSqr8eAp0DbEa
# K/XSYu7Hmm4VGlQ0jTZ2
# SIG # End signature block
