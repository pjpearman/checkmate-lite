##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS Switch L2S
# Version:  V3R1
# Class:    UNCLASSIFIED
# Updated:  10/7/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V220623 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220623
        STIG ID    : CISC-L2-000020
        Rule ID    : SV-220623r863275_rule
        CCI ID     : CCI-000778, CCI-001958
        Rule Name  : SRG-NET-000148-L2S-000015
        Rule Title : The Cisco switch must uniquely identify and authenticate all network-connected endpoint devices before establishing any connection.
        DiscussMD5 : F8510CA83F388038C74BF5CBCCB63E0C
        CheckMD5   : F5CCE008FAB15C9C85F0AD4C5B4FA5A8
        FixMD5     : 3A4F20AFCEF659CBF0DADBB0DDA4A25E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $InterfacesConfigured = @()
    $GlobalConfigs = $True
    $Exception = $False

    # Check for applicable interfaces
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        # Create list of any interfaces with 802.1x configurations
        IF ($InterfaceConfig -contains "switchport mode access") {
            $Exception = $True
            IF (($InterfaceConfig -contains "authentication port-control auto") -AND ($InterfaceConfig -contains "dot1x pae authenticator")) {
                $InterfacesConfigured += $Interface
            }
        }
    }

    IF ($InterfacesConfigured.count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces are configured with 802.1x authentication. Review the list below and verify that no host-facing interfaces on the switch are missing from the list. All host-facing interfaces must have 802.1x authentication configured:" | Out-String
        $FindingDetails += "---------------------------------------------------------" | Out-String
        ForEach ($Int in $InterfacesConfigured){
            $FindingDetails += $Int | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No interfaces are configured with 802.1x authentication. All host-facing interfaces must have 802.1x authentication configured." | Out-String
        $FindingDetails += "" | Out-String
    }

    # Locate 802.1x authentication groups
    IF ($ShowRunningConfig -like "aaa group server *") {
        $aaa = $ShowRunningConfig | Select-String -Pattern "^aaa group server"
        $serverType = ($aaa -split " ")[-2]
        $serverGroup = ($aaa -split " ")[-1]
        $servers = @()
        $startSTR = "^aaa group server .* $serverGroup"
        $endSTR = "^!"
        $running = $False

        # Isolate 802.1x authentication server groups
        ForEach ($line in $ShowRunningConfig) {
            IF ($line -match $startSTR){
                $running = $True
                $FindingDetails += "Review the configuration below and verify that 802.1x authentication is properly configured on this device." | Out-String
                $FindingDetails += "---------------------------------------------------------" | Out-String
                $FindingDetails += $line | Out-String
            }
            ELSEIF ($line -match $endSTR -and $running) {
                $running = $False
                $FindingDetails += "" | Out-String
            }
            ELSEIF ($running) {
                $FindingDetails += $line | Out-String
                IF ($line.StartsWith("server name")) {
                    $serverName = ($line -split " ")[2]
                    $servers += $serverName
                }
            }
        }

        # Iterate over 802.1x authentication server groups to extract configs
        IF ($servers.count -gt 0){
            ForEach ($server in $servers) {
                $running = $False
                ForEach ($line in $ShowRunningConfig) {
                    $startSTR = "$serverType server $server"
                    $endSTR = "^!"
                    IF ($line -match $startSTR){
                        $running = $True
                        $FindingDetails += $line | Out-String
                    }
                    ELSEIF ($line -match $endSTR -and $running) {
                        $running = $False
                        $FindingDetails += "" | Out-String
                    }
                    ELSEIF ($running) {
                        $FindingDetails += $line | Out-String
                    }
                }
            }
        }
        ELSE {
            $NonCompliant += "No servers configuration detected under 'aaa group server'." | Out-String
            $NonCompliant += "" | Out-String
            $GlobalConfigs = $False
        }

        # Flag missing global 802.1x authentication configurations
        IF (!($ShowRunningConfig -like "aaa authentication dot1x * $serverGroup")){
            $NonCompliant += "802.1x authentication group configuration 'aaa authentication dot1x * $serverGroup' is missing for group $serverGroup." | Out-String
            $NonCompliant += "" | Out-String
            $GlobalConfigs = $False
        }
        ELSE {
            $FindingDetails += $ShowRunningConfig -like "aaa authentication dot1x * $serverGroup" | Out-String
        }

        IF (!($ShowRunningConfig -like "dot1x system-auth-control")){
            $NonCompliant += "802.1x authentication configuration 'dot1x system-auth-control' is missing." | Out-String
            $NonCompliant += "" | Out-String
            $GlobalConfigs = $False
        }
        ELSE {
            $FindingDetails += $ShowRunningConfig -like "dot1x system-auth-control" | Out-String
        }

        # Get Radius servers configuration
        $RadiusServers = $ShowRunningConfig | Select-String -Pattern "^radius server"
        IF ($RadiusServers) {
            $RadiusServerConfig = @()
            ForEach ($RadiusServer in $RadiusServers) {
                $RadiusServerConfig += $RadiusServer
                $RadiusServerConfig += Get-Section $ShowRunningConfig $RadiusServer.ToString() | Out-String
            }
                $FindingDetails += "" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Below is the Radius servers configuration:" | Out-String
                $FindingDetails += "------------------------------------------" | Out-String
                $FindingDetails += ($RadiusServerConfig | Out-String).Trim()
                $FindingDetails += "" | Out-String
        }
        ELSE {
            $NonCompliant += "Radius servers configuration is missing." | Out-String
        }

        IF ($NonCompliant) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $NonCompliant | Out-String
        }
    }
    ELSE {
        $FindingDetails += "No global 'aaa group server' configurations detected." | Out-String
        $FindingDetails += "" | Out-String
        $GlobalConfigs = $False
    }

    IF (!$GlobalConfigs) {
        $Status = "Open"
    }
    ELSE {
        $Status = "Not_Reviewed"
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

Function Get-V220624 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220624
        STIG ID    : CISC-L2-000030
        Rule ID    : SV-220624r539671_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-NET-000168-L2S-000019
        Rule Title : The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
        DiscussMD5 : 3AE4D767685B7AF17D665812E8F2833C
        CheckMD5   : F5EFA2035BB5C143FB6D0AB7B62BCE25
        FixMD5     : 88D9C4A45B1C0D08181714C2C01D15F0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available. This check must be done manually." | Out-String
    $FindingDetails += "Review the switch configuration manually to verify that VTP is enabled using the 'show vtp status' command. If 'VTP Operating Mode :' is set to anything other than 'Off' then verify that a password has been configured using the 'show vtp password' command on the device being evaluated." | Out-String
    $FindingDetails += "If a password is not assigned but required, one must be applied via the 'vtp password xxxxxxxxx' command." | Out-String
    $FindingDetails += ""
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

Function Get-V220625 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220625
        STIG ID    : CISC-L2-000040
        Rule ID    : SV-220625r991847_rule
        CCI ID     : CCI-001095, CCI-004866
        Rule Name  : SRG-NET-000193-L2S-000020
        Rule Title : The Cisco switch must manage excess bandwidth to limit the effects of packet-flooding types of denial-of-service (DoS) attacks.
        DiscussMD5 : 8A6959F5099C051B40C1A47143841F29
        CheckMD5   : 87B32454DF37107DD71A7ED35E6B5613
        FixMD5     : 09648DA25B0BFEF1DDA232773D04B24A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF ($ShowRunningConfig -contains "mls qos") {
        $FindingDetails += "Quality of Service (QoS) is enabled for management of excess bandwidth to limit the effects of packet-flooding types of denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify QoS has been enabled for management of excess bandwidth to limit the effects of packet-flooding types of denial-of-service (DoS) attacks." | Out-String
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

Function Get-V220629 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220629
        STIG ID    : CISC-L2-000090
        Rule ID    : SV-220629r856223_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000021
        Rule Title : The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches.
        DiscussMD5 : 124CEDD0825F9EB53FD1BAD11587A763
        CheckMD5   : 2BFB928840AC292F87F3B9665DE1936C
        FixMD5     : CFA2817C5768CA96D97F3F81DC7A17BB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $ConfiguredInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "spanning-tree guard root") {
            $ConfiguredInterfaces += $Interface
        }
    }

    IF ($ConfiguredInterfaces.count -gt 0) {
        $FindingDetails += "Root Guard enabled ('spanning-tree guard root') on the following interfaces. Review the interfaces below and verify that all switch ports connecting to access layer switches are included." | Out-String
        $FindingDetails += "-------------------- Interfaces --------------------" | Out-String
        ForEach ($int in $ConfiguredInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "Root Guard not enabled on any interfaces. Configure the switch to have Root Guard enabled ('spanning-tree guard root') on all ports connecting to access layer switches." | Out-String
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

Function Get-V220630 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220630
        STIG ID    : CISC-L2-000100
        Rule ID    : SV-220630r856224_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000022
        Rule Title : The Cisco switch must have Bridge Protocol Data Unit (BPDU) Guard enabled on all user-facing or untrusted access switch ports.
        DiscussMD5 : A2BDDD0621AD0F44AB64CAE0CE9213E7
        CheckMD5   : 66D0BC7EF09FB7A6742A5154DAEEBC0D
        FixMD5     : 45B0C7817CCFD00A5515E5CD40B89789
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $ConfiguredInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "spanning-tree bpduguard enable") {
            $ConfiguredInterfaces += $Interface
        }
    }

    IF ($ConfiguredInterfaces.count -gt 0) {
        $FindingDetails += "Bridge Protocol Data Unit (BPDU) Guard enabled ('spanning-tree guard root') on the following interfaces. Review the interfaces below and verify that all user-facing or untrusted access switch ports are included." | Out-String
        $FindingDetails += "-------------------- Interfaces --------------------" | Out-String
        ForEach ($int in $ConfiguredInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "Bridge Protocol Data Unit (BPDU) Guard not enabled on any interfaces. Configure the switch to have Bridge Protocol Data Unit (BPDU) Guard enabled ('spanning-tree bpduguard enable') on user-facing or untrusted access switch ports." | Out-String
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

Function Get-V220631 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220631
        STIG ID    : CISC-L2-000110
        Rule ID    : SV-220631r856225_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000023
        Rule Title : The Cisco switch must have Spanning Tree Protocol (STP) Loop Guard enabled.
        DiscussMD5 : 5F7E6F78500EBEC75807A7CEDD8C240C
        CheckMD5   : 1FA851858FFE7C4A7DF77097657DC7BB
        FixMD5     : 3EE4773F0F7238F3BFDF4857EC0D2289
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF ($ShowRunningConfig -contains "spanning-tree loopguard default") {
        $FindingDetails += "Spanning Tree Protocol (STP) Loop Guard is enabled." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Enable Spanning Tree Protocol (STP) Loop Guard via global 'spanning-tree loopguard default' configuration." | Out-String
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

Function Get-V220632 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220632
        STIG ID    : CISC-L2-000120
        Rule ID    : SV-220632r856226_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000024
        Rule Title : The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
        DiscussMD5 : F32B69482A84A19037E46DB6D49C0A46
        CheckMD5   : BA90B6897D05E3562F404AC62DAD74BF
        FixMD5     : 5F4476B456B7FDDB3C310D899C348993
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $ConfiguredInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "switchport block unicast") {
            $ConfiguredInterfaces += $Interface
        }
    }

    IF ($ConfiguredInterfaces.count -gt 0) {
        $FindingDetails += "Unknown Unicast Flood Blocking (UUFB) enabled ('switchport block unicast') on the following interfaces. Review the interfaces below and verify that all access switch ports are included." | Out-String
        $FindingDetails += "-------------------- Interfaces --------------------" | Out-String
        ForEach ($int in $ConfiguredInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "Unknown Unicast Flood Blocking (UUFB) not enabled on any interfaces. Configure the switch to have Unknown Unicast Flood Blocking (UUFB) enabled ('switchport block unicast') on all access switch ports." | Out-String
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

Function Get-V220633 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220633
        STIG ID    : CISC-L2-000130
        Rule ID    : SV-220633r929007_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000025
        Rule Title : The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
        DiscussMD5 : 9B26E14681DCBFA3930E53A4CD82DB5F
        CheckMD5   : 686D38193215026556C1898AD3D4B233
        FixMD5     : E53D124AE9857E3453F973DBD6E27F70
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    IF ($ShowRunningConfig -like "ip dhcp snooping *") {
        $SnoopingConfigs = $ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping vlan*"
        $FindingDetails += "DHCP snooping to validate DHCP messages from untrusted sources for following VLAN configurations enabled. Verify all user VLANs are included." | Out-String
        foreach ($vlan in $SnoopingConfigs) {
            $FindingDetails += $vlan.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "Enable DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources." | Out-String
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

Function Get-V220634 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220634
        STIG ID    : CISC-L2-000140
        Rule ID    : SV-220634r929009_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000026
        Rule Title : The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
        DiscussMD5 : 933D2A99F3F9DF8746FE33DB06D14F3A
        CheckMD5   : DC982306E8AEB5C9C192AD2D80522DB9
        FixMD5     : 4EF0CC421145023A5D4C2043D164ACF6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $ConfiguredInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "ip verify source") {
            $ConfiguredInterfaces += $Interface
        }
    }

    IF ($ConfiguredInterfaces.count -gt 0) {
        $FindingDetails += "IP Source Guard enabled ('ip verify source') on the following interfaces. Review the interfaces below and verify that all user-facing or untrusted access switch ports are included." | Out-String
        $FindingDetails += "-------------------- Interfaces --------------------" | Out-String
        ForEach ($int in $ConfiguredInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "IP Source Guard not enabled on any interfaces. Configure the switch to have IP Source Guard enabled ('ip verify source') on all user-facing or untrusted access switch ports." | Out-String
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

Function Get-V220635 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220635
        STIG ID    : CISC-L2-000150
        Rule ID    : SV-220635r929011_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000027
        Rule Title : The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
        DiscussMD5 : EE6894AEABF2580CF4D37303BFB8D268
        CheckMD5   : 1ECF38A9719545F12E33876ABCE76264
        FixMD5     : 2C591F7903A62781F296AD013738114B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -like "ip arp inspection *") {
        $ARPConfigs = $ShowRunningConfig | Select-String -Pattern "^ip arp inspection vlan*"
        $FindingDetails += "Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on following VLAN configurations enabled. Verify all user VLANs are included." | Out-String
        foreach ($dai in $ARPConfigs) {
            $FindingDetails += $dai.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "Configure the switch to have DAI enabled on all user VLANs." | Out-String
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

Function Get-V220636 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220636
        STIG ID    : CISC-L2-000160
        Rule ID    : SV-220636r648763_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000001
        Rule Title : The Cisco switch must have Storm Control configured on all host-facing switchports.
        DiscussMD5 : 15D17FB802182D99BE321FC5B295585F
        CheckMD5   : 62DD8E608E587959AFF8BA237046833E
        FixMD5     : 3A7E5A24630D054EDB185AD1611617E5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $GigInterfaces = $ShowRunningConfig | Select-String -Pattern "^interface Gigabit"
    $TenGigInterfaces = $ShowRunningConfig | Select-String -Pattern "^interface TenGigabit"
    $FlaggedInterfaces = @()

    ForEach ($Interface in $GigInterfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "storm-control broadcast level bps *") {
            $StormConfig = $InterfaceConfig | Select-String -Pattern "^storm-control broadcast level bps"
            $Bandwidth = ($StormConfig -split " ")[4]

            if ($Bandwidth -gt 1000000000 -or $Bandwidth -lt 10000000) {
                $FindingDetails += "Interface has storm control enabled but is outside the accetable range of 10000000-1000000000 for a Gigabit interface." | Out-String
                $FindingDetails += "Review the configuration below and verify storm control is enabled if this is a host-facing interface." | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $FindingDetails += "" | Out-String
                $Status = "Open"
            }
        }
        else {
            $FlaggedInterfaces += $Interface
        }
    }

    ForEach ($Interface in $TenGigInterfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "storm-control broadcast level bps *") {
            $StormConfig = $InterfaceConfig | Select-String -Pattern "^storm-control broadcast level bps"
            $Bandwidth = ($StormConfig -split " ")[4]

            if ($Bandwidth -gt 10000000000 -or $Bandwidth -lt 100000000) {
                $FindingDetails += "Interface has storm control enabled but is outside the accetable range of 100000000-10000000000 for a TenGigabit interface." | Out-String
                $FindingDetails += "Review the configuration below and verify storm control is enabled if this is a host-facing interface." | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $FindingDetails += "" | Out-String
                $Status = "Open"
            }
        }
        else {
            $FlaggedInterfaces += $Interface
        }
    }

    if ($FlaggedInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces have no storm control enabled." | Out-String
        $FindingDetails += "Review the interface configuration for any host-facing interfaces listed below and verify storm control is enabled within the accepatable range of 10000000-1000000000 for gigabit interfaces and 100000000-10000000000 for 10-gigabit interfaces." | Out-String
        $FindingDetails += "-------------------- Interfaces --------------------" | Out-String
        foreach ($int in $FlaggedInterfaces){
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Status_Reviewed"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220637 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220637
        STIG ID    : CISC-L2-000170
        Rule ID    : SV-220637r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000002
        Rule Title : The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
        DiscussMD5 : 20ACC76CEE52CC898D8D88427963DB56
        CheckMD5   : BCE59F4A2B55E23D69CD0417D0D41E12
        FixMD5     : DB901F9180D78C24AD2DCD85C9AA76CC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -like "no ip igmp snooping*") {
        $IGMPConfigs = $ShowRunningConfig | Select-String -Pattern "^no ip igmp snooping*"
        $FindingDetails += "IGMP or MLD Snooping is disabled on some or all VLANs. Review the configuration below and ensure IGMP or MLD Snooping is enabled for all VLANs." | Out-String
        foreach ($vlan in $IGMPConfigs) {
            $FindingDetails += $vlan.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "IGMP or MLD Snooping is configured on all VLANs." | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V220638 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220638
        STIG ID    : CISC-L2-000180
        Rule ID    : SV-220638r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000003
        Rule Title : The Cisco switch must implement Rapid Spanning Tree Protocol (STP) where VLANs span multiple switches with redundant links.
        DiscussMD5 : 060516BA1D02731FB538AFBD48BF3B28
        CheckMD5   : 270CEFC8020638B44C0B0A0AF4778EE8
        FixMD5     : B8123D454A8726521B83B298A32E1E0B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF ($ShowRunningConfig -contains "spanning-tree mode rapid-pvst") {
        $FindingDetails += "Rapid Per-Vlan-Spanning-Tree Protocol is implemented on this device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Elseif ($ShowRunningConfig -contains "spanning-tree mode mst") {
        $FindingDetails += "Multiple Spanning-Tree Protocol is implemented on this device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Elseif ($ShowRunningConfig -contains "spanning-tree mode pvst") {
        $FindingDetails += "Per-Vlan-Spanning-Tree Protocol is implemented on this device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify if Rapid STP or MSTP need to be implemented at the access and distribution layers where VLANs span multiple switches. IF VLANs span multiple switches for this configuration then STP must be implemented." | Out-String
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

Function Get-V220639 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220639
        STIG ID    : CISC-L2-000190
        Rule ID    : SV-220639r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000004
        Rule Title : The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
        DiscussMD5 : 2E6C1A1FC6E897D73B9A728B28719206
        CheckMD5   : E5EBFB1C441E34FB2EAE3350E10E2621
        FixMD5     : D0519B97FE606259B5E99DAB74EE8616
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $InterfacesConfigured = $False

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "udld port") {
            $InterfacesConfigured = $True
        }
    }

    IF ($ShowRunningConfig -contains "udld enable") {
        $FindingDetails += "Unidirectional Link Detection (UDLD) to protect against one-way connections is enabled globally in this configuration." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Elseif ($InterfacesConfigured) {
        $FindingDetails += "Unidirectional Link Detection (UDLD) to protect against one-way connections is enabled via interface configurations for this device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify if the switch has fiber optic interconnections with neighbors. If it does then UDLD must be enabled. An alternative implementation when UDLD is not supported by connected devices is to deploy a single member Link Aggregation Group (LAG) via IEEE 802.3ad Link Aggregation Control Protocol (LACP)." | Out-String
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

Function Get-V220640 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220640
        STIG ID    : CISC-L2-000200
        Rule ID    : SV-220640r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000005
        Rule Title : The Cisco switch must have all trunk links enabled statically.
        DiscussMD5 : 3136190C17D97A0CCC8071C58EB373BC
        CheckMD5   : E285E1E86AB745320CA5001F0CBEB1FD
        FixMD5     : 39035E61FFFA04CD741AB6A8B374CF0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $OpenFinding = $False

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -contains "switchport mode trunk") {
            if ($InterfaceConfig -notcontains "switchport nonegotiate") {
                $OpenFinding = $True
                $FindingDetails += "Review the switch configuration below and verify that trunk negotiation is disabled on this interface. Configure the switch to enable trunk links statically only." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
            }
        }
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

Function Get-V220641 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220641
        STIG ID    : CISC-L2-000210
        Rule ID    : SV-220641r991848_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000007
        Rule Title : The Cisco switch must have all disabled switch ports assigned to an unused VLAN.
        DiscussMD5 : 5659584D65011B8A3036273A1F73EEAC
        CheckMD5   : B6D96EA1E48D76E489EA6B9B1DB08E83
        FixMD5     : B021B6E1819543A9C62F11EDB944805A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    
    $FlaggedVlans = @()
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        
        if ($InterfaceConfig -contains "shutdown") {
            if ($InterfaceConfig -like "switchport access vlan *") {
                if (!($InterfaceConfig -like "*dot1x*")) {
                    $SwitchportCmd = $InterfaceConfig | Select-String -Pattern "^switchport access vlan .*"
                    $VlanID = ($SwitchportCmd -split " ")[3]
                    if ($FlaggedVlans -notcontains $VlanID) {
                        $FlaggedVlans += $VlanID.Trim().ToString()
                    }
                }
            }
        }
    }

    if ($FlaggedVlans -gt 0) {
        $FindingDetails += "The following switchport access vlans are associated to 'shutdown' interfaces and believed to be inactive VLANs. Inactive interfaces should only be assigned to inactive VLANs. Review the switchport access VLANs below and verify they are inactive." | Out-String
        $FindingDetails += "-------------------- VLAN IDs --------------------" | Out-String
        ForEach ($vlan in $FlaggedVlans) {
            $FindingDetails += "VLAN ID: $vlan" | Out-String
        }
        $FindingDetails += "" | Out-String
    
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

            if ($InterfaceConfig -like "switchport trunk allowed vlan *") {
                $TrunkVlans = $InterfaceConfig | Select-String -Pattern "^switchport trunk allowed vlan .*"
                $VlanIDsExtract = ($TrunkVlans -split " ")[4]
                $VlanIDs = $VlanIDsExtract -split ","

                foreach ($id in $VlanIDs) {
                    $OpenFinding = $False
                    if ($FlaggedVlans -contains $id){
                        $OpenFinding = $True
                    }
                    elseif ($id -like "*-*") {
                        $upperLimit = ($id -split "-")[1]
                        $lowerLimit = ($id -split "-")[0]
                        foreach ($FlaggedID in $FlaggedVlans) {
                            if ($FlaggedID -in $lowerLimit .. $upperLimit) {
                                $OpenFinding = $True
                                break
                            }
                        }
                    }

                    if ($OpenFinding){
                        $FindingDetails += "The following interface/port has been detected as allowing a believed inactive VLAN on a trunk port. Inactive VLANs are not allowed on any trunk links. Review the configuration below and verify that no inactive VLANs are allowed on trunk links." | Out-String
                        $FindingDetails += "-------------------- Interface Configuration --------------------" | Out-String
                        $FindingDetails += $Interface | Out-String
                        $FindingDetails += $InterfaceConfig | Out-String
                        $FindingDetails += "" | Out-String
                        $Status = "Not_Reviewed"
                        break
                    }
                }
            }
        }
    }
    else {
        $FindingDetails += "There were no 'shutdown' interfaces detected with 'switchport access vlan ##' configurations. No inactive VLANs were detected in the switch configuration. Review the switch configuration manually and verify that any inactive switch ports/interfaces are assigned to an inactive VLAN and any inactive VLANs on the device are not allowed on trunk ports." | Out-String
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

Function Get-V220642 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220642
        STIG ID    : CISC-L2-000220
        Rule ID    : SV-220642r991849_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000008
        Rule Title : The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
        DiscussMD5 : F32901248E280F4FA2D773B65868A198
        CheckMD5   : 54E17845BC3BC8BB30EAEC5ED486CC4E
        FixMD5     : D2950AF027B4A536392116BB95AE6A72
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # For this code to work, the following code must be added to the (Get-CiscoShowTechData) Function:
    <#
    "Vlan" {
                #This pulls show vlan section from show tech config file
                $startSTR = "^-{18} show vlan -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            #>
    # Addtionally, "Vlan" must be added as an option to the '[ValidateSet(...)]' Param(...) variables.

    $ShowVlan = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType Vlan)
    $Vlans = $ShowVlan -split "\n"
    $DefaultVlan = $ShowVlan | Select-String -Pattern "^2 \s+ U_UNUSED .*"
    $DefaultVlanConfig = @()

    ForEach ($line in $Vlans){
        if ($line -match "VLAN Type .*") {
            break
        }
        elseif ($line -match "^1 \s+ default .*") {
            $line = $line.replace(",","")
            $Ports += ($line -split "\s+") | Select-Object -skip 3
            if ($Ports.count -gt 0) {
                Write-Output "Appending: $line"
                $DefaultVlanConfig += $line
            }
            else {
                break
            }
        }
        elseif ($line -match "[0-9]+\s+.*") {
            $Port = ($line -split " ")[0]
            if ($port -gt 1) {
                break
            }
        }
        elseif ($line -match "^\s+") {
            $DefaultVlanConfig += $line
        }
    }

    if ($DefaultVlanConfig.count -gt 0) {
        $FindingDetails += "The following ports are assigned to the default VLAN. Review the Vlan configuration below and remove assignment of any access switch ports from the default Vlan (Vlan 1)." | Out-String
        $FindingDetails += "-------------------- VLAN Configuration --------------------" | Out-String
        foreach ($line in $DefaultVlanConfig) {
            $FindingDetails += $line.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    else {
        $FindingDetails += "No access switch ports configured for default Vlan." | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V220643 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220643
        STIG ID    : CISC-L2-000230
        Rule ID    : SV-220643r991850_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000009
        Rule Title : The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
        DiscussMD5 : 257CDB108E63ED01F412AEF044DB5713
        CheckMD5   : 6800C8C1165C318A739318700DF4DC55
        FixMD5     : 01D902F784D8E449F82E2D257DAA5155
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ShowInterfacesTrunk = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType Trunk)
    $OpenFinding = $False
    $Exception = $False
    $TrunkLines = $ShowInterfacesTrunk -split "\n"
    $NativeVlanDefault = @()
    $Running = $False
    $NativeVlanAllowed = @()

    ForEach ($line in $TrunkLines) {
        if ($line -like "*trunking*") {
            $LineElements = ($line -split "\s+").Trim()
            if ($LineElements[4] -eq 1) {
                #Write-Output $line
                $NativeVlanDefault += $line
            }
        }
        elseif ($line -like "*Vlans allowed on trunk*") {
            $VlansAllowedLine = $line
            $Running = $True
        }
        elseif ($line -like "*Vlans allowed and active in management domain*") {
            $Running = $False
        }
        elseif ($Running) {
            $LineElements = ($line -split "\s+")[1]
            $TrunkPorts = $LineElements -split ","
            #Write-Output "Ports: $TrunkPorts"
            forEach ($port in $TrunkPorts) {
                if ($port -contains 1){
                    $NativeVlanAllowed += $line
                    $Exception = $True
                    break
                }
                elseif ($port -like "*-*") {
                    $lowerPort = ($port -split "-")[0]
                    if ($lowerPort -eq 1){
                        $NativeVlanAllowed += $line
                        $Exception = $True
                        break
                    }
                }
            }
        }
    }

    if ($NativeVlanDefault.count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below interfaces have Vlan 1 as the Native Vlan:" | Out-String
        $FindingDetails += "----------------------------------------------------" | Out-String
        $FindingDetails += "Port`t`t    Mode`t Encapsulation`tStatus`t      Native vlan" | Out-String
        foreach ($port in $NativeVlanDefault) {
            $FindingDetails += $port.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no interfaces with Vlan 1 as the Native Vlan." | Out-String
        $FindingDetails += "" | Out-String
    }
    if ($NativeVlanAllowed.count -gt 0){
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below interfaces have Vlan 1 allowed on trunk. Verify the default VLAN is pruned from trunk links that do not require it and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += $VlansAllowedLine | Out-String
        foreach ($port in $NativeVlanAllowed) {
            $FindingDetails += $port.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no interfaces with Vlan 1 allowed on trunk." | Out-String
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

Function Get-V220644 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220644
        STIG ID    : CISC-L2-000240
        Rule ID    : SV-220644r991852_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-L2S-000010
        Rule Title : The Cisco switch must not use the default VLAN for management traffic.
        DiscussMD5 : 9C6BF9540DD979FF91891473C106DF2F
        CheckMD5   : 6800C8C1165C318A739318700DF4DC55
        FixMD5     : 3F1B1D11FC57475117E0D9519DDE4EB9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ShowInterfacesTrunk = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType Trunk)
    $OpenFinding = $False
    $Exception = $False
    $TrunkLines = $ShowInterfacesTrunk -split "\n"
    $NativeVlanDefault = @()
    $Running = $False
    $NativeVlanAllowed = @()

    ForEach ($line in $TrunkLines) {
        if ($line -like "*trunking*") {
            $LineElements = ($line -split "\s+").Trim()
            if ($LineElements[4] -eq 1) {
                #Write-Output $line
                $NativeVlanDefault += $line
            }
        }
        elseif ($line -like "*Vlans allowed on trunk*") {
            $VlansAllowedLine = $line
            $Running = $True
        }
        elseif ($line -like "*Vlans allowed and active in management domain*") {
            $Running = $False
        }
        elseif ($Running) {
            $LineElements = ($line -split "\s+")[1]
            $TrunkPorts = $LineElements -split ","
            #Write-Output "Ports: $TrunkPorts"
            forEach ($port in $TrunkPorts) {
                if ($port -contains 1){
                    $NativeVlanAllowed += $line
                    $Exception = $True
                    break
                }
                elseif ($port -like "*-*") {
                    $lowerPort = ($port -split "-")[0]
                    if ($lowerPort -eq 1){
                        $NativeVlanAllowed += $line
                        $Exception = $True
                        break
                    }
                }
            }
        }
    }

    if ($NativeVlanDefault.count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below interfaces have Vlan 1 as the Native Vlan:" | Out-String
        $FindingDetails += "----------------------------------------------------" | Out-String
        $FindingDetails += "Port`t`t    Mode`t Encapsulation`tStatus`t      Native vlan" | Out-String
        foreach ($port in $NativeVlanDefault) {
            $FindingDetails += $port.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no interfaces with Vlan 1 as the Native Vlan." | Out-String
        $FindingDetails += "" | Out-String
    }
    if ($NativeVlanAllowed.count -gt 0){
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below interfaces have Vlan 1 allowed on trunk. Verify the default VLAN is pruned from trunk links that do not require it and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += $VlansAllowedLine | Out-String
        foreach ($port in $NativeVlanAllowed) {
            $FindingDetails += $port.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no interfaces with Vlan 1 allowed on trunk." | Out-String
        $FindingDetails += "" | Out-String
    }

    # Get Vlan 1 interface configuration.
    $VlanOneInterface = $ShowRunningConfig | Select-String -Pattern "^interface Vlan1`$"
    IF ($VlanOneInterface) {
        $InterfaceVlanOneConfig = Get-Section $ShowRunningConfig $VlanOneInterface.ToString()
        IF ($InterfaceVlanOneConfig -like "ip address*") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interface Vlan1 is configured with an IP address. This is a finding:" | Out-String
            $FindingDetails += "--------------------------------------------------------------------" | Out-String
            $FindingDetails += $VlanOneInterface.ToString() | Out-String
            $FindingDetails += $InterfaceVlanOneConfig -like "ip address*" | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interface Vlan1 is not configured with an IP address." | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V220645 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220645
        STIG ID    : CISC-L2-000250
        Rule ID    : SV-220645r991853_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000011
        Rule Title : The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
        DiscussMD5 : 8A173F02E72EB8639CFA2A586304E64F
        CheckMD5   : 173C611442BF78CE6CF85615AA8A7CF1
        FixMD5     : 11352E60542E0F8E4B24945C0228BC9F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $ConfiguredInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        
        if ($InterfaceConfig -like "switchport mode trunk") {
            $ConfiguredInterfaces += $Interface
        }
    }

    if ($ConfiguredInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces are configured as trunks. Verify and disable trunking for any that are user-facing or untrusted switch ports." | Out-String
        $FindingDetails += "-------------------- Interfaces --------------------" | Out-String
        ForEach ($int in $ConfiguredInterfaces){
            $FindingDetails += $int.ToString() | Out-String
        }
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

Function Get-V220646 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220646
        STIG ID    : CISC-L2-000260
        Rule ID    : SV-220646r991854_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000012
        Rule Title : The Cisco switch must have the native VLAN assigned to an ID other than the default VLAN for all 802.1q trunk links.
        DiscussMD5 : 7487C158C04500D4109BE98D9395EB72
        CheckMD5   : F78D4FBE7F7A3091A18D2C15A7E2E0B0
        FixMD5     : 772A2610F5A5891DFB4A343FA0F55CBE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $NativeVlan = $False
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF ($InterfaceConfig -like "switchport trunk native vlan *") {
            $NativeVlan = $True
            $Switchport = $InterfaceConfig | Select-String -Pattern "^switchport trunk native vlan"
            IF ($Switchport -like "switchport trunk native vlan 1") {
                # Add non-compliant interface to inventory
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($Switchport | Out-String).Trim()
                $NonCompliantInt += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add compliant interface to inventory
                $CompliantInt += ($Interface | Out-String).Trim()
                $CompliantInt += ($Switchport | Out-String).Trim()
                $CompliantInt += "" | Out-String
            }
        }
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below trunk interfaces are configured with the default VLAN 1 as the Native Vlan. This device must have the native VLAN assigned to an ID other than the default VLAN, this is a finding:" | Out-String
        $FindingDetails += "-----------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += $NonCompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }
    IF ($CompliantInt) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below trunk interfaces are configured with a Native Vlan different to the default Vlan:" | Out-String
        $FindingDetails += "-------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += $CompliantInt | Out-String
    }

    IF (!$NativeVlan) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Native Vlans are not configured under any trunk interface on this device." | Out-String
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

Function Get-V220647 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220647
        STIG ID    : CISC-L2-000270
        Rule ID    : SV-220647r991855_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000013
        Rule Title : The Cisco switch must not have any switchports assigned to the native VLAN.
        DiscussMD5 : CB3AD9DF8356FDBA68DC80F1BA3A457A
        CheckMD5   : 25595046E054827DCCCEFF79DBF12CF0
        FixMD5     : B83768DE527DF9D987AC617125B2DB48
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $NativeVlan = $False
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $SwitchportTrunk = $InterfaceConfig | Select-String -Pattern "^switchport trunk native vlan"
        $SwitchportAccess = $InterfaceConfig | Select-String -Pattern "^switchport access vlan"
        IF ($SwitchportTrunk -AND $SwitchportAccess) {
            $NativeVlan = $True
            # Get Native Vlan ID
            $NativeVlanId = $SwitchportTrunk.ToString().Split([char[]]"") | Select-Object -Last 1
            # Get Access Vlan
            $AccessVlan = $SwitchportAccess.ToString().Split([char[]]"") | Select-Object -Last 1
            IF ($NativeVlanId -eq $AccessVlan) {
                # Add non-compliant interface to inventory
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($SwitchportAccess | Out-String).Trim()
                $NonCompliantInt += ($SwitchportTrunk | Out-String).Trim()
                $NonCompliantInt += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add compliant interface to inventory
                $CompliantInt += ($Interface | Out-String).Trim()
                $CompliantInt += ($SwitchportAccess | Out-String).Trim()
                $CompliantInt += ($SwitchportTrunk | Out-String).Trim()
                $CompliantInt += "" | Out-String
            }
        }
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below trunk interfaces are configured with the same Access VLAN as the Native Vlan. This device must not have a switchport assigned to the native VLAN, this is a finding:" | Out-String
        $FindingDetails += "-----------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += $NonCompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }
    IF ($CompliantInt) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below trunk interfaces are configured with a Native Vlan different to the Access Vlan:" | Out-String
        $FindingDetails += "------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += $CompliantInt | Out-String
    }

    IF (!$NativeVlan) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Native Vlans matching Access Vlans are not configured under any interface on this device." | Out-String
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

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCvh28poc/h96Qt
# Mn3qj3XG04v+8b2pKRLIrBCUdqSrOaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCA7E3QItqF5X6SkVUAozJjo3ucoLCe0+R4jtnExyViTGjANBgkqhkiG9w0BAQEF
# AASCAQAjvq09E7IhI1pgElcJgTCRVxiEXrIqWoTbKy06jIW8G0+aPh1WTmCKpc5h
# rZsfKlxw12owPvRog+D79sf9+HRuoCt9krqkQLvPPJThFaSSKJNcuJjLzKedg7Lc
# reJk7QsSM5FAYZe+CtgmEaMaQBTRWqAU7WKxVHVml8E96+pYQjhLHQ2hOgSI5U5l
# 71fa7/bq5kTbHHvHF/631kaz26i81w/CfFxImCkQfEf/2KTnnX48SmCVuz+/s0gD
# +U+UEBcxcyAxSDHHylH4tkLCb/ML0cz7E78oqjypVByQrfXHNSFB0H/GRF4sR6B/
# mmwLF2XvnfspXN4mZeX+O2W9JpS+oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTYzMlowLwYJKoZIhvcNAQkEMSIEIFw4G4ITZP+vXHOjVjUJ8wxyaGmM
# mlYPA/9nx5Pg3n1bMA0GCSqGSIb3DQEBAQUABIICAM20VanUzMM9iHXOPCIjL6OD
# oDgQSnQ/2P7TuGy706QX3EZoxgEKztQjjx6tr6KfBigoViVTLYlwacsfUgH9+mHZ
# EgGAdnzIvJiXamrHVhgOJFNu9Dy8+2pOqrMnTzBxbay7lQnDC2HZbWngDrHtKosI
# qQp43p43ZpnirBBvuxfJ1jCkkV4hCWOfQ0ZfPQ+u+q/O7e0FIBbWzP0yW0y/iFrK
# jGvVe9HQbbKMbMTnc9id1RWQZPBgBPS/PfF/XFOuZ6ASj+ZMlmHBM8HrMTOxazqI
# 7IkLIxVjjryKH5g4laJ+eKM/oVbkUToj0J0Utx9nk00aQRzvstLTDDV/0H9AVmli
# p/2JK77EbDXiIG7SJSP8+sU0KHSONKrv5xNfZ5jjUHV9Y+gTf0oAwTcV8fMwblFe
# DSCsvpT4O53yiZxbAntWg/Y+20CavuMSmL6LCMPCbKvh4lhKhlRHh/1rAqw3uFgj
# bfT4qP07+uoNcz/k2yhO2Ov4jx8kTJolAD8sepcQ8HeHaNL2Y+lW05m2xrZwOxzZ
# 9fd2dCL2A2DjNCsrrqu7M5i0Vj0FPOczMxyy9R2XCr5mSW8LLvcaV7cKBrIoSFkK
# TbB7g1EehALCqXSo7N+PT46NX5iLNbKx3IFRr15LxmvOPipveCxOJsi/mJ3wm+Ot
# v7Pvi3WOrvDIGgYDIcPg
# SIG # End signature block
