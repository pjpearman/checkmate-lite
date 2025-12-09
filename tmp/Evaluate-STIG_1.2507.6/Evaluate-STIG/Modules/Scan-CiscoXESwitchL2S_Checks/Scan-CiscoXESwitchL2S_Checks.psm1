##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XE Switch L2S
# Version:  V3R2
# Class:    UNCLASSIFIED
# Updated:  10/7/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V220649 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220649
        STIG ID    : CISC-L2-000020
        Rule ID    : SV-220649r863283_rule
        CCI ID     : CCI-000778, CCI-001958
        Rule Name  : SRG-NET-000148-L2S-000015
        Rule Title : The Cisco switch must uniquely identify and authenticate all network-connected endpoint devices before establishing any connection.
        DiscussMD5 : F8510CA83F388038C74BF5CBCCB63E0C
        CheckMD5   : DDB343463008CCC67D5D81DD5FCC03B9
        FixMD5     : B01C9E2DE307BE04E7EA44A232AF1EF3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $InterfacesConfigured = @()
    $OpenFinding = $False
    $Exception = $False
    $Non8021xInterfacesWithMab = @()
    $Non8021xInterfacesWithOutMab = @()
    # Check for applicable interfaces
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        # Create list of any interfaces with 802.1x configurations
        IF ($InterfaceConfig -contains "switchport mode access") {
            $Exception = $True
            IF (($InterfaceConfig -contains "authentication port-control auto") -AND ($InterfaceConfig -contains "dot1x pae authenticator")) {
                $InterfacesConfigured += $Interface
            } ELSE {
                $MabConfig = ($InterfaceConfig | Select-String -Pattern "^mab ")
                If ($MabConfig) {
                   $Non8021xInterfacesWithMab += "$Interface"
                } Else {
                    $Non8021xInterfacesWithOutMab += "$Interface"
                }
            }
        }
    }
    IF ($InterfacesConfigured.count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces are configured with 802.1x authentication. Review the list below and verify that no host-facing interfaces on the switch are missing from the list. All host-facing interfaces must have 802.1x authentication configured:" | Out-String
        $FindingDetails += "---------------------------------------------------------" | Out-String
        ForEach ($Int in $InterfacesConfigured){
            $FindingDetails += "$Int`n"
        }
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No interfaces are configured with 802.1x authentication. All host-facing interfaces must have 802.1x authentication configured." | Out-String
        $FindingDetails += "" | Out-String
    }
    IF ($Non8021xInterfacesWithMab.count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are configured with MAB." | Out-String
        $FindingDetails += "---------------------------------------------------------" | Out-String
        $FindingDetails += $Non8021xInterfacesWithMab | Out-String
        $FindingDetails += "" | Out-String
    }
    IF ($Non8021xInterfacesWithOutMab.count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are not configured with 802.1X authentication or MAB." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "---------------------------------------------------------" | Out-String
        $FindingDetails += $Non8021xInterfacesWithOutMab | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    $NonCompliant = @()
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
        # Flag missing global 802.1x authentication configurations
        IF (!($ShowRunningConfig -like "aaa authentication dot1x * $serverGroup")){
            $NonCompliant += "802.1x authentication group configuration 'aaa authentication dot1x * $serverGroup' is missing for group $serverGroup." | Out-String
            $NonCompliant += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            $FindingDetails += $ShowRunningConfig -like "aaa authentication dot1x * $serverGroup" | Out-String
        }
        IF (!($ShowRunningConfig -like "dot1x system-auth-control")){
            $NonCompliant += "802.1x authentication configuration 'dot1x system-auth-control' is missing." | Out-String
            $NonCompliant += "" | Out-String
            $OpenFinding = $True
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
                $FindingDetails += "Radius server configurations:" | Out-String
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
        $OpenFinding = $True
    }
    If ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        $Status = "NotAFinding"
        If ($Exception) {
            $Status = "Not_Reviewed"
        }
        If ($NotApplicable) {
           $Status = "Not_Applicable"
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

Function Get-V220650 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220650
        STIG ID    : CISC-L2-000030
        Rule ID    : SV-220650r539671_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-NET-000168-L2S-000019
        Rule Title : The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
        DiscussMD5 : 24E89763F6CA1B9FDF7D4F21731C370D
        CheckMD5   : DA2B247E426A0C758B1FD8575A8CC7BE
        FixMD5     : C5BA77EB57896898F0186FF2F1E8DCB7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V220651 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220651
        STIG ID    : CISC-L2-000040
        Rule ID    : SV-220651r1107171_rule
        CCI ID     : CCI-001095, CCI-004866
        Rule Name  : SRG-NET-000193-L2S-000020
        Rule Title : The Cisco switch must manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks.
        DiscussMD5 : 87D3D56BCC93C83E4B12D331B6F1C190
        CheckMD5   : CD4E9B2B6ED1A63BDE1F291245E26459
        FixMD5     : EB377BFD432C32F1572E2E2F9DA9183E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $CompliantClassMapConfig = @()
    $CompliantClassMap = @()
    $CompliantPolicyMapConfig = @()
    $CompliantPolicyMap = @()
    $CompliantInterface = @()
    $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map match-*"
    IF ($ClassMaps) {
        ForEach ($ClassMap in $ClassMaps) {
            $ClassMapConfig = Get-Section $ShowRunningConfig $ClassMap.ToString()
            # Get class-maps that match DSCP
            IF ($ClassMapConfig | Select-String -Pattern "match dscp *|match ip dscp *") {
                $CompliantClassMapConfig += ($ClassMap.ToString() | Out-String).Trim()
                $CompliantClassMapConfig += (($ClassMapConfig | Select-String -Pattern "match dscp *|match ip dscp *").ToString() | Out-String).Trim()
                $CompliantClassMapConfig += "" | Out-String
                $CompliantClassMap += ($ClassMap).ToString().Split([char[]]"")[-1]
            }
        }
        $Exception = $True
    }

    # Get policy-map configuration
    $PolicyMaps = $ShowRunningConfig | Select-String -Pattern "^policy-map*"
    IF ($PolicyMaps -AND $CompliantClassMap) {
        ForEach ($PolicyMap in $PolicyMaps) {
            $PolicyMapConfig = Get-Section $ShowRunningConfig $PolicyMap.ToString()
            ForEach ($Class in $CompliantClassMap) {
                IF ($PolicyMapConfig | Select-String -Pattern "class $Class`$") {
                    $CompliantPolicyMapConfig += ($PolicyMap.ToString() | Out-String).Trim()
                    $CompliantPolicyMapConfig += $PolicyMapConfig
                    $CompliantPolicyMapConfig += "" | Out-String
                    $CompliantPolicyMap += ($PolicyMap).ToString().Split([char[]]"")[-1]
                }
            }
        }
    }

    # Get interfaces with policy-maps configured
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
    IF ($CompliantPolicyMap) {
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            ForEach ($Policy in $CompliantPolicyMap) {
                IF ($InterfaceConfig -like "service-policy output $Policy") {
                    $CompliantInterface += ($Interface.ToString() | Out-String).Trim()
                    $CompliantInterface += (($InterfaceConfig -like "service-policy output $Policy") | Out-String).Trim()
                    $CompliantInterface += "" | Out-String
                }
            }
        }
    }

    IF ($CompliantClassMapConfig) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify the below class-maps are properly configured to manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-----------------------------------------------------------------------------" | Out-String
        $FindingDetails += $CompliantClassMapConfig | Out-String
        $FindingDetails += "" | Out-String

        IF ($CompliantPolicyMapConfig) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify the below policy-maps are properly configured to manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-----------------------------------------------------------------------------" | Out-String
            $FindingDetails += $CompliantPolicyMapConfig | Out-String
            $FindingDetails += "" | Out-String

            IF ($CompliantInterface) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify the below interfaces are properly configured to manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-----------------------------------------------------------------------------" | Out-String
                $FindingDetails += $CompliantInterface | Out-String
                $FindingDetails += "" | Out-String
            }
            ELSE {
                $FindingDetails += "" | Out-String
                $FindingDetails += "This device does not have interfaces configured with the DSCP policy-maps. This is a finding." | Out-String
                $OpenFinding = $True
            }
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device does not have policy-maps configured matching the DSCP class-maps. This is a finding." | Out-String
            $OpenFinding = $True
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have class-maps configured that match DSCP values. This is a finding." | Out-String
        $OpenFinding = $True
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

Function Get-V220655 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220655
        STIG ID    : CISC-L2-000090
        Rule ID    : SV-220655r917683_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000021
        Rule Title : The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches.
        DiscussMD5 : 919F25DECAC50CC844E5F32293AA2CD3
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -like "switchport*") {
            IF ($InterfaceConfig -contains "spanning-tree guard root") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "spanning-tree guard root") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "spanning-tree guard root"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "spanning-tree guard root is not configured"
                $NonCompliantInt += ""
            }
        }
    }

    IF ($CompliantInt) {
        $FindingDetails += "Compliant Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "Review the switch topology as well as the switch configuration below to verify that Root Guard is enabled on all switch ports connecting to access layer switches." | Out-String
        $FindingDetails += "Interfaces without spanning-tree guard root configured" | Out-String
        $FindingDetails += "-------------------------------------------------------" | Out-String
        $FindingDetails += $NonCompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF (!$OpenFinding) {
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

Function Get-V220656 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220656
        STIG ID    : CISC-L2-000100
        Rule ID    : SV-220656r856278_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000022
        Rule Title : The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
        DiscussMD5 : 94230130CD0AE05E3249EC678D069733
        CheckMD5   : 66D0BC7EF09FB7A6742A5154DAEEBC0D
        FixMD5     : 3043178CCBE2ACDC6E2F469DF0D05BC0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "spanning-tree bpduguard enable") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "spanning-tree bpduguard enable") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "spanning-tree bpduguard enable"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "spanning-tree bpduguard enable is not configured"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review the switch configuration to verify that BPDU Guard is enabled on all user-facing or untrusted access switch ports:" | Out-String
            $FindingDetails += "Interfaces without BDPU guard enabled" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220657 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220657
        STIG ID    : CISC-L2-000110
        Rule ID    : SV-220657r856279_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000023
        Rule Title : The Cisco switch must have STP Loop Guard enabled.
        DiscussMD5 : EEFE508FFEDFDF8955D91E4127265557
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
    $LoopGuard = $ShowRunningConfig | Select-String -Pattern "^spanning-tree loopguard default"
    $FindingDetails += "Spanning-tree loopguard" | Out-String
    $FindingDetails += "-----------------------------" | Out-String
    IF ($LoopGuard) {
        $FindingDetails += ($LoopGuard | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "spanning-tree loopguard not enabled" | Out-String
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

Function Get-V220658 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220658
        STIG ID    : CISC-L2-000120
        Rule ID    : SV-220658r856280_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000024
        Rule Title : The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
        DiscussMD5 : 5AF49A78E3E971FF676BF9515E287A64
        CheckMD5   : BA90B6897D05E3562F404AC62DAD74BF
        FixMD5     : 38B6FB7665948A84EED2EA954824003B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    # Check each Interface that it is NOT shutdown AND it is in switchport access (optional "mode")
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

            # TODO: Somewhere in here add an optional check for VLAN = 1 or $NULL if a Trunk with DTP enabled and note V-220668? See Issue 1488
            If (($InterfaceConfig -match "switchport (mode)?\s?trunk") -and ($InterfaceConfig -contains "switchport nonegotiate")) {
                    # Port is configured to be TRUNK, but DTP (Dynamic Trunking Protocol) is NOT turned off. Could fallback to access.
                    $CompliantInt += ($Interface | Out-String).Trim()
                    $CompliantInt += "Interface is configured to be a Trunk, but DTP is NOT enabled. It can never be an access port."
                    $NonCompliantInt += ""
            } Else {
                IF ($InterfaceConfig -contains "switchport block unicast") {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "switchport block unicast") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport block unicast"} | Out-String).Trim()
                    }
                    $CompliantInt += " "
                }
                Else {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += "switchport block unicast is not configured"
                    $NonCompliantInt += ""
                }
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220659 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220659
        STIG ID    : CISC-L2-000130
        Rule ID    : SV-220659r928999_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000025
        Rule Title : The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
        DiscussMD5 : 52AD90E48CDE65A4672D118864101A67
        CheckMD5   : 686D38193215026556C1898AD3D4B233
        FixMD5     : F5DA9C7FA27C75DDC0AEA3520FC5F716
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $ActiveVLANs = @() # Inventory of VLANs assigned to active switchports
    $SnoopingVLANS = @() # Inventory of VLANs covered by DHCP snooping
    $ActiveNoSnooping = @() # Inventory of active VLANs without DHCP snooping enabled

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If ($InterfaceConfig -like "switchport access vlan*") {
                $AccessVLAN = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3]
                If ($AccessVLAN -notin $ActiveVLANs) {
                    # Add active VLAN to inventory
                    $ActiveVLANs += [int]$AccessVLAN
                }
            }
            Else {
                If ("1" -notin $ActiveVLANs) {
                    # Add default VLAN to inventory
                    $ActiveVLANs += [int]1
                }
            }
        }
    }

    $Compliant = $true
    If ($ActiveAccessSwitchPorts) {
        $DHCPSnoopingLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping`$" | Out-String).Trim()
        If ($DHCPSnoopingLine) {
            $FindingDetails += "Found:`t`t`t`t`t'$($DHCPSnoopingLine)'" | Out-String
            $DHCPSnoopingVLANLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping vlan .*" | Out-String).Trim()
            $DHCPSnoopingVLANs = ($DHCPSnoopingVLANLine).Split([char[]]"").Split(",") | Select-Object -Skip 4
            If ($DHCPSnoopingVLANs) {
                $FindingDetails += "Found:`t`t`t`t`t'$($DHCPSnoopingVLANLine)'" | Out-String
                # Get list of VLANs with DHCP Snooping
                ForEach ($Vlan in $DHCPSnoopingVLANs) {
                    If ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $SnoopingVLANS += [int]$StartInt..[int]$EndInt
                    }
                    Else {
                        $SnoopingVLANS += [int]$Vlan
                    }
                }
                # Check each active VLAN against VLANs with DHCP Snooping
                ForEach ($ActiveVLAN in $ActiveVLANs) {
                    If ($ActiveVLAN -notin $SnoopingVLANS) {
                        $Compliant = $false
                        $ActiveNoSnooping += [int]$ActiveVLAN
                    }
                }
                $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
                $FindingDetails += "DHCP Snooping VLANs:`t`t$(($SnoopingVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
                If ($ActiveNoSnooping) {
                    $Compliant = $false
                    $VLANsToVerify = $ActiveNoSnooping
                }
            }
            Else {
                $Compliant = $false
                $VLANsToVerify = $ActiveVLANs
                $FindingDetails += "NOT Found:`t`t`t`t'ip dhcp snooping vlan <user-vlans>'" | Out-String
            }
        }
        Else {
            $Compliant = $false
            $VLANsToVerify = $ActiveVLANs
            $FindingDetails += "NOT Found:`t`t`t`t'ip dhcp snooping'" | Out-String
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "" | Out-String
            $FindingDetails += "All active access VLANs have DHCP Snooping enabled." | Out-String
        }
        Else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if any of the below are user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "VLANs without Snooping:`t$(($VLANsToVerify | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220660 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220660
        STIG ID    : CISC-L2-000140
        Rule ID    : SV-220660r929001_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000026
        Rule Title : The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
        DiscussMD5 : 355BEC1413E67C2234943A0C25DBF547
        CheckMD5   : 75ABABCC10D5354B107F20485240BCA9
        FixMD5     : ECD33A14A8CE655D0565017250543FA8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $BadSwitchPorts = [System.Collections.Generic.List[System.Object]]::new() # Inventory of non-compliant switch ports

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If (-Not($InterfaceConfig | Where-Object {$_ -like "ip verify source"})) {
                # Add non-compliant interface to inventory
                $NewObj = [PSCustomObject]@{
                    Interface   = ($Interface | Out-String).Trim()
                    Description = ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    Vlan        = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim()
                    Mode        = ($InterfaceConfig -like "switchport mode access*" | Out-String).Trim()
                }
                $BadSwitchPorts.Add($NewObj)
            }
        }
    }

    $Compliant = $true
    If ($ActiveAccessSwitchPorts) {
        If ($BadSwitchPorts) {
            $Compliant = $false
            $FindingDetails += "The below active interfaces do not have 'ip verify source' configured.  Verify if any are user-facing or untrusted and make finding determinitation based on STIG check guidance:" | Out-String
            ForEach ($Item in $BadSwitchPorts) {
                $FindingDetails += "" | Out-String
                $FindingDetails += $Item.Interface | Out-String
                If ($Item.Description) {
                    $FindingDetails += " $($Item.Description)" | Out-String
                }
                If ($Item.Vlan) {
                    $FindingDetails += " $($Item.Vlan)" | Out-String
                }
                If ($Item.Mode) {
                    $FindingDetails += " $($Item.Mode)" | Out-String
                }
            }
        }
        Else {
            $FindingDetails += "All active interfaces have 'ip verify source'." | Out-String
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220661 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220661
        STIG ID    : CISC-L2-000150
        Rule ID    : SV-220661r929003_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000027
        Rule Title : The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
        DiscussMD5 : ADCCF2024DB567605E03B203F42CC4F7
        CheckMD5   : 733A12EBC16F3F5DD5FB9137BDB1BE9E
        FixMD5     : 2FAAC2499CE2CF9CC522D2033FABDB89
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $ActiveVLANs = @() # Inventory of VLANs assigned to active switchports
    $SnoopingVLANS = @() # Inventory of VLANs covered by DHCP snooping
    $ArpInspectVLANS = @() # Inventory of VLANs covered by ARP inspection
    $ActiveNoArpInspect = @() # Inventory of active VLANs without ARP inspection enabled
    $ArpInspectNoSnoop = @() # Inventory of ARP inspect VLANs not in DHCP snooping
    $CiscoCmdFound = "" # Cisco commands per STIG

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If ($InterfaceConfig -like "switchport access vlan*") {
                $AccessVLAN = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3]
                If ($AccessVLAN -notin $ActiveVLANs) {
                    # Add active VLAN to inventory
                    $ActiveVLANs += [int]$AccessVLAN
                }
            }
            Else {
                If ("1" -notin $ActiveVLANs) {
                    # Add default VLAN to inventory
                    $ActiveVLANs += [int]1
                }
            }
        }
    }

    $Compliant = $true
    If ($ActiveAccessSwitchPorts) {
        $DHCPSnoopingLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping`$" | Out-String).Trim()
        If ($DHCPSnoopingLine) {
            $CiscoCmdFound += "Found:`t`t`t`t`t'$($DHCPSnoopingLine)'" | Out-String
            $DHCPSnoopingVLANLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping vlan .*" | Out-String).Trim()
            $DHCPSnoopingVLANs = ($DHCPSnoopingVLANLine).Split([char[]]"").Split(",") | Select-Object -Skip 4
            If ($DHCPSnoopingVLANs) {
                $CiscoCmdFound += "Found:`t`t`t`t`t'$($DHCPSnoopingVLANLine)'" | Out-String
                # Get list of VLANs with DHCP Snooping
                ForEach ($Vlan in $DHCPSnoopingVLANs) {
                    If ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $SnoopingVLANS += [int]$StartInt..[int]$EndInt
                    }
                    Else {
                        $SnoopingVLANS += [int]$Vlan
                    }
                }
            }
            Else {
                $Compliant = $false
                $CiscoCmdFound += "NOT Found:`t`t`t`t'ip dhcp snooping vlan <user-vlans>'" | Out-String
            }
        }
        Else {
            $Compliant = $false
            $CiscoCmdFound += "NOT Found:`t`t`t`t'ip dhcp snooping'" | Out-String
        }

        $ARPInspectionLine = ($ShowRunningConfig | Select-String -Pattern "^ip arp inspection vlan" | Out-String).Trim()
        If ($ARPInspectionLine) {
            $CiscoCmdFound += "Found:`t`t`t`t`t'$($ARPInspectionLine)'" | Out-String
            $ARPInspectionVLANs = ($ARPInspectionLine).Split([char[]]"").Split(",") | Select-Object -Skip 4
            If ($ARPInspectionVLANs) {
                # Get list of VLANs with DHCP Snooping
                ForEach ($Vlan in $ARPInspectionVLANs) {
                    If ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $ArpInspectVLANS += [int]$StartInt..[int]$EndInt
                    }
                    Else {
                        $ArpInspectVLANS += [int]$Vlan
                    }
                }
                # Check each ARP inspection VLAN against VLANs with DHCP snooping
                ForEach ($ArpVlan in $ArpInspectVLANS) {
                    If ($ArpVlan -notin $SnoopingVLANS) {
                        $Compliant = $false
                        $ArpInspectNoSnoop += [int]$ArpVlan
                    }
                }
                If ($ArpInspectNoSnoop) {
                    $Compliant = $false
                }

                # Check each active VLAN against VLANs with ARP inspection
                ForEach ($ActiveVLAN in $ActiveVLANs) {
                    If ($ActiveVLAN -notin $ArpInspectVLANS) {
                        $Compliant = $false
                        $ActiveNoArpInspect += [int]$ActiveVLAN
                    }
                }
                If ($ActiveNoArpInspect) {
                    $Compliant = $false
                }
            }
            Else {
                $Compliant = $false
                $ActiveNoArpInspect = $ActiveVLANs
                $CiscoCmdFound += "NOT Found:`t`t`t`t'ip arp inspection vlan <user-vlans>'" | Out-String
            }
        }
        Else {
            $Compliant = $false
            $ActiveNoArpInspect = $ActiveVLANs
            $CiscoCmdFound += "NOT Found:`t`t`t`t'ip arp inspection vlan <user-vlans>'" | Out-String
        }

        $FindingDetails += $CiscoCmdFound
        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "DHCP Snooping VLANs:`t`t$(($SnoopingVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "ARP Inspection VLANs:`t`t$(($ArpInspectVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "All active access VLANs have DAI enabled." | Out-String
        }
        Else {
            $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "DHCP Snooping VLANs:`t`t$(($SnoopingVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "ARP Inspection VLANs:`t`t$(($ArpInspectVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            If ($ArpInspectNoSnoop) {
                $Status = "Open"
                $FindingDetails += "" | Out-String
                $FindingDetails += "The following VLANs have DAI configured but not DHCP snooping which is a dependency [finding]:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "DAI without Snooping:`t$(($ArpInspectNoSnoop | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            }
            If ($ActiveNoArpInspect) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if any of the below are user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "VLANs without DAI:`t$(($ActiveNoArpInspect | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220662 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220662
        STIG ID    : CISC-L2-000160
        Rule ID    : SV-220662r648766_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000001
        Rule Title : The Cisco switch must have Storm Control configured on all host-facing switchports.
        DiscussMD5 : 08F946B5EDD028D508AF047F74E132CA
        CheckMD5   : 62DD8E608E587959AFF8BA237046833E
        FixMD5     : F140B20E1D21E60A9359652A9A203DE3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $CompliantInt = @()
    $NonCompliantInt = @()

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        If ($Interface -like "*Gigabit*" -or $Interface -like "*tengigabitethernet") {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            If ($InterfaceConfig -match "^switchport mode trunk") {
                # trunk ports are not host-facing
                Switch -Regex ($InterfaceConfig) {
                    "^switchport mode trunk" {
                        $FirstMatchingString = $Matches[0]
                        $CompliantInt += $Interface.ToString().Trim()
                        If ($InterfaceConfig -like "description*") {
                            $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"}).ToString().Trim()
                        }
                        $CompliantInt += " " + $FirstMatchingString.ToString().Trim() + " (storm-control not required)"
                        $CompliantInt += ""
                    }
                }
            }
            ElseIf ($InterfaceConfig -match "^storm-control broadcast level \d+" -or $InterfaceConfig -match "^storm-control broadcast level bps \d+") {
                Switch -Regex ($InterfaceConfig) {
                    "^storm-control broadcast level \d+" {
                        $FirstMatchingString = $Matches[0]
                        $StormCtrlValue = ($FirstMatchingString.ToString()).Split([char[]]"")[3]

                        If ($StormCtrlValue -gt 0 -and $StormCtrlValue -le 100) {
                            $CompliantInt += $Interface.ToString().Trim()
                            If ($InterfaceConfig -like "description*") {
                                $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"}).ToString().Trim()
                            }
                            $CompliantInt += " " + $FirstMatchingString.ToString().Trim()
                            $CompliantInt += ""
                        }
                        Else {
                            $OpenFinding = $True
                            $NonCompliantInt += $Interface.ToString().Trim()
                            If ($InterfaceConfig -like "description*") {
                                $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"}).ToString().Trim()
                            }
                            $NonCompliantInt += "storm-control broadcast level is outside expected parameters of 0-100%"
                            $NonCompliantInt += ""
                        }
                    }
                    "^storm-control broadcast level bps \d+." {
                        $FirstMatchingString = $Matches[0]
                        $StormCtrlValue = ($FirstMatchingString.ToString()).Split([char[]]"")[4]

                        If ($Interface -like "*Gigabit*") {
                            # Gigabit range
                            [Int]$MinRange = 10000000
                            [Int]$MaxRange = 1000000000
                        }
                        Else {
                            # Ten Gigabit range
                            [Int64]$MinRange = 100000000
                            [Int64]$MaxRange = 10000000000
                        }

                        # Normalize the value
                        If ($StormCtrlValue -match "^\d+$") {
                            $StormCtrlValue = [Int]$StormCtrlValue
                        }
                        Switch ($StormCtrlValue) {
                            { $_ -like "*k" } {
                                $StormCtrlValue = [Int]$StormCtrlValue.Replace("k", "") * 1000
                            }
                            { $_ -like "*m" } {
                                $StormCtrlValue = [Int]$StormCtrlValue.Replace("m", "") * 1000000
                            }
                            { $_ -like "*g" } {
                                $StormCtrlValue = [Int]$StormCtrlValue.Replace("g", "") * 1000000000
                            }
                        }

                        If ($StormCtrlValue -ge $MinRange -and $StormCtrlValue -le $MaxRange) {
                            $CompliantInt += $Interface.ToString().Trim()
                            If ($InterfaceConfig -like "description*") {
                                $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"}).ToString().Trim()
                            }
                            $CompliantInt += " " + $FirstMatchingString.ToString().Trim()
                            $CompliantInt += ""
                        }
                        Else {
                            $OpenFinding = $True
                            $NonCompliantInt += $Interface.ToString().Trim()
                            If ($InterfaceConfig -like "description*") {
                                $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"}).ToString().Trim()
                            }
                            $NonCompliantInt += " " + $FirstMatchingString.ToString().Trim() + ' - NON-COMPLIANT'
                            $NonCompliantInt += ""
                        }
                    }
                }
            }
            Else {
                # no match so storm-control for broadcast is NOT configured
                $OpenFinding = $True
                $NonCompliantInt += $Interface.ToString().Trim()
                If ($InterfaceConfig -like "description*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"}).ToString().Trim()
                }
                $NonCompliantInt += "storm-control broadcast level NOT CONFIGURED"
                $NonCompliantInt += ""
            }
        }
        Else {
            $OpenFinding = $True
            $NonCompliantInt += $Interface.ToString().Trim()
            If ($InterfaceConfig -like "description*") {
                $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"}).ToString().Trim()
            }
            $NonCompliantInt += "Interface is not supported"
            $NonCompliantInt += ""
        }
    }

    If ($CompliantInt) {
        $FindingDetails += "Compliant Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt -join "`n" | Out-String
        $FindingDetails += "" | Out-String
    }

    If ($NonCompliantInt) {
        $FindingDetails += "Review the switch configuration below and verify that interfaces are not host facing, make finding determinitation based on STIG check guidance:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces" | Out-String
        $FindingDetails += "---------------" | Out-String
        $FindingDetails += $NonCompliantInt -join "`n" | Out-String
    }

    If (-Not($OpenFinding)) {
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

Function Get-V220663 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220663
        STIG ID    : CISC-L2-000170
        Rule ID    : SV-220663r929005_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000002
        Rule Title : The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
        DiscussMD5 : 12C9D548B2EC855884201C0650FF9D12
        CheckMD5   : 4E9F5CD5F98E951B5D07A1C0015E5C17
        FixMD5     : CB857F07BD0E760BDE2A85091FAE00AE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $ActiveVLANs = @() # Inventory of VLANs assigned to active switchports
    $CiscoCmdFound = "" # Cisco commands per STIG

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If ($InterfaceConfig -like "switchport access vlan*") {
                $AccessVLAN = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3]
                If ($AccessVLAN -notin $ActiveVLANs) {
                    # Add active VLAN to inventory
                    $ActiveVLANs += [int]$AccessVLAN
                }
            }
            Else {
                If ("1" -notin $ActiveVLANs) {
                    # Add default VLAN to inventory
                    $ActiveVLANs += [int]1
                }
            }
        }
    }

    $Compliant = $true
    $NoIpIgmpSnoopLine = ($ShowRunningConfig | Select-String -Pattern "^no ip igmp snooping`$" | Out-String).Trim()
    If ($NoIpIgmpSnoopLine) {
        $Compliant = $false
        $CiscoCmdFound += "Found:`t`t`t`t`t'$($NoIpIgmpSnoopLine)' [finding]" | Out-String
    }
    Else {
        $CiscoCmdFound += "NOT Found:`t`t`t`t'no ip igmp snooping'" | Out-String
    }

    $NoIpIgmpSnoopVlanLine = ($ShowRunningConfig | Select-String -Pattern "^no ip igmp snooping vlan .*" | Out-String).Trim()
    If ($NoIpIgmpSnoopVlanLine) {
        $Compliant = $false
        $CiscoCmdFound += "Found:`t`t`t`t`t'$($NoIpIgmpSnoopVlanLine)' [finding]" | Out-String
    }
    Else {
        $CiscoCmdFound += "NOT Found:`t`t`t`t'no ip igmp snooping vlan <vlan>'" | Out-String
    }

    $FindingDetails += $CiscoCmdFound
    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "IGMP snooping is enabled on all VLANs" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "IGMP snooping is NOT enabled for all VLANs" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220664 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220664
        STIG ID    : CISC-L2-000180
        Rule ID    : SV-220664r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000003
        Rule Title : The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.
        DiscussMD5 : 1E6A4E97F703C160564E7473275F90CC
        CheckMD5   : 491211EE657C6DB1E5E2A652574F6192
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

Function Get-V220665 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220665
        STIG ID    : CISC-L2-000190
        Rule ID    : SV-220665r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000004
        Rule Title : The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
        DiscussMD5 : D229039FB1EDE59283095AED5157DDBC
        CheckMD5   : E5EBFB1C441E34FB2EAE3350E10E2621
        FixMD5     : 486CD48786EFF8078D850A6111757A39
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $GlobalUDLD = $ShowRunningConfig | Select-String -Pattern "^udld enable"
    IF ($GlobalUDLD) {
        $FindingDetails += "Unidirection Link Detection (UDLD)" | Out-String
        $FindingDetails += "----------------------------------" | Out-String
        $FindingDetails += "$GlobalUDLD" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $CompliantInt = @()
        $NonCompliantInt = @()
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "shutdown")) {
                IF ($InterfaceConfig -like "udld port*") {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -like "udld port*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "udld port*"} | Out-String).Trim()
                    }
                    $CompliantInt += " "
                }
                Else {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += " Unidirectional Link Detection is not configured"
                    $NonCompliantInt += ""
                }
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review interfaces below and ensure that none of the interfaces have fiber optic interconnections with neighbors; make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "UDLD Disabled Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
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

Function Get-V220666 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220666
        STIG ID    : CISC-L2-000200
        Rule ID    : SV-220666r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000005
        Rule Title : The Cisco switch must have all trunk links enabled statically.
        DiscussMD5 : 11BF6C81F04B646088CDA0E1FA8C1CDB
        CheckMD5   : 09A7B52A41D46E11EED4B2C0E9A33A09
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    $ActiveTrunkSwitchPorts = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport mode trunk") {
            $ActiveTrunkSwitchPorts += $Interface
        }
    }

    IF ($ActiveTrunkSwitchPorts) {
        ForEach ($Interface in $ActiveTrunkSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "switchport nonegotiate") {
                $CompliantInt += ($Interface | Out-String).Trim()
                $CompliantInt += " " + ($InterfaceConfig | Select-String -Pattern "^switchport mode trunk" | Out-String).Trim()
                $CompliantInt += " " + ($InterfaceConfig | Select-String -Pattern "^switchport nonegotiate" | Out-String).Trim()
                $CompliantInt += ""
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active trunk switchports configured on this switch" | Out-String
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

Function Get-V220667 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220667
        STIG ID    : CISC-L2-000210
        Rule ID    : SV-220667r991904_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000007
        Rule Title : The Cisco switch must have all disabled switch ports assigned to an unused VLAN.
        DiscussMD5 : 225620DA2F853DE034CA2A8DB3D8CDAB
        CheckMD5   : 2B1DAF048AA48F82E574669D3D2FFDB8
        FixMD5     : B43F9760182ECCF6A2980FE16084CFAD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Non8021xInterfaces = @()
    $NAInterfaces = @()
    $AllTrunkVLANs = @()
    $InterfaceResults = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    $VlanStartString = "^VLAN\s+Name\s+Status\s+Ports"
    $VlanEndString = "^VLAN\s+Type\s+SAID\s+MTU\s+Parent RingNo\s+BridgeNo\s+Stp\s+BrdgMode\s+Trans1\s+Trans2"
    $VlanStartIndex = ($ShowTech | Select-String $VlanStartString).LineNumber
    $VlanEndIndex = ($ShowTech | Select-String $VlanEndString).LineNumber
    IF ($VlanStartIndex -ne $null -and $VlanEndIndex -ne $null) {
        $ShowVlan = $ShowTech | Select-Object -Index (($VlanStartIndex + 1)..($VlanEndIndex - 3))
    }
    $ShowVlanPSO = New-Object System.Collections.Generic.List[System.Object]
    $TrunkstartSTR = "^Port\s+Vlans\sallowed\son\strunk"
    $TrunkstartIndex = ($ShowTech | Select-String $TrunkstartSTR).LineNumber
    IF ($TrunkstartIndex) {
        $TrunkEndIndex = $TrunkstartIndex
        DO {
            $TrunkEndIndex++
        }
        Until ($ShowTech[$TrunkEndIndex] -match "")
        $ShowInterfacesTrunk = $ShowTech | Select-Object -Index (($TrunkstartIndex - 1)..($TrunkEndIndex))

        ForEach ($Trunk in ($ShowInterfacesTrunk | Select-Object -Skip 1)) {
            IF ($Trunk) {
                $Interface = (-split $Trunk)[0]
                $TrunkVlans = (-split $Trunk)[1].Split(",")

                ForEach ($TVlan in $TrunkVlans) {
                    IF ($TVlan -like "*-*") {
                        $DashIndex = $TVlan.IndexOf("-")
                        $StartInt = $TVlan.Substring(0, $DashIndex)
                        $EndInt = $TVlan.Substring($DashIndex + 1)
                        $AllTrunkVLANs += $StartInt..$EndInt
                    }
                    ELSE {
                        $AllTrunkVLANs += $TVlan
                    }
                }
            }
        }
    }

    ForEach ($Vlan in $ShowVLan) {
        IF (!(($Vlan -split '\s{2,}')[0])) {
            $ShowVlanPSO = @()
            IF ($ShowVlanPSO.Count -eq 0) {
                continue
            }
            ELSE {
                $Ports = $ShowVlanPSO[$ShowVlanPSO.Count - 1].Ports
                $AdditionalPorts = ($Vlan -split '\s{2,}')[1]
                $UpdatedPorts = $Ports + $AdditionalPorts
                $ShowVlanPSO[$ShowVlanPSO.Count - 1].Ports = $UpdatedPorts
            }
        }
        ELSE {
            IF ($ShowVlanPSO.Count -eq 0) {
                continue
            }
            ELSE {
                $NewVlanObj = [PSCustomObject]@{
                    VLAN   = ($Vlan -split '\s+')[0]
                    Name   = (($Vlan -split '\s+', 2)[1] -split '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)')[0].Trim()
                    Status = (($Vlan | Select-String '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)').Matches).Value
                    Ports  = ($Vlan -split '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)')[1].Trim()
                }
                $ShowVlanPSO.Add($NewVlanObj)
            }
        }
    }

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF ($InterfaceConfig -contains "shutdown" -AND $InterfaceConfig -match "switchport (mode)?\s?access" -AND !($InterfaceConfig -contains "dot1x pae authenticator")) {
            $Non8021xInterfaces += $Interface
        }

        IF ($InterfaceConfig -contains "shutdown" -AND $InterfaceConfig -match "switchport (mode)?\s?access" -AND $InterfaceConfig -contains "dot1x pae authenticator") {
            $NAInterfaces += ($Interface | Out-String).Trim()
            IF ($InterfaceConfig -like "description*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -contains "switchport mode access") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -like "switchport access vlan*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"})
            }
            IF ($InterfaceConfig -like "shutdown*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "shutdown*"} | Out-String).Trim()
            }
            $NAInterfaces += ""
        }
    }

    IF ($Non8021xInterfaces) {
        ForEach ($Interface in $Non8021xInterfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $InterfaceResults += ($Interface | Out-String).Trim()
            $InterfaceResults += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            #$VLAN = ( -split ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" ))[3]
            # New code
            $VlanLine = $InterfaceConfig | Select-String -Pattern "^switchport access vlan.*"
            IF ($VlanLine) {
                $VLAN = (-split $VlanLine)[3]
            } ELSE {
                $VLAN = $null
            }
            # End of new code
            IF (($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status -eq "act/lshut" -AND $Vlan -notin $AllTrunkVLANs) {
                $InterfaceResults += " " + ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" | Out-String).Trim()
            }
            ELSE {
                $OpenFinding = $True
                $InterfaceResults += " " + ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" | Out-String).Trim()
                IF (!(($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status -eq "act/lshut")) {
                    $InterfaceResults += "  VLAN Status For VLAN " + $VLAN + ": " + ($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status + " - NON-COMPLIANT"
                }
                IF ($Vlan -in $AllTrunkVLANs) {
                    $InterfaceResults += "  VLAN $VLAN is allowed on trunk links"
                }
            }
            $InterfaceResults += " " + ($InterfaceConfig | Select-String -patter "^shutdown$" | Out-String).Trim()
            $InterfaceResults += ""
        }

        $FindingDetails += "Inactive VLANs:" | Out-String
        $FindingDetails += ($ShowVlanPSO | Where-Object {$_.Status -ne "active"} | Select-Object VLAN, Name, STATUS | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "Trunk Ports:" | Out-String
        $FindingDetails += IF ($ShowInterfacesTrunk) {
            ($ShowInterfacesTrunk | Out-String)
        }
        ELSE {
            ("Trunk ports not configured" | Out-String).Trim()
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "Shutdown Interfaces (without 802.1x)" | Out-String
        $FindingDetails += "-------------------------------------" | Out-String
        $FindingDetails += ($InterfaceResults | Out-String).Trim()
        IF ($OpenFinding) {
            $Status = "Open"
        }
        ELSE {
            $Status = "NotAFinding"
        }
    }
    ELSE {
        $FindingDetails += "All shutdown switchport mode access VLANs are managed by 802.1x" | Out-String
        $FindingDetails += "Switch ports configured for 802.1x are exempt from this requirement." | Out-String
        $FindingDetails += "" | Out-String
        IF ($NAInterfaces) {
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "-----------" | Out-String
            $FindingDetails += $NAInterfaces -join "`n" | Out-String
        }
        $Status = "Not_Applicable"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220668 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220668
        STIG ID    : CISC-L2-000220
        Rule ID    : SV-220668r991905_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000008
        Rule Title : The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
        DiscussMD5 : CC13E41763978069BFB299C68B65A154
        CheckMD5   : F476375DE9FDA75252B696D5703DB207
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $SwitchPortVLAN = $InterfaceConfig | Select-String -Pattern "^switchport access .*"
            IF ($SwitchPortVLAN) {
                IF (($SwitchPortVLAN | Out-String).Trim().Split([char[]]"")[3] -eq "1") {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $NonCompliantInt += " " + ($SwitchPortVLAN | Out-String).Trim()
                    $NonCompliantInt += ""
                }
                Else {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $CompliantInt += " " + ($SwitchPortVLAN | Out-String).Trim()
                    $CompliantInt += ""
                }
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                $NonCompliantInt += "switch port access vlan not configured, switchport will default to VLAN 1"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces " | Out-String
            $FindingDetails += "---------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces " | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220669 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220669
        STIG ID    : CISC-L2-000230
        Rule ID    : SV-220669r991906_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000009
        Rule Title : The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
        DiscussMD5 : 338F8B6991B345E3A5A323147021041A
        CheckMD5   : C2F2F0BC729950111E64707DCB1CF0F2
        FixMD5     : 557326D03F6FC5762202F76A1EB7A126
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V220670 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220670
        STIG ID    : CISC-L2-000240
        Rule ID    : SV-220670r991907_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-L2S-000010
        Rule Title : The Cisco switch must not use the default VLAN for management traffic.
        DiscussMD5 : 8C62CF7A41941A44EFC29FDDA49EFD40
        CheckMD5   : D90FDB909EABE1A307BDAB48F5B04BEA
        FixMD5     : 9DD1285EDD75AAC6CF95B1146D17EB13
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Vlan1 = ($ShowRunningConfig | Select-String -Pattern "^interface vlan1$" | Out-String).Trim()
    $DefaultVLan = Get-Section $ShowRunningConfig "$Vlan1"
    IF ($DefaultVLan -contains "shutdown" -AND $DefaultVLan -contains "no ip address") {
        $FindingDetails += $Vlan1 | Out-String
        $FindingDetails += $DefaultVLan | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration below and verify that the default VLAN is not used to access the switch for management." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $Vlan1 | Out-String
        $FindingDetails += $DefaultVLan | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220671 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220671
        STIG ID    : CISC-L2-000250
        Rule ID    : SV-220671r991908_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000011
        Rule Title : The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
        DiscussMD5 : 6F8F274B359BEF8A81A9ACBBDEEC588F
        CheckMD5   : E61E77F6FBB329C07A7837AB2EFAA48C
        FixMD5     : 68D38CA681E1501831A7110FB42D8C1F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $TrunkInterfaces = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown")) {
            IF ($InterfaceConfig -contains "switchport mode trunk") {
                $TrunkInterfaces += ($Interface | Out-String).Trim()
                $TrunkInterfaces += ($InterfaceConfig | Out-String).Trim()
                $TrunkInterfaces += ""
            }
        }
    }

    IF ($TrunkInterfaces) {
        $FindingDetails += "Review switch configuration below and determine if any interfaces are user-facing or untrusted switchports." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Trunk Interfaces" | Out-String
        $FindingDetails += "------------------------" | Out-String
        $FindingDetails += $TrunkInterfaces | Out-String
    }
    Else {
        $FindingDetails += "There are no trunk interfaces on this switch" | Out-String
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

Function Get-V220672 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220672
        STIG ID    : CISC-L2-000260
        Rule ID    : SV-220672r991909_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000012
        Rule Title : The Cisco switch must have the native VLAN assigned to an ID other than the default VLAN for all 802.1q trunk links.
        DiscussMD5 : 5C7174907755B77D7ECA1434D7B54A6D
        CheckMD5   : B45514755376BB74865CC68F2DDCA053
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

Function Get-V220673 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220673
        STIG ID    : CISC-L2-000270
        Rule ID    : SV-220673r991910_rule
        CCI ID     : CCI-004891
        Rule Name  : SRG-NET-000512-L2S-000013
        Rule Title : The Cisco switch must not have any switchports assigned to the native VLAN.
        DiscussMD5 : AC50A426EC1059E53A9F11F6E08EBE66
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBOqC7lzw4IMqmW
# eYjIyrXNc7PlE28R5ae1Ug94BxRxvaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCAKG4NhCWC9QGMYqgjFgd8z0xh/pUv02y+I6v9uh1D5rTANBgkqhkiG9w0BAQEF
# AASCAQCCO1qR7k1eCEy/ER+OZHg82/ockAAJynzkhslHuNSyShOjVEyTg+6ZS0kS
# bA1SwIYjqC/KHA1YEhNfUStYpB9Dk9dedAm2FCJqI/CG3AFIdwbn5MkJh9FENrys
# F5VFer6nwfo7O/+EkiBrgtVCsINYuxXz+Zm4xol4t6roU8w/p9sowKkknTd3l/Iz
# BwW6px4CfNFXngS7n5R9adqGF+g1WHWomKx3SeZGV+b7ljm+4QsXLGIeW60clXtP
# 4tIvk0LZnGekX6oRJbCNSRaKETEuelvhGTxV0afxnyck5c2RbwtjbW9b/zcKt/Wf
# iDiK2yHYfMDTyv8po1SmAW8dTzC0oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTAxM1owLwYJKoZIhvcNAQkEMSIEIFrwHCgBNmR/kOZJbQH8LJ+qAMXh
# eXGK6KjuUW2fLoNkMA0GCSqGSIb3DQEBAQUABIICAHm8q2i+kWY5u1ZO66NrcmRI
# WY4sjYkxZtU38AEFWmT0df3FiGPplRUchtr+wN1KPg8ml13gM9RQxbu6/6dzVMEg
# 8B3OGvk9ympsRVrgai6IOy29KSXUyD8NKcJhDWyNCPCSmg53wv7ZhIa6UmHYiJ17
# PaHUJQ39UdigNyYWtZVKCUnKcUSKOyEiKwCISnfaZf+Y2NJSfywisEpJXE+wibgY
# XU2IzPqzhtfqxpO/HdBC4RUZacHa64jBtr6qy6XGLNLI/1LC9kExRsdBG1OwUa/A
# oE2b/0ijI5hiATeglE6ZLMVlkqHNWCsWiMWBMUPK2J93+3CnilRdKr67g0L2vTCf
# 9CMq0VP9qF5WtgOZZ4eR6+4h6E4esWWmlMV3H1Z/WuERVcE4jVQVL55QCXBMdewy
# 76Qt7rCPhWHS9JWpDO73MHdqmkJCiNxXfGdts5RoRhtmHFHuXujmiBGt6Haq+f7J
# THpU9PI9brT/qkN7ytnjJFXOkAPjzqkH030zi4wobJQ8UzlUmVSIvSlZs09mt7Oa
# YjVg3WOlZnodXAzxWwjkGg2xmkAGrKJKHeI4GftcMDYDMq+vEZT1/WaELStpm1Xk
# bOt4Hlzba7fQF0qTka0X0U+eJPufuCxMQH4pDlDcxRaVRYjFviuqD4YwE3QffvYa
# +8QRdbMPM7ZcLp7kzScK
# SIG # End signature block
