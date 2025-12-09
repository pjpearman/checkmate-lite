##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS Switch RTR
# Version:  V3R1
# Class:    UNCLASSIFIED
# Updated:  10/7/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V220419 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220419
        STIG ID    : CISC-RT-000010
        Rule ID    : SV-220419r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000001
        Rule Title : The Cisco switch must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.
        DiscussMD5 : 8219800AE6B5A7B3DF3732757D66DBFF
        CheckMD5   : 6D0CC3D00F65CDF38CB2A47630AA1554
        FixMD5     : 6BF97C5971572AD520B119525684E0FA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip access-group *")) {
            # Add interface without an inbound or outbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below interface requires an Access Control List (ACL) to allow or deny traffic for specific source and destination addresses as well as ports and protocols and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "Interface without an ACL configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            $ACLName = ($InterfaceConfig | Select-String -Pattern "ip access-group .*").ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            IF (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "ACL $ACLName under $Interface is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify that the ACL $ACLName under $Interface is configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "ACL $ACLName entries:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += ($ACLConfig | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
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

Function Get-V220423 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220423
        STIG ID    : CISC-RT-000050
        Rule ID    : SV-220423r929046_rule
        CCI ID     : CCI-000803, CCI-002205
        Rule Name  : SRG-NET-000168-RTR-000078
        Rule Title : The Cisco switch must be configured to enable routing protocol authentication using FIPS 198-1 algorithms with keys not exceeding 180 days of lifetime.
        DiscussMD5 : 87FE0A00E795631BFE3EE27302A89E07
        CheckMD5   : 9EC4A6050023EA1B5CA7495B206E55F2
        FixMD5     : BBBC361B26B8568137EE4A450C5DB05B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Check if keys are configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^key chain")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Key chain is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    ELSE {
        $KeyChains = $ShowRunningConfig | Select-String -Pattern "^key chain*"
        ForEach ($KeyChain in $KeyChains) {
            $KeyChainConfig = Get-Section $ShowRunningConfig $KeyChain.ToString()
            # Add key chain configuration to Finding Details
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the key chain configuration to verify the FIPS 198-1 algorithm and to determine if the key lifetime does not exceed 180 days and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($KeyChain.ToString() | Out-String).Trim()
            IF ($KeyChainConfig) {
                $FindingDetails += "" | Out-String
                $FindingDetails += ($KeyChainConfig | Out-String).Trim()
            }
            $FindingDetails += "" | Out-String
            $Exception = $True 
        }
    }
    
    # Check if RIP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router rip")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "RIP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String    
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "RIP is configured on this device and only supports MD5. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    # Check if EIGRP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router eigrp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "EIGRP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String    
    }
    ELSE {
        $RouterEigrp = $ShowRunningConfig | Select-String -Pattern "^router eigrp*"
        $RouterEigrpConfig = Get-Section $ShowRunningConfig $RouterEigrp.ToString()
        # Check if EIGRP authentication is configured
        $EigrpAuth = $RouterEigrpConfig | Select-String -Pattern "authentication mode hmac.*"
        IF ($EigrpAuth) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "EIGRP authentication using FIPS 198-1 algorithms is configured on this device, make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "---------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $RouterEigrp | Out-String
            $FindingDetails += $RouterEigrpConfig | Out-String
            $Exception = $True
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "EIGRP authentication using FIPS 198-1 algorithms is not configured on this device. This is a finding." | Out-String
            $FindingDetails += $RouterEigrp | Out-String
            $FindingDetails += $RouterEigrpConfig | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }

    # Check if IS-IS is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router isis")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IS-IS is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String    
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IS-IS is configured on this device and only supports MD5. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    # Check if OSPF is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router ospf")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "OSPF is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String    
    }
    ELSE {
        $RouterOspf = $ShowRunningConfig | Select-String -Pattern "^router ospf*"
        $RouterOspfConfig = Get-Section $ShowRunningConfig $RouterOspf.ToString()
        # Check if OSPF authentication is configured
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
        $InterfaceConfig = @()
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $KeyChainName = ($InterfaceConfig | Select-String -Pattern "ip ospf authentication key-chain*" | Out-String).Trim().Split([char[]]"")[-1]
            IF ($InterfaceConfig | Select-String -Pattern "ip ospf authentication key-chain*") {
                # Add compliant interface to Finding Details
                $FindingDetails += "" | Out-String
                $FindingDetails += "OSPF authentication is configured on the below interface:" | Out-String
                $FindingDetails += "---------------------------------------------------------" | Out-String
                $FindingDetails += ("interface $Interface" | Out-String).Trim()
                IF ($InterfaceConfig) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += ($InterfaceConfig | Select-String -Pattern "ip ospf authentication key-chain*" | Out-String).Trim()
                    IF (!($ShowRunningConfig | Select-String -Pattern "^key chain $KeyChainName")) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Key Chain $KeyChainName is not configured on this device." | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                $FindingDetails += "" | Out-String
            }
            Else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "OSPF authentication is not configured on interface $Interface." | Out-String
                $FindingDetails += "" | Out-String    
                $OpenFinding = $True
            }
        }
    }
    
    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get main BGP table configuration.
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        $BgpConfig = @()
        ForEach ($Entry in $RouterBgpConfig) {
            $NewBgpConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "address-family ipv4") {
                Break
            }
        }
        IF ($NewBgpConfig) {
            $NewBgpConfig = ($NewBgpConfig -split "[\r\n]+")
            # Check for BGP authentication on the main BGP table.
            IF ($NewBgpConfig | Select-String -Pattern "neighbor .* ao") {
                # Add compliant BGP Neighbors to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Review the BGP authentication configuration on the main BGP table:" | Out-String
                $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($NewBgpConfig | Select-String -Pattern "neighbor .* ao" | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $KeyChainBGP = ($NewBgpConfig | Select-String -Pattern "neighbor .* ao" | Out-String)
                $KeyChainBGP = ($KeyChainBGP -split "[\r\n]+") | Where-Object { $_ -ne "" }
                ForEach ($Item in $KeyChainBGP) {
                    $KeyChain = $Item.Trim().Split([char[]]"")[-1]
                    IF (!($ShowRunningConfig | Select-String -Pattern "^key chain $KeyChain")) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Key Chain $KeyChain is not configured on this device." | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                $OpenFinding = $True
            }
            ELSE {
                $FindingDetails += "" | Out-String
                $FindingDetails += "BGP authentication is not configured on the main BGP table." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True    
            }
        }
    
        #Get BGP VRFs configuration.
        $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
        ForEach ($Item in $RouterBgpVrf) {
            $RouterBgpVrfConfig += ($Item | Out-String).Trim()
            $RouterBgpVrfConfig += "" | Out-String
            $RouterBgpVrfConfig += (Get-Section $ShowRunningConfig $Item.ToString() | Out-String).Trim()
            $RouterBgpVrfConfig += "" | Out-String
            IF ($RouterBgpVrfConfig) {
                $RouterBgpVrfConfig = ($RouterBgpVrfConfig -split "[\r\n]+")
                Break
            }
        }
    
        # Check for BGP authentication on each VRF.
        ForEach ($Entry in $RouterBgpVrfConfig) {
            # Get config from BGP VRF.
            $NewBgpVrfConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "exit-address-family") {
                $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                # Check for BGP authentication on the VRFs.
                IF ($NewBgpVrfConfig | Select-String -Pattern "neighbor .* ao") {
                    # Add compliant BGP Neighbors to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review the BGP authentication configuration on VRF ${Vrf}:" | Out-String
                    $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += ($NewBgpVrfConfig | Select-String -Pattern "neighbor .* ao" | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                    $KeyChainVrfBGP = ($NewBgpVrfConfig | Select-String -Pattern "neighbor .* ao" | Out-String)
                    $KeyChainVrfBGP = ($KeyChainVrfBGP -split "[\r\n]+") | Where-Object { $_ -ne "" }
                    ForEach ($Item in $KeyChainVrfBGP) {
                        $KeyChainVrf = $Item.Trim().Split([char[]]"")[-1]
                        IF (!($ShowRunningConfig | Select-String -Pattern "^key chain $KeyChainVrf")) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Key Chain $KeyChainVrf is not configured on this device." | Out-String
                            $FindingDetails += "" | Out-String
                        }
                    }
                }
                ELSE {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "BGP VRF authentication is not configured on VRF $Vrf." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True    
                }
                IF ($NewBgpVrfConfig) {
                    Clear-Variable -Name "NewBgpVrfConfig"
                }
                continue
            }
        }
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

Function Get-V220424 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220424
        STIG ID    : CISC-RT-000060
        Rule ID    : SV-220424r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000007
        Rule Title : The Cisco switch must be configured to have all inactive Layer 3 interfaces disabled.
        DiscussMD5 : 4F2E9D52B6440EDFA5EFA782FD5A1B33
        CheckMD5   : C4FC8DB3DFD55ED2B3AD2613061D4F11
        FixMD5     : 1BB2ACAF63E377F3A38D2F06E3AA0F87
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $OpenFinding = $False

        If ($InterfaceConfig -notcontains "shutdown"){
            $OpenFinding = $True
        }
        If ($InterfaceConfig -notcontains "no switchport"){
            $OpenFinding = $True
        }

        if ($OpenFinding){
            $Status = "Not_Reviewed"
            $FindingDetails += "This interface is not disabled and appears still active. Review the interface configuration and verify that this interface is still in active use. Any inactive interfaces must be disabled." | Out-String
            $FindingDetails += "---------------------------------------- Interface Configuration ----------------------------------------"
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
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

Function Get-V220427 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220427
        STIG ID    : CISC-RT-000090
        Rule ID    : SV-220427r856231_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000109
        Rule Title : The Cisco switch must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.
        DiscussMD5 : DE8491522A4956F725339F3D14CCB5A5
        CheckMD5   : 87A4C062B520033CA443800D25EC67D5
        FixMD5     : 24455DB8D6DB60294DC9BFA2F9A18858
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF ($ShowRunningConfig | Select-String -Pattern "^service config") {
        $FindingDetails += "" | Out-String
        $FindingDetails += "'service config' is configured on this device." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $true
    }
    
    $BootConfig = $ShowRunningConfig | Select-String -Pattern "^boot"
    ForEach ($Item in $BootConfig) {
        IF ($Item.ToString() -contains "boot-start-marker" -or $Item.ToString() -contains "boot-end-marker" -or $Item.ToString() -like "boot network tftp*") {
                # Add non-compliant configuration to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Review the device configuration to verify that auto-configuration is not configured on this device." | Out-String
                $FindingDetails += "Non-Compliant Configuration:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += ($Item.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
        }
    }
    
    $CnsConfig = $ShowRunningConfig | Select-String -Pattern "^cns"
    ForEach ($Item in $CnsConfig) {
        IF ($Item.ToString() -contains "cns image" -or $Item.ToString() -like "cns exec*" -or $Item.ToString() -like "cns config initial*" -or $Item.ToString() -like "cns trusted-server config*" -or $Item.ToString() -like "cns trusted-server image*") {
                # Add non-compliant configuration to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Review the device configuration to verify that CNS zero touch is not configured on this device." | Out-String
                $FindingDetails += "Non-Compliant Configuration:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += ($Item.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
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

Function Get-V220428 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220428
        STIG ID    : CISC-RT-000120
        Rule ID    : SV-220428r991872_rule
        CCI ID     : CCI-001097, CCI-002385, CCI-004866
        Rule Name  : SRG-NET-000362-RTR-000110
        Rule Title : The Cisco switch must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by employing control plane protection.
        DiscussMD5 : B5F6E45D5BC4A26AA0640B36C1A997AB
        CheckMD5   : 3842CE3EEE1E47EEFEB5ED2D6E51C438
        FixMD5     : 01377EEE8F41E7113C7CCB972614A442
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ControlPlaneFlag = $True
    $CppPolicyFlag = $True

    $ClassMapConfig = @()
    $CompliantConfig = @()
    $UncompliantConfig = @()

    # Get class-map configurations
    $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map match-*"
    IF ($ClassMaps) {
        ForEach ($ClassMap in $ClassMaps) {
            $ClassMapConfig = Get-Section $ShowRunningConfig $ClassMap.ToString() | Select-String -Pattern "match access-group name"
            # Get access-lists referenced by class-maps
            IF ($ClassMapConfig | Select-String -Pattern "match access-group name") {
                $ACL = ($ClassMapConfig | Select-String -Pattern "match access-group name").ToString().Split([char[]]"")[-1]
                $CompliantConfig += $ClassMap.ToString()
                $CompliantConfig += $ClassMapConfig.ToString()
                $CompliantConfig += "" | Out-String

                IF (Get-Section $ShowRunningConfig "ip access-list extended $ACL") {
                    $ACLConfig = Get-Section $ShowRunningConfig "ip access-list extended $ACL"
                    $CompliantConfig += ("ip access-list extended $ACL" | Out-String).Trim()
                    $CompliantConfig += ($ACLConfig | Out-String).Trim()
                    $CompliantConfig += "" | Out-String
                }
                ELSE {
                    $CompliantConfig += ("ip access-list extended $ACL is not configured on this device." | Out-String).Trim()
                    $CompliantConfig += "" | Out-String
                }
            }
            ELSE {
                $UncompliantConfig += $ClassMap.ToString()
            }
        }

        # Add class-maps to FindingDetails
        IF ($CompliantConfig) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the following class-maps and access-lists to verify if traffic types have been classified based on importance levels for Control Plane Protection and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            ForEach ($line in $CompliantConfig) {
                $FindingDetails += $line | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        IF ($UncompliantConfig) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The following class-maps don't have an access-lists attached:" | Out-String
            $FindingDetails += "-------------------------------------------------------------" | Out-String
            ForEach ($line in $UncompliantConfig) {
                $FindingDetails += $line | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        $Exception = $True
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have class-maps configured for Control Plane Protection." | Out-String
        $OpenFinding = $True
    }

    # Verify CoPP is enabled
    IF ($ShowRunningConfig | Select-String -Pattern "^control-plane") {
        $CoPPConfig = Get-Section $ShowRunningConfig "control-plane"
        IF ($CoPPConfig) {
            $PolicyMap = ($CoPPConfig | Select-String -Pattern "service-policy input")
            IF ($PolicyMap) {
                $PolicyMap = ($PolicyMap).ToString().Split([char[]]"")[-1]
                # Add CoPP policy-map to FindingDetails
                $PolicyMapConfig = Get-Section $ShowRunningConfig "policy-map $PolicyMap"
                $FindingDetails += "" | Out-String
                $FindingDetails += "Review the policy-map configuration under 'control-plane' to verify if traffic is being policed appropriately for each classification for Control Plane Protection and make finding determination based on STIG check guidance:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                IF ($PolicyMapConfig) {
                    $FindingDetails += ("policy-map $PolicyMap" | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += ($PolicyMapConfig | Out-String).Trim()
                }
                ELSE {
                    $FindingDetails += ("Policy map $PolicyMap is not configured on this device." | Out-String).Trim()
                    $ControlPlaneFlag = $False
                }
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            ELSE {
                $FindingDetails += "" | Out-String
                $FindingDetails += "This device does not have a policy-map properly configured under 'control-plane'." | Out-String
                $ControlPlaneFlag = $False
            }
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have 'control-plane' configured for Control Plane Protection." | Out-String
        $ControlPlaneFlag = $False
    }

    # Verify if 'policy-map system-cpp-policy' is configured
    IF ($ShowRunningConfig | Select-String -Pattern "^policy-map system-cpp-policy") {
        $CppPolicyMapConfig = Get-Section $ShowRunningConfig "policy-map system-cpp-policy"
        # Add Policy Map to FindingDetails
        IF ($CppPolicyMapConfig) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the policy-map configuration under 'policy-map system-cpp-policy' to verify if traffic is being policed appropriately for each classification for Control Plane Protection and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ("policy-map system-cpp-policy" | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($CppPolicyMapConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device does not have 'policy-map system-cpp-policy' properly configured for Control Plane Protection." | Out-String
            $CppPolicyFlag = $False
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have 'policy-map system-cpp-policy' configured for Control Plane Protection." | Out-String
        $CppPolicyFlag = $False
    }

    IF (!($ControlPlaneFlag) -AND !($CppPolicyFlag)) {
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

Function Get-V220431 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220431
        STIG ID    : CISC-RT-000150
        Rule ID    : SV-220431r856233_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000111
        Rule Title : The Cisco switch must be configured to have gratuitous ARP disabled on all external interfaces.
        DiscussMD5 : 4079563A47158A2AC9D218FA97C791BA
        CheckMD5   : 53C5D56BCE65E5EFD669718010867447
        FixMD5     : 7EF700EB041679FC8BE3A2E7A7DD730B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -contains "no ip gratuitous-arps") {
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify that gratuitous-arps is globally disabled." | Out-String
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

Function Get-V220432 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220432
        STIG ID    : CISC-RT-000160
        Rule ID    : SV-220432r856234_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000112
        Rule Title : The Cisco switch must be configured to have IP directed broadcast disabled on all interfaces.
        DiscussMD5 : FBAA0B696C4AFA315D1CF9DCD2FE8465
        CheckMD5   : 08B5B917AEE0C6B26C087C8981BF25C9
        FixMD5     : 22B9077DC3B3E11E321B75F49972E2F5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        if ($InterfaceConfig -contains "ip directed-broadcast") {
            $OpenFinding = $True
            $Status = "Open"
            $FindingDetails += "Review the switch configuration below and verify that 'ip directed-broadcast' is not enabled on any interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
        }
        
    }
    if (!$OpenFinding){ 
        $FindingDetails += "There are no interfaces with 'ip directed-broadcast' configured on this device."
        $Status = "NotAFinding."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220433 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220433
        STIG ID    : CISC-RT-000170
        Rule ID    : SV-220433r856235_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000113
        Rule Title : The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
        DiscussMD5 : AA3A075D2F7E7680BEECE67D356055DA
        CheckMD5   : 884CB8B3B6AD41E8DDC233574B3CF0BF
        FixMD5     : B3AD49140207952BECC19C1B1551C603
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $UnconfiguredInterfaces = @()
    $OpenFinding = $False
    $GloballyConfigured = $False
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "no ip unreachables") {
            $ConfiguredInterfaces += $Interface
        }
        else {
            if ($Interface -like "*Null*") {
                $FindingDetails += "Internet Control Message Protocol (ICMP) unreachable messages is not disabled on this Null interface. If this Null interface is being utilized to blackhole pockets then ICMP unreachable messages must be disabled via the 'no ip unreachables' command and a route-map, ACL and corresponding policy to forward these ICMP messages to the Null interface must be correctly configured. Review the interface configuration below and verify these steps have been taken." | Out-String
                $FindingDetails += "-------------------- Null Interface Configuration --------------------" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
            }
            $UnconfiguredInterfaces += $Interface
            $OpenFinding = $True
        }
    }

    IF (!($ShowRunningConfig -like "ip icmp rate-limit unreachable *")) {
        $OpenFinding = $True
    }
    else {
        $GloballyConfigured = $True
    }

    if ($OpenFinding){ 
        if ($UnconfiguredInterfaces.count -gt 0) {
            $FindingDetails += "Internet Control Message Protocol (ICMP) unreachable messages must be disabled on all external interfaces. The following interfaces do not have ICMP unreachable messages disabled. Review the interfaces below and verify that none of them are external interfaces. The configuration 'no ip unreachables' must be added to any external interfaces not currently disabling ICMP unreachable messages." | Out-String
            $FindingDetails += "-------------------- Interfaces --------------------" | Out-String
            forEach ($int in $UnconfiguredInterfaces){
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        
        if (!$GloballyConfigured) {
            $FindingDetails += "This switch is not globally configured to rate limit ICMP unreachable messages. Add rate limiting for ICMP unreachable messages via the configuration command: 'ip icmp rate-limit unreachable *'." | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
        else {
            $Status = "Not_Reviwed"
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

Function Get-V220434 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220434
        STIG ID    : CISC-RT-000180
        Rule ID    : SV-220434r856236_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000114
        Rule Title : The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) mask reply messages disabled on all external interfaces.
        DiscussMD5 : 06C6F1BE37F5426916FCDA003136A622
        CheckMD5   : 4DFD33A2A82CEE8EB13F5BE3B532210F
        FixMD5     : 31D616FA328BE5280C3C8F7FD81A999B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OpenFinding = $False
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "ip mask-reply".Trim()) {
            $OpenFinding = $True
            $Status = "Open"
            $FindingDetails += "Review the switch configuration below and verify that 'ip mask-reply' is not enabled on any external interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
        }
    }
    if (!$OpenFinding){ 
        $FindingDetails += "There are no interfaces with 'ip mask-reply' configured on this device."
        $Status = "NotAFinding."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220435 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220435
        STIG ID    : CISC-RT-000190
        Rule ID    : SV-220435r856237_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000115
        Rule Title : The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.
        DiscussMD5 : 9EDE1F6BC31DD8CE1502AD5F7592EFD8
        CheckMD5   : D5BA1C6BB799F3F0EA18447D15586E74
        FixMD5     : 1489BD6AC49820F2D58121A2F2EC4A11
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $count = 0
    $OpenFinding = $False
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"

    ForEach ($Interface in $Interfaces) {
        $TestInterface = $True

        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -contains "no ip address".Trim()) {
            Write-Output "$Interface contains no ip address config."
            $TestInterface = $False
        }
        elseif ($InterfaceConfig -contains "shutdown".Trim()){
            Write-Output "$Interface contains shutdown config."
            $TestInterface = $False
        }

        if ($TestInterface){
            if ($InterfaceConfig -notcontains "no ip redirects".Trim()) {
                $OpenFinding = $True
                $Status = "Open"
                $FindingDetails += "Review the switch interface configuration below and verify that ICMP redirects are disabled if it is an external interface." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $count += 1
            }
        }
    }
    if (!$OpenFinding){ 
        $FindingDetails += "There are no interfaces with ICMP redirects enabled on this device." | Out-String
        $Status = "NotAFinding."
    }
    else {
        $FindingDetails += "$count interfaces flagged." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220436 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220436
        STIG ID    : CISC-RT-000200
        Rule ID    : SV-220436r622190_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-NET-000078-RTR-000001
        Rule Title : The Cisco switch must be configured to log all packets that have been dropped at interfaces via an access control list (ACL).
        DiscussMD5 : FE94D3A3F2DBEE19BA50B5E322FE11F4
        CheckMD5   : E17D90B5C738AA4DD76583962BFA2DB2
        FixMD5     : 1B2FD384D3CE3B9ACEF78681B3CE4CA6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        IF (!($AccessListConfig -like "deny[ ]*ip any any log" -or $AccessListConfig -like "deny[ ]*ip any any log-input")) {
            # Add non-compliant Access List to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the device configuration to verify that ACLs log dropped packets." | Out-String
            $FindingDetails += "ACLs not logging dropped packets:" | Out-String
            $FindingDetails += "---------------------------------" | Out-String
            $FindingDetails += ($AccessList.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
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

Function Get-V220437 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220437
        STIG ID    : CISC-RT-000210
        Rule ID    : SV-220437r622190_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-NET-000076-RTR-000001
        Rule Title : The Cisco switch must be configured to produce audit records containing information to establish where the events occurred.
        DiscussMD5 : B1301209072377F37E19C2042C77AAFF
        CheckMD5   : BBBC50997DD8C56659FAAB0127F8EB88
        FixMD5     : EE530CDBB5E816C620A51D78E908C064
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $CompliantACLs = @()

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        IF ($AccessListConfig -like "deny ip any any log-input") {
            $CompliantACLs += $AccessList
        }
    }

    if ($CompliantACLs.count -gt 0) {
        $FindingDetails += "The Cisco switch must be configured to produce audit records containing information to establish where the events occurred. The following ACLs are compliant. Please review the switch configuration and ensure at least one compliant ACL is applied on every interface." | Out-String
        $FindingDetails += "---------------------------------------- ACLs ----------------------------------------" | Out-String
        ForEach ($int in $CompliantACLs) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "The Cisco switch must be configured to produce audit records containing information to establish where the events occurred but no compliant ACLs match this requirement. Review the switch configurations to ensure `log-input` is configured via an applied ACL on all interfaces to produce audit records containing information to establish where the events occurred." | Out-String
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

Function Get-V220438 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220438
        STIG ID    : CISC-RT-000220
        Rule ID    : SV-220438r622190_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-NET-000077-RTR-000001
        Rule Title : The Cisco switch must be configured to produce audit records containing information to establish the source of the events.
        DiscussMD5 : EEE886CCEB17F9D328BAE53F2CA44B08
        CheckMD5   : 4BEFF0DD7DA0CFE311648A0BB1FF8540
        FixMD5     : EE530CDBB5E816C620A51D78E908C064
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $CompliantACLs = @()

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        IF ($AccessListConfig -like "deny ip any any log-input") {
            $CompliantACLs += $AccessList
        }
    }

    if ($CompliantACLs.count -gt 0) {
        $FindingDetails += "The Cisco switch must be configured to produce audit records containing information to establish the source of the events. The following ACLs are compliant. Please review the switch configuration and ensure at least one compliant ACL is applied on every interface." | Out-String
        $FindingDetails += "---------------------------------------- ACLs ----------------------------------------" | Out-String
        ForEach ($int in $CompliantACLs) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "The Cisco switch must be configured to produce audit records containing information to establish the source of the events but no compliant ACLs match this requirement. Review the switch configurations to ensure `log-input` is configured via an applied ACL on all interfaces to produce audit records containing information to establish where the events occurred. When the log-input parameter is configured on deny statements, the log record will contain the Layer 2 address of the forwarding device for any packet being dropped." | Out-String
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

Function Get-V220439 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220439
        STIG ID    : CISC-RT-000230
        Rule ID    : SV-220439r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000001
        Rule Title : The Cisco switch must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.
        DiscussMD5 : 9C2783E08E315CF9980AA01302F390C2
        CheckMD5   : FB6C644F954AF46A644246420F2DE69F
        FixMD5     : EC3C2DB905CE3FFD7973BA5A972EF2E4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OpenFinding = $False

    IF ($ShowRunningConfig -notcontains "line aux 0") {
        $Status = "Open"
        $OpenFinding = $True
        $FindingDetails += "The required 'line aux 0' configuration is missing. Review the switch configuration and verify that the auxiliary port is disabled unless it is connected to a secured modem providing encryption and authentication." | Out-String
        $FindingDetails += "" | Out-String
    }
    IF ($ShowRunningConfig -notcontains "no exec") {
        $Status = "Open"
        $OpenFinding = $True
        $FindingDetails += "The required 'no exec' configuration is missing. Review the switch configuration and verify that the auxiliary port is disabled unless it is connected to a secured modem providing encryption and authentication." | Out-String
        $FindingDetails += "" | Out-String
    }

    If (!$OpenFinding) {
        $Status = "NotAFinding"
    }
    else {
        $FindingDetails += "Review the switch configuration and verify that the auxiliary port is disabled unless it is connected to a secured modem providing encryption and authentication. The configuration should contain 'line aux 0', 'no exec', and the additional command 'transport input none' should be run for good measure if the auxiliary port was not already initially disabled correctly." | Out-String
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

Function Get-V220440 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220440
        STIG ID    : CISC-RT-000240
        Rule ID    : SV-220440r622190_rule
        CCI ID     : CCI-001109
        Rule Name  : SRG-NET-000202-RTR-000001
        Rule Title : The Cisco perimeter switch must be configured to deny network traffic by default and allow network traffic by exception.
        DiscussMD5 : 65D3822C9D73E1C3FDA7CD2364763F02
        CheckMD5   : C322048F8EFFB53C4500AD1037CA104E
        FixMD5     : 84120F3290E772C5D26D7AF3EC219E38
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $CompliantACLs = @()
    $CompliantInterfaces = @()
    $NonCompliantInterfaces = @()

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        IF ($AccessListConfig -contains "deny ip any any log-input") {
            $AccessListName = ($AccessList -split " ")[3]
            $CompliantACLs += $AccessListName
        }
    }
    
    ForEach ($Interface in $Interfaces) {
        $IntCompliant = $False
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ip access-group * in") {
            ForEach ($acl in $CompliantACLs) {
                if ($InterfaceConfig -contains "ip access-group $acl in"){
                    $CompliantInterfaces += $Interface
                    $IntCompliant = $True
                    break
                }
            }
        }
        if (!($IntCompliant)) {
            $NonCompliantInterfaces += $Interface
        }
    }

    If ($CompliantACLs.count -gt 0) {
        $FindingDetails += "The Cisco perimeter switch must be configured to deny network traffic on all external interfaces by default and allow network traffic by exception. Review the lists below and verify that compliant ACLs meeting this requirement have been applied as ingress filters to all external interfaces." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------------------------------------- Compliant ACLs -------------------------------------------" | Out-String
        foreach ($acl in $CompliantACLs) {
            $FindingDetails += $acl.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    If ($CompliantInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces have ingress ACLs applied that deny network traffic by default and are considered compliant." | Out-String
        $FindingDetails += "------------------------------------------- Compliant Interfaces -------------------------------------------" | Out-String
        foreach ($int in $CompliantInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    if ($NonCompliantInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces do not have ingress ACLs applied that deny network traffic by default. Verify and/or configure all external interfaces with an ACL to filter all ingress traffic and deny any traffic not explicitly defined as allowed by default." | Out-String
        $FindingDetails += "------------------------------------------- Uncompliant Interfaces -------------------------------------------" | Out-String
        foreach ($int in $NonCompliantInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
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

Function Get-V220441 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220441
        STIG ID    : CISC-RT-000250
        Rule ID    : SV-220441r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000002
        Rule Title : The Cisco perimeter switch must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.
        DiscussMD5 : C13A2B26E79E6D5BA74510DE4AF0E5AF
        CheckMD5   : 227DF7E3CC8C53EE830BC059E83FC53C
        FixMD5     : 18ABB87DF8894A892803847424F9A64B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
      
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfig = ($InterfaceConfig -split "[\r\n]+")
        IF (!($InterfaceConfig -like "ip access-group *")) {
            # Add interface without an inbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below interface connects to another network and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "Interface without an ACL configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            IF ($InterfaceConfig | Select-String -Pattern "ip access-group .* in") {
                $ACLInName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
                $IPACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list (standard|extended) $ACLInName`$"
                IF (!$IPACL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound ACL $ACLInName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $IPACL.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify that the inbound ACL $ACLInName under $Interface is configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols, and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "ACL $ACLInName entries:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($ACLConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }    
            }
            IF ($InterfaceConfig | Select-String -Pattern "ip access-group .* out") {
                $ACLOutName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* out").ToString().Split([char[]]"") | Select-Object -Index 2
                $IPACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list (standard|extended) $ACLOutName`$"
                IF (!$IPACL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Outbound ACL $ACLOutName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $IPACL.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify that the outbound ACL $ACLOutName under $Interface is configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols, and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "ACL $ACLOutName entries:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($ACLConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $Exception = $True
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

Function Get-V220442 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220442
        STIG ID    : CISC-RT-000260
        Rule ID    : SV-220442r856238_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000109
        Rule Title : The Cisco perimeter switch must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
        DiscussMD5 : 906B999ED9768BFFB6ECC5A94E5BBD8C
        CheckMD5   : 3AC7EB4A431237D55DBB07AE0757C08D
        FixMD5     : 7A2BCD5E8E5DCB4EB32F34C4E75B33AD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Get ACL configuration
    IF ($ShowRunningConfig | Select-String -Pattern "^ip access-list extended") {
        $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
        ForEach ($AccessList in $AccessLists) {
            $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
            # Add Access List to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the below ACL configuration to verify that it allows only incoming communications from authorized sources to be routed to authorized destinations and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($AccessList.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($AccessListConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have an extended ACL configured, make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfig = ($InterfaceConfig -split "[\r\n]+")
        IF (!($InterfaceConfig -like "ip access-group * in")) {
            # Add interface without an inbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interface without an inbound ACL configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $ACLInName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
            $IPACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list (standard|extended) $ACLInName`$"
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interface with inbound ACL $ACLInName configured:" | Out-String
            $FindingDetails += "-----------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
            IF (!$IPACL) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound ACL $ACLInName under $Interface is not configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
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

Function Get-V220443 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220443
        STIG ID    : CISC-RT-000270
        Rule ID    : SV-220443r863240_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000110
        Rule Title : The Cisco perimeter switch must be configured to block inbound packets with source Bogon IP address prefixes.
        DiscussMD5 : FF2A4B7629939398BC463DF86378208A
        CheckMD5   : 406FDD914ACF0FDEAD13E7BED5A900C9
        FixMD5     : 8DC2FB940510C3EEA3F224769A3EFE1D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Exception = $False
    $OpenFinding = $False
    
    $bogons = @(
        'deny ip 0.0.0.0 0.255.255.255 any log-input',
        'deny ip 10.0.0.0 0.255.255.255 any log-input',
        'deny ip 100.64.0.0 0.63.255.255 any log-input',
        'deny ip 127.0.0.0 0.255.255.255 any log-input',
        'deny ip 169.254.0.0 0.0.255.255 any log-input',
        'deny ip 172.16.0.0 0.15.255.255 any log-input',
        'deny ip 192.0.0.0 0.0.0.255 any log-input',
        'deny ip 192.0.2.0 0.0.0.255 any log-input',
        'deny ip 192.168.0.0 0.0.255.255 any log-input',
        'deny ip 198.18.0.0 0.1.255.255 any log-input',
        'deny ip 198.51.100.0 0.0.0.255 any log-input',
        'deny ip 203.0.113.0 0.0.0.255 any log-input',
        'deny ip 224.0.0.0 31.255.255.255 any log-input',
        'deny ip 240.0.0.0 15.255.255.255 any log-input',
        'permit tcp any any established')
        
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $ACLList = @()
    $UncompliantInterfaces = @()
    
    #Check all access lists for configuration and compile list for those with configuration present
    ForEach ($AccessList in $AccessLists) {
        $ConfigActive = $False
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $null = $AccessList -match "ip access-list extended (?<content>.*)"
        
        # Compare bogon configurations against ACL configurations
        ForEach ($config in $bogons) {
            IF (!($AccessListConfig -like $config)) {
                $ConfigActive = $False
                break
            }
            else {
                $ConfigActive = $True
            }
        }
        # Check if this ACL blocks all bogon prefixes
        If ($ConfigActive -eq $True) {
            if ($ACLList.count -eq 0){
                $FindingDetails += "" | Out-String
                $FindingDetails += "These ACLs are configured to block bogon sourced traffic:" | Out-String
                $FindingDetails += "---------------------------------------------------------" | Out-String
                $FindingDetails += ($matches['content'].ToString() | Out-String)
                $ACLList += ($matches['content'].ToString() | Out-String).Trim()
            }
            else {
                $ACLList += ($matches['content'].ToString() | Out-String).Trim()
                #$ACLList += ($matches['content'].ToString() | Out-String).Trim()
                $FindingDetails += ($matches['content'].ToString() | Out-String)
                $Exception = $True
            }
        }
    }
    $FindingDetails += "" | Out-String
    
    # Verify whether we have a properly configured acl
    if ($ACLList.count -gt 0) {
        # Check each interface for the configuration or an ACL
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $aclPresent = $False
            ForEach ($acl in $ACLList) {
                if ($InterfaceConfig -like "ip access-group $acl in"){
                    $aclPresent = $True
                    $FindingDetails += "ACL $acl properly applied to $Interface blocking bogon addresses." | Out-String
                    $FindingDetails += "" | Out-String
                    break
                }
            }
            # Check whether required ACL is applied to this interface
            if ($aclPresent -eq $False) {
                $OpenFinding = $True
                $UncompliantInterfaces += $Interface.ToString()
                $OpenFinding = $True
            }
        }
    }
    else {
        $FindingDetails += "No ACLs have been properly configured to block inbound packets with source Bogon IP address prefixes." | Out-String
        $FindingDetails += "Review the device configuration to verify that an ingress Access Control List (ACL) is applied to all external interfaces and blocking packets with Bogon source addresses and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    
    IF ($OpenFinding) {
        $FindingDetails += "There are currently ACLs configured on the device to block bogon prefixes but they are not applied on the following interfaces. Verify that the inbound ACL applied to all external interfaces will block all traffic from Bogon source addresses and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($int in $UncompliantInterfaces) {
            $FindingDetails += $int | Out-String
            
        }
        $FindingDetails += "" | Out-String
        $Exception = $True
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

Function Get-V220445 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220445
        STIG ID    : CISC-RT-000320
        Rule ID    : SV-220445r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000003
        Rule Title : The Cisco perimeter switch must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.
        DiscussMD5 : E14B155BE20D22616346C2950515E481
        CheckMD5   : C1AB01FCEDC8ACB114547E8A0E8D0E0C
        FixMD5     : 49D227287075F7FE132F43A4AB6675BC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
      
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfig = ($InterfaceConfig -split "[\r\n]+")
        IF (!($InterfaceConfig -like "ip access-group * in")) {
            # Add interface without an inbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below is an external interface and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "Interface without an inbound ACL configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            IF ($InterfaceConfig | Select-String -Pattern "ip access-group .* in") {
                $ACLInName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
                $IPACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list (standard|extended) $ACLInName`$"
                IF (!$IPACL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound ACL $ACLInName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $IPACL.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "If $Interface is external, verify that the inbound ACL $ACLInName is filtering traffic in accordance with DoD 8551.1, and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "ACL $ACLInName entries:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($ACLConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $Exception = $True
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

Function Get-V220446 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220446
        STIG ID    : CISC-RT-000330
        Rule ID    : SV-220446r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000004
        Rule Title : The Cisco perimeter switch must be configured to filter ingress traffic at the external interface on an inbound direction.
        DiscussMD5 : 16F07BE2B7881C1461A257E87F446221
        CheckMD5   : 0E042F88CB32FCDCA4B679E07A47CC48
        FixMD5     : 71754716C05DD9244887CF3F1EAB8255
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $aclPositive = @()
    $aclNegative = @()
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ip access-group * in") {
            $aclPositive += ($Interface.ToString() | Out-String).Trim()
            $aclPositive += ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString()
            $Exception = $True
        }
        else {
            $aclNegative += ($Interface | Out-String).Trim()
            $Exception = $True
        }
    }
    
    If ($aclPositive.count -gt 0) {
        $FindingDetails += "The following interfaces have ACLs applied. Verify the ACLs filter all ingress traffic on an inbound direction for all external interfaces." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($config in $aclPositive) {
            $FindingDetails += $config | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    if ($aclNegative.count -gt 0) {
        $FindingDetails += "The following interfaces do not have ACLs applied. Verify and/or configure all external interfaces with an ACL to filter all ingress traffic on an inbound direction." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($config in $aclNegative) {
            $FindingDetails += $config | Out-String
        }
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

Function Get-V220447 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220447
        STIG ID    : CISC-RT-000340
        Rule ID    : SV-220447r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000005
        Rule Title : The Cisco perimeter switch must be configured to filter egress traffic at the internal interface on an inbound direction.
        DiscussMD5 : 16F07BE2B7881C1461A257E87F446221
        CheckMD5   : 481CE1CB78E9519CBDB95148B722EB83
        FixMD5     : 468801388BD2118C8434B7EC26A40967
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $aclPositive = @()
    $aclNegative = @()
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ip access-group * in") {
            $aclPositive += ($Interface.ToString() | Out-String).Trim()
            $aclPositive += ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString()
            $Exception = $True
        }
        else {
            $aclNegative += ($Interface | Out-String).Trim()
            $Exception = $True
        }
    }
    
    If ($aclPositive.count -gt 0) {
        $FindingDetails += "The following interfaces have ACLs applied. Verify the ACLs are bound to filter egress traffic on internal interfaces in an inbound direction." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($config in $aclPositive) {
            $FindingDetails += $config | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    if ($aclNegative.count -gt 0) {
        $FindingDetails += "The following interfaces do not have ACLs applied. Verify and/or configure all internal interfaces with an ACL to filter all engress traffic on an inbound direction." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($config in $aclNegative) {
            $FindingDetails += $config | Out-String
        }
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

Function Get-V220449 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220449
        STIG ID    : CISC-RT-000360
        Rule ID    : SV-220449r856240_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter switch must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
        DiscussMD5 : DE2DF3FF764906583974A231590A2AA7
        CheckMD5   : CBD7AF5957DE103DF48E67AFD5C84262
        FixMD5     : 5E6EB62E2FDC45D5E3DD6FA1E3975A8E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF (!($ShowRunningConfig | Select-String -Pattern "^lldp run")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "LLDP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get interface configuration.
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -like "no lldp transmit")) {
                # Add non-compliant interface to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below is an external interface and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without 'no lldp transmit' configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            Else {
                # Add compliant interface to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Compliant Interface:" | Out-String
                $FindingDetails += "--------------------" | Out-String
                $FindingDetails += ($Interface | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
        }
    }
    
    IF ($OpenFinding) {
        $Status = "Not_Reviewed"
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

Function Get-V220450 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220450
        STIG ID    : CISC-RT-000370
        Rule ID    : SV-220450r856241_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter switch must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.
        DiscussMD5 : 6D0E28E70C1F62DD2E3E3F6CE9141CF7
        CheckMD5   : 1A8A58D433E811B6B61A86724D1BAC07
        FixMD5     : 7593923F90762501C890FEEDE7BC327C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -notcontains "cdp run") {
        $Status = "Open"
        $OpenFinding = $True
        $FindingDetails += "Global configuration of CDP is detected: 'cdp run'. Review the switch configuration and disable Cisco Discovery Protocol (CDP)." | Out-String
        $FindingDetails += "" | Out-String
    }
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -contains "cdp enable") {
            $OpenFinding = $True
            $Status = "Not_Reviewed"
            $FindingDetails += "Review the switch interface configuration below and verify that Cisco Discovery Protocol (CDP) ('cdp enable') is not enabled on any external interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
        }
    }

    if (!$OpenFinding) {
        $Status = "NotAFinding"
        $FindingDetails += "Cisco Discovery Protocol (CDP) is not enabled globally or per any interface." | Out-String
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

Function Get-V220451 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220451
        STIG ID    : CISC-RT-000380
        Rule ID    : SV-220451r856242_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000112
        Rule Title : The Cisco perimeter switch must be configured to have Proxy ARP disabled on all external interfaces.
        DiscussMD5 : C5C36F4A495CF6396443AC65A2D12B52
        CheckMD5   : D53761C8079F31623B665C9765CE3158
        FixMD5     : 1108F6C3BC66CCC089D3F4347D985DE6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $TestInterface = $False

        If ($InterfaceConfig -notcontains "shutdown"){
            $TestInterface = $True
        }

        if ($TestInterface){
            if ($InterfaceConfig -notcontains "no proxy arp") {
                $OpenFinding = $True
                $Status = "Not_Reviewed"
                $FindingDetails += "Proxy ARP is enabled by default is not explicitly disabled on this interface. Review the interface configuration below. If this is an external interface then Proxy ARP must be disabled via the configuration: 'no proxy arp'." | Out-String
                $FindingDetails += "---------------------------------------- Interface Configuration ----------------------------------------"
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    if (!$OpenFinding){ 
        $FindingDetails += "There are no interfaces with Proxy ARP enabled on this device."
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220452 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220452
        STIG ID    : CISC-RT-000390
        Rule ID    : SV-220452r945857_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000364-RTR-000113
        Rule Title : The Cisco perimeter switch must be configured to block all outbound management traffic.
        DiscussMD5 : A869964F5D48C9EF4C880FFA61D569BD
        CheckMD5   : 102588E4AF33D17D6C72AE7E3E8BFBB9
        FixMD5     : 78B0778A3EB6A20CF70E317FBCDCCCE5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $CompliantACLs = @()
    $UncompliantACLs = @()
    $CompliantInterfaces = @()
    $UncompliantInterfaces = @()
    
    ForEach ($AccessList in $AccessLists) {
        
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        IF (!($AccessListConfig -like "deny tcp * eq tacacs log-input")) {
            $UncompliantACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "deny tcp * eq 22 log-input")) {
            $UncompliantACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "deny udp * eq snmp log-input")) {
            $UncompliantACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "deny udp * eq snmptrap log-input")) {
            $UncompliantACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "deny udp * eq syslog log-input")) {
            $UncompliantACLs += $AccessList
        }
        else {
            $CompliantACLs += $AccessList
        }
    }

    if ($CompliantACLs.count -gt 0) {
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
        
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $IntValid = $False

            ForEach ($acl in $CompliantACLs){
                $AccessListName = ($acl -split " ")[3]
                $configuration = "ip access-group $AccessListName out"
                if ($InterfaceConfig -contains $configuration){
                    $CompliantInterfaces += $Interface
                    $IntValid = $True
                    break
                }
            }
            if (!$IntValid) {
                $UncompliantInterfaces += $Interface
            }
        }

        if ($UnCompliantInterfaces.count -gt 0) {
            $FindingDetails += "The Cisco perimeter switch must be configured to block all outbound management traffic. If this is a switch of the managed network, then an outbound ACL must be configured on the external interfaces to block all management traffic." | Out-String
            $FindingDetails += "The following ACLs are compliant with this requirement." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------------------------------- Compliant ACLs ----------------------------------------" | Out-String
            ForEach ($acl in $CompliantACLs) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | out-string
            
            if ($CompliantInterfaces.count -gt 0) {
                $FindingDetails += "The following interfaces are configured with an ACL compliant with this requirement." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "---------------------------------------- Compliant Interfaces ----------------------------------------" | Out-String
                ForEach ($int in $CompliantInterfaces) {
                    $FindingDetails += $int.ToString() | Out-String
                }
                $FindingDetails += "" | out-string
                $FindingDetails += "" | out-string
            }
            else {
                $FindingDetails += "There are currently no interfaces configured with a compliant ACL." | out-string
                $FindingDetails += "" | out-string
            }
            
            $FindingDetails += "The following interfaces lack an ACL compliant with this requirement. Review the interfaces below to verify if any are external interfaces in need of a compliant ACL." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------------------------------- Uncompliant Interfaces ----------------------------------------" | Out-String
            ForEach ($int in $UncompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | out-string

        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    else {
        $FindingDetails += "The Cisco perimeter switch must be configured to block all outbound management traffic. If this is a switch of the managed network, then an outbound ACL must be configured on the external interfaces to block all management traffic." | Out-String
        $FindingDetails += "The following ACLs have been discovered on device. Configure or add a new ACL to block all management traffic ('tacacs', ssh(port 22)', 'snmp', 'snmptrap', 'syslog') with 'log-input' enabled for logging, to be applied to all external interfaces." | Out-String
        $FindingDetails += "---------------------------------------- Uncompliant ACLs ----------------------------------------" | Out-String
        ForEach ($acl in $UncompliantACLs) {
            $FindingDetails += $acl.ToString() | Out-String
        }
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

Function Get-V220453 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220453
        STIG ID    : CISC-RT-000450
        Rule ID    : SV-220453r991873_rule
        CCI ID     : CCI-001097, CCI-004891
        Rule Name  : SRG-NET-000205-RTR-000012
        Rule Title : The Cisco switch must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface.
        DiscussMD5 : B8662AA48D9C927F2E6CB16F00AF7C6C
        CheckMD5   : 526873C0184C96B3D195B6D2DF28617F
        FixMD5     : BC2C7E022220293E7B3AFEF04C05AA49
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $IngressACLs = @()
    $EgressACLs = @()
    $CompliantInterfaces = @()
    
    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()

        IF (!($AccessListConfig -like "permit tcp * eq tacacs")) {
            $IngressACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "permit tcp * eq 22")) {
            $IngressACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "permit udp * eq snmp")) {
            $IngressACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "permit udp * eq snmp-trap")) {
            $IngressACLs += $AccessList
        }
        Elseif (!($AccessListConfig -like "permit udp * eq ntp")) {
            $IngressACLs += $AccessList
        }
        else {
            $IngressACLs += ($AccessList -split " ")[3]
        }

        if ($AccessListConfig -contains "deny ip any any log-input") {
            $EgressACLs += ($AccessList -split " ")[3]
        }
    }

    if ($IngressACLs.count -eq 0) {
        $FindingDetails += "The Cisco switch must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface. No ingress ACLs have been found matching this requirement. If this device has a managed interface, locate and verify that the interface is configured with an ingress ACL that only allows management and ICMP traffic and an egress ACL that blocks any transit traffic." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    elseif ($EgressACLs.count -eq 0) {
        $FindingDetails += "The Cisco switch must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface. No egress ACLs have been found matching this requirement. If this device has a managed interface, locate and verify that the interface is configured with an ingress ACL that only allows management and ICMP traffic and an egress ACL that blocks any transit traffic." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    else {
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $Ingress = $False
            $Egress = $False
            
            #Does this interface contain both an egress and ingress ACL
            if ($InterfaceConfig -like "ip access-group * in" -and $InterfaceConfig -like "ip access-group * out") {
                ForEach ($acl in $IngressACLs){
                    $configuration = "ip access-group $acl in"

                    if ($InterfaceConfig -contains $configuration){
                        $CompliantInterfaces += $Interface
                        $Ingress = $True
                        break
                    }
                }
                ForEach ($acl in $EgressACLs){
                    $configuration = "ip access-group $acl out"

                    if ($InterfaceConfig -contains $configuration){
                        $CompliantInterfaces += $Interface
                        $Egress = $True
                        break
                    }
                }
                
                if ($Egress -and $Ingress) {
                    $CompliantInterfaces += $Interface
                }
            }
        }

        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The Cisco switch must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface. The following interfaces have been detected containing both an ingress and egress ACL configured. If this device has a managed interface then identify the OOBM interface below and review its configurations. Verify that the ingress ACL only allows management and ICMP traffic and the egress ACL blocks any transit traffic configured." | Out-String
            $FindingDetails += "---------------------------------------- Possible OOBM Interfaces ----------------------------------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Not_Reviewed"
            
            $FindingDetails += "---------------------------------------- Ingress ACLs Matching Requirement ----------------------------------------" | Out-String
            ForEach ($acl in $IngressACLs) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String

            $FindingDetails += "---------------------------------------- Egress ACLs Matching Requirement ----------------------------------------" | Out-String
            ForEach ($acl in $EgressACLs) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "The Cisco switch must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface. No interfaces have been detected containing both an ingress and egress ACL configured. If this device has a managed interface, locate and verify that the interface has an ingress ACL that only allows management and ICMP traffic and an egress ACL that blocks any transit traffic configured." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V220454 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220454
        STIG ID    : CISC-RT-000660
        Rule ID    : SV-220454r864159_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-NET-000343-RTR-000001
        Rule Title : The Cisco PE switch providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.
        DiscussMD5 : 401526A9698D4F512F1C1B337678FB98
        CheckMD5   : D25A7F9602D186B89BCCB325E2639BA1
        FixMD5     : 14058E8F6C558BE190E7A46574106F49
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -like "mpls ldp neighbor * password *") {
        IF ($ShowRunningConfig -contains "mpls label protocol ldp"){
            $FindingDetails += "The Cisco switch is not compliant with this requirement but has been correctly configured to mitigate this requirement from a category 2 to a category 3 severity level." | Out-String
            $FindingDetails += "While this requirement cannot be met for this device, all available remediations have been applied and nothing further can be done." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Whilst a password has been applied for MD5 LDP sessions, 'mlps label protocol ldp' has not been enabled to successfully mitigate this category 2 severity level down to a category 3." | Out-String
            $FindingDetails += "Review the configuration and verify the switch is correctly configured to authenticate targeted LDP sessions using MD5." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "Review the configuration and verify the switch is correctly configured to authenticate targeted LDP sessions using MD5 to mitigate this to a category 3 from a category 2 severity level." | Out-String
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

Function Get-V220455 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220455
        STIG ID    : CISC-RT-000730
        Rule ID    : SV-220455r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000007
        Rule Title : The Cisco PE switch must be configured to block any traffic that is destined to the IP core infrastructure.
        DiscussMD5 : 0C00C595B03E79CE450BDCE69546FE4A
        CheckMD5   : B149D0739DB9CE66D9B52A5376152DCE
        FixMD5     : 7D4E664D58F56D1F1624E77E41B88130
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $CompliantInterfaces = @()
    $CompliantACLs = @()
    
    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()

        IF ($AccessListConfig -like "deny ip any * log-input") {
            $CompliantACLs += ($AccessList -split " ")[3]
        }
    }

    Write-Output "Detected AccessLists: $CompliantACLs"

    if ($CompliantACLs.count -gt 0) {
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            
            if ($InterfaceConfig -like "ip access-group * in") {
                ForEach ($acl in $CompliantACLs) {
                    $aclConfig = "ip access-group $acl in"
                    #Write-Output "Compliant aclConfig: $aclConfig"

                    if ($InterfaceConfig -contains $aclConfig) {
                        $CompliantInterfaces += $Interface
                        #Write-Output "Compliant Interface: $Interface"
                        break
                    }
                }
            }
        }

        #Write-Output "Detected Interfaces: $CompliantInterfaces"
        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The Cisco PE switch must be configured to block any traffic that is destined to the IP core infrastructure. Potential interface and ACL matches have been detected for this requirement. If this is a PE switch, review the lists below and verify that an ingress ACL to discard and log packets destined to the IP core address space is configured inbound to all external or CE-facing interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "The ACLs listed below contain a 'deny ip any <IP address> log-input' configuration and are considered a potential requirement match for 'deny ip any <IP core address space> log-input' per this requirement. Verify if any of these ACLs match on the 'IP core address space'." | Out-String
            $FindingDetails += "---------------------------------------- Potential ACL Matches ----------------------------------------" | Out-String
            ForEach ($acl in $CompliantACLs) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "The interfaces listed below contain a matching ACL to the 'deny ip any <IP address> log-input' configuration and are considered a potential requirement match for 'deny ip any <IP core address space> log-input' per this requirement. Verify that a matching ingress ACL is applied to all external or CE-facing interfaces and that no external or CE-facing interfaces are missing from this list." | Out-String
            $FindingDetails += "---------------------------------------- Potential ACL Matches ----------------------------------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $Status = "Not_Reviewed"
        }
        else {
            $FindingDetails += "The Cisco PE switch must be configured to block any traffic that is destined to the IP core infrastructure. Potential ACL matches containing a 'deny ip any <IP Address Space> log-input' configuration have been detected but need the <IP core address space> verified against these ACLs. Additionally, none of these ACLs have been applied to any interfaces. If this is a PE switch, apply the appropriate ACL inbound to all external or CE-facing interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------------------------------- Potential ACL Matches ----------------------------------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $Status = "Not_Reviewed"
        }
    }
    else {
        $FindingDetails += "The Cisco PE switch must be configured to block any traffic that is destined to the IP core infrastructure. No ACLs containing a 'deny ip any <IP Core Address Space> log-input' configuration have been detected for this requirement. If this is a PE switch, configure an ACL matching this requirement and apply the ACL inbound to all external or CE-facing interfaces." | Out-String
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

Function Get-V220456 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220456
        STIG ID    : CISC-RT-000740
        Rule ID    : SV-220456r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000008
        Rule Title : The Cisco PE switch must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.
        DiscussMD5 : B0DED1F2B02B3D8822D5F09021FD4071
        CheckMD5   : DCA1346DCCA541007669A9E3FF8D9C61
        FixMD5     : A68D2D210E2009795E2009C1712988D7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $count = 0
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $OpenFinding = $False

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -notcontains "ip verify unicast source reachable-via any") {
            $OpenFinding = $True
            $Status = "Open"
            $FindingDetails += "Review the interface configuration and verify that uRPF loose mode is enabled on all CE-facing interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
            $count += 1
        }
        else {
            $FindingDetails += "Interface $Interface has uRPF loose mode enabled." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    if (!$OpenFinding){ 
        $FindingDetails += "All CE-facing interfaces have uRPF loose mode enabled."
        $Status = "NotAFinding."
    }
    else {
        $FindingDetails += "There are $count interfaces with uRPF loose mode not enabled on this device."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220458 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220458
        STIG ID    : CISC-RT-000760
        Rule ID    : SV-220458r917423_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000113
        Rule Title : The Cisco PE switch must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : DD595397B0345C451D83D6B9937F3AEC
        CheckMD5   : 3820646845B1B0D37D089FDE55450537
        FixMD5     : 94A93DEF1DEA589C168A413AE040C214
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map"
    $PolicyMaps = $ShowRunningConfig | Select-String -Pattern "^policy-map"
    $ClassMapNames = @()
    $VerifiedPolicies = $False
    
    if ($ClassMaps.count -eq 0) {
        $FindingDetails += "No class map has been configured on this device. Verify that a class map has been configured with a 'match ip *' applied and that the designated class map has been applied to a policy-map with any additional 'bandwith percent #' configurations required." | Out-String
        $FindingDetails += "The Cisco PE Switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    elseif ($PolicyMaps.count -eq 0) {
        $FindingDetails += "No policy map has been configured on this device. Review the device configuration and remediate." | Out-String
        $FindingDetails += "The Cisco PE Switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    else {
        ForEach ($map in $ClassMaps) {
            $mapConfig = Get-Section $ShowRunningConfig $map.ToString()
            # Verify there is a class map with the proper configuration
            if ($mapConfig -like "match ip dscp af47") {
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp ef"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp af41"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp cs6"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp af33"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
        }

        if ($ClassMapNames.count -eq 5) {
            ForEach ($policy in $PolicyMaps) {
                $policyConfig = Get-Section $ShowRunningConfig $policy.ToString()
                $policyName = ($policy -split " ")[1]
                $mapValid = $True
                foreach ($map in $ClassMapNames) {
                    if ($policyConfig -notcontains "class $map") {
                        $mapValid = $False
                    }
                }
                # Class maps valid for this policy. Look for bandwidth config.
                if ($mapValid) {
                    if ($policyConfig -like "bandwidth percent *") {
                        ForEach ($Interface in $Interfaces) {
                            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                            if ($InterfaceConfig -like "service-policy output $policyName") {
                                $FindingDetails += "Review the switch configuration below and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
                                $FindingDetails += "This Interface: ($Interface) is configured with the Policy: ($policy) containing the requisite 'match ip *' requirements as well as 'bandwidth percent #' limitations as per this requirement." | Out-String
                                $FindingDetails += "---------------------------------------- Findings ----------------------------------------" | Out-String
                                $FindingDetails += "---------- Interface Configs ----------" | Out-String
                                $FindingDetails += $Interface | Out-String
                                $FindingDetails += $InterfaceConfig | Out-String
                                $FindingDetails += "---------- Policy Configs ----------" | Out-String
                                $FindingDetails += $policy | Out-String
                                $FindingDetails += $policyConfig | Out-String
                                $FindingDetails += "---------- Compliant Class Maps ----------" | Out-String
                                ForEach ($map in $ClassMapNames) {
                                    $FindingDetails += $map | Out-String
                                }
                                $FindingDetails += "--------------------------------------------------------------------------------"
                                $FindingDetails += "" |  Out-String
                                $VerifiedPolicies = $True
                                $Status = "Not_Reviewed"
                            }
                        }
                    }
                }
                else {}
            }    
        }
        else {
            $FindingDetails += "Class maps have been found in this device configuration but lack the proper overall 'match ip *' configuration. Review the Switch configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
            $FindingDetails += "-------------------- Required Map Matches --------------------" | Out-String
            $FindingDetails += "match ip dscp af47 
match ip dscp ef 
match ip dscp af41
match ip dscp cs6
match ip dscp af33" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "-------------------- Available Compliant Class Maps --------------------" | Out-String
            ForEach ($map in $ClassMapNames) {
                $FindingDetails += $map | Out-String
            }
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
    }

    if (!$VerifiedPolicies) {
        $FindingDetails += "No compliant QoS policies have been identified for this requirement. Review the Switch configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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

Function Get-V220459 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220459
        STIG ID    : CISC-RT-000770
        Rule ID    : SV-220459r917426_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000114
        Rule Title : The Cisco P switch must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : DD595397B0345C451D83D6B9937F3AEC
        CheckMD5   : 9DE4632B8FFBAC54FF323683EA6F807B
        FixMD5     : 94A93DEF1DEA589C168A413AE040C214
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map"
    $PolicyMaps = $ShowRunningConfig | Select-String -Pattern "^policy-map"
    $ClassMapNames = @()
    $VerifiedPolicies = $False
    
    if ($ClassMaps.count -eq 0) {
        $FindingDetails += "No class map has been configured on this device. Verify that a class map has been configured with a 'match ip *' applied and that the designated class map has been applied to a policy-map with any additional 'bandwith percent #' configurations required." | Out-String
        $FindingDetails += "The Cisco PE switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    elseif ($PolicyMaps.count -eq 0) {
        $FindingDetails += "No policy map has been configured on this device. Review the device configuration and remediate." | Out-String
        $FindingDetails += "The Cisco PE switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    else {
        ForEach ($map in $ClassMaps) {
            $mapConfig = Get-Section $ShowRunningConfig $map.ToString()
            # Verify there is a class map with the proper configuration
            if ($mapConfig -like "match ip dscp 47") {
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp ef"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp 41"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp cs6"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
            elseif ($mapConfig -like "match ip dscp af33"){
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
        }

        if ($ClassMapNames.count -eq 5) {
            ForEach ($policy in $PolicyMaps) {
                $policyConfig = Get-Section $ShowRunningConfig $policy.ToString()
                $policyName = ($policy -split " ")[1]
                $mapValid = $True
                foreach ($map in $ClassMapNames) {
                    if ($policyConfig -notcontains "class $map") {
                        $mapValid = $False
                    }
                }
                # Class maps valid for this policy. Look for bandwidth config.
                if ($mapValid) {
                    if ($policyConfig -like "bandwidth percent *") {
                        ForEach ($Interface in $Interfaces) {
                            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                            if ($InterfaceConfig -like "service-policy output $policyName") {
                                $FindingDetails += "Review the switch configuration below and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
                                $FindingDetails += "This Interface: ($Interface) is configured with the Policy: ($policy) containing the requisite 'match ip *' requirements as well as 'bandwidth percent #' limitations as per this requirement." | Out-String
                                $FindingDetails += "---------------------------------------- Findings ----------------------------------------" | Out-String
                                $FindingDetails += "---------- Interface Configs ----------" | Out-String
                                $FindingDetails += $Interface | Out-String
                                $FindingDetails += $InterfaceConfig | Out-String
                                $FindingDetails += "---------- Policy Configs ----------" | Out-String
                                $FindingDetails += $policy | Out-String
                                $FindingDetails += $policyConfig | Out-String
                                $FindingDetails += "---------- Compliant Class Maps ----------" | Out-String
                                ForEach ($map in $ClassMapNames) {
                                    $FindingDetails += $map | Out-String
                                }
                                $FindingDetails += "--------------------------------------------------------------------------------"
                                $FindingDetails += "" |  Out-String
                                $VerifiedPolicies = $True
                                $Status = "Not_Reviewed"
                            }
                        }
                    }
                }
                else {}
            }    
        }
        else {
            $FindingDetails += "Class maps have been found in this device configuration but lack the proper overall 'match ip *' configuration. Review the switch configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
            $FindingDetails += "-------------------- Required Map Matches --------------------" | Out-String
            $FindingDetails += "match ip dscp 47 
match ip dscp ef 
match ip dscp af41
match ip dscp cs6
match ip dscp af33" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "-------------------- Available Compliant Class Maps --------------------" | Out-String
            ForEach ($map in $ClassMapNames) {
                $FindingDetails += $map | Out-String
            }
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
    }

    if (!$VerifiedPolicies) {
        $FindingDetails += "No compliant QoS policies have been identified for this requirement. Review the switch configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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

Function Get-V220460 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220460
        STIG ID    : CISC-RT-000780
        Rule ID    : SV-220460r622190_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000112
        Rule Title : The Cisco switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.
        DiscussMD5 : F5E8F727DE225728A2565FF8E60E3B0A
        CheckMD5   : 920958D1ECBA43B658303F6F9F57843F
        FixMD5     : A1D2246CBD2E2602FDF239D05B76B923
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map"
    $PolicyMaps = $ShowRunningConfig | Select-String -Pattern "^policy-map"
    $ClassMapNames = @()
    $VerifiedPolicies = $False
    
    if ($ClassMaps.count -eq 0) {
        $FindingDetails += "No class map has been configured on this device. Verify that a class map has been configured with a 'match ip *' applied and that the designated class map has been applied to a policy-map with any additional 'bandwith percent #' configurations required." | Out-String
        $FindingDetails += "The Cisco switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    elseif ($PolicyMaps.count -eq 0) {
        $FindingDetails += "No policy map has been configured on this device. Review the device configuration and remediate." | Out-String
        $FindingDetails += "The Cisco switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    else {
        ForEach ($map in $ClassMaps) {
            $mapConfig = Get-Section $ShowRunningConfig $map.ToString()
            # Verify there is a class map with the proper configuration
            if ($mapConfig -like "match ip dscp cs1") {
                $mapName = ($map -split " ")[2]
                $ClassMapNames += $mapName
            }
        }

        if ($ClassMapNames.count -gt 0) {
            ForEach ($policy in $PolicyMaps) {
                $policyConfig = Get-Section $ShowRunningConfig $policy.ToString()
                foreach ($map in $ClassMapNames) {
                    if ($policyConfig -contains "class $map") {
                        if ($policyConfig -like "bandwidth percent *") {
                            $FindingDetails += "Review the configuration below and verify that the switch is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
                            $FindingDetails += "This Policy ($policy) contains both a class map ($map) with the requisite 'match ip *' requirement as well as 'bandwidth percent #' limitations. Verify the map is set with low priority in the policy." | Out-String
                            $FindingDetails += $policy | Out-String
                            $FindingDetails += $policyConfig | Out-String
                            $FindingDetails += "" |  Out-String
                            $VerifiedPolicies = $True
                            $Status = "Not_Reviewed"
                            break
                        }
                    }
                }
            }
        }
        else {
            $FindingDetails += "Class maps have been found in this device configuration but lack the proper 'match ip *' configuration. Review the switch configuration to determine if it is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
    }

    if (!$VerifiedPolicies) {
        $FindingDetails += "No compliant QoS policies have been identified for this requirement. Review the switch configuration to determine if it is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
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

Function Get-V220461 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220461
        STIG ID    : CISC-RT-000790
        Rule ID    : SV-220461r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000003
        Rule Title : The Cisco multicast switch must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.
        DiscussMD5 : 1820C2C743A0115DDC978ED153736F85
        CheckMD5   : 61BC0C91C8BB0644A8A7C75A46904EA6
        FixMD5     : 523BE1A450641FEA09CFBD7D3F0F6583
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*Port-channel*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip pim sparse-mode") -AND !($InterfaceConfig -like "ip pim dense-mode") -AND !($InterfaceConfig -like "ip pim sparse-dense-mode")) {
            # Add interface without PIM to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The below interface doesn't have PIM configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF ($InterfaceConfig -like "shutdown") {
                # Add disabled interface with PIM to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below interface requires multicast routing and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Disabled interface with multicast routing configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            ELSE {
                # Add enabled interface with PIM to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below interface requires multicast routing and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Enabled interface with multicast routing configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
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

Function Get-V220462 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220462
        STIG ID    : CISC-RT-000800
        Rule ID    : SV-220462r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000004
        Rule Title : The Cisco multicast switch must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.
        DiscussMD5 : FD0F868F2ABEC48DD2F045C26EB82556
        CheckMD5   : 485A038C40E7C527921ECEB6A9709F53
        FixMD5     : 841121D72677A7B6F57AD6E6708AC6A3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*Port-channel*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip pim sparse-mode") -AND !($InterfaceConfig -like "ip pim dense-mode") -AND !($InterfaceConfig -like "ip pim sparse-dense-mode")) {
            # Add interface without PIM to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The below interface doesn't have PIM configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip pim neighbor-filter*")) {
                # Add interface with PIM but without a neighbor ACL to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "The below interface configured with PIM requires a neighbor ACL configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                $ACLName = ($InterfaceConfig | Select-String -Pattern "ip pim neighbor-filter").ToString().Split([char[]]"") | Select-Object -Last 1
                $ACLStandard = $ShowRunningConfig | Select-String -Pattern "^ip access-list standard $ACLName"
                IF (!$ACLStandard) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "PIM Neighbor ACL $ACLName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLStandard.ToString()
                    IF (!($ACLConfig -like "permit*")) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the configured ACL $ACLName under $Interface for filtering PIM neighbors and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    ForEach ($Item in $ACLConfig) {
                        IF ($Item -like "permit*") {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Review the configured ACL under $Interface for filtering PIM neighbors and make finding determination based on STIG check guidance." | Out-String
                            $FindingDetails += "PIM Neighbor ACL $ACLName permit statements:" | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += ($Item.ToString() | Out-String).Trim()
                            $FindingDetails += "" | Out-String
                            $Exception = $True
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

Function Get-V220463 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220463
        STIG ID    : CISC-RT-000810
        Rule ID    : SV-220463r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000005
        Rule Title : The Cisco multicast edge switch must be configured to establish boundaries for administratively scoped multicast traffic.
        DiscussMD5 : 8E87341785365D57F4ED7961ED2BAAB8
        CheckMD5   : AC5F166CD2785461441FE3F4C0D4A192
        FixMD5     : 3041FA36BDC80B3F981CCAAC1187742D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*Port-channel*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip pim sparse-mode") -AND !($InterfaceConfig -like "ip pim dense-mode") -AND !($InterfaceConfig -like "ip pim sparse-dense-mode")) {
            # Add interface without PIM to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The below interface doesn't have PIM configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip multicast boundary*")) {
                # Add interface with PIM but without a multicast boundary to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if any of the below interfaces are part of the multicast edge and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without multicast boundary configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            ELSE {
                $ACLName = ($InterfaceConfig | Select-String -Pattern "ip multicast boundary").ToString().Split([char[]]"") | Select-Object -Last 1
                $ACLStandard = $ShowRunningConfig | Select-String -Pattern "^ip access-list standard $ACLName"
                IF (!$ACLStandard) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Multicast boundary ACL $ACLName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLStandard.ToString()
                    IF (!($ACLConfig -like "deny 239.0.0.0 0.255.255.255*") -or !($ACLConfig -like "permit any")) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the configured ACL $ACLName under $Interface to verify that admin-scope multicast traffic is blocked and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "ACL $ACLName under $Interface is blocking admin-scope multicast traffic." | Out-String
                        $FindingDetails += "" | Out-String
    
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

Function Get-V220464 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220464
        STIG ID    : CISC-RT-000860
        Rule ID    : SV-220464r864160_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000114
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.
        DiscussMD5 : 0F580EAEAFBC40BECD98693EFABA7E34
        CheckMD5   : 9DC7EE9FEB8F737893758C9595E23031
        FixMD5     : D74B89D1AAEBCFB6B0E686ACF8B8306E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*Port-channel*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip pim sparse-mode") -AND !($InterfaceConfig -like "ip pim dense-mode") -AND !($InterfaceConfig -like "ip pim sparse-dense-mode")) {
            # Add interface without PIM to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The below interface doesn't have PIM configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip igmp access-group*")) {
                # Add interface with PIM but without an IGMP join filter to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below is a host facing interface and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without an IGMP or MLD Membership Report messages filter configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            ELSE {
                $ACLName = ($InterfaceConfig | Select-String -Pattern "ip igmp access-group").ToString().Split([char[]]"") | Select-Object -Last 1
                $ACLStandard = $ShowRunningConfig | Select-String -Pattern "^ip access-list standard $ACLName"
                IF (!$ACLStandard) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "IGMP or MLD Membership Report messages filter ACL $ACLName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLStandard.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify if the ACL $ACLName is filtering IGMP or MLD Membership Report messages to allow hosts to join only those multicast groups that have been approved and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "ACL $ACLName entries:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($ACLConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $Exception = $True
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

Function Get-V220465 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220465
        STIG ID    : CISC-RT-000870
        Rule ID    : SV-220465r864161_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000115
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.
        DiscussMD5 : BC62F6A539A6B3CDB8D915307F15609E
        CheckMD5   : 6C096FB571D5ADF546C278045F72E8B6
        FixMD5     : 60B8608067C1D9E3A1712D7B61138ACF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*" -AND $_ -notlike "*Loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip pim sparse-mode") -AND !($InterfaceConfig -like "ip pim dense-mode") -AND !($InterfaceConfig -like "ip pim sparse-dense-mode")) {
            # Add interface without PIM to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The below interface doesn't have PIM configured:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip igmp access-group*")) {
                # Add interface with PIM but without an IGMP join filter to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below is a host facing interface and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without an IGMP or MLD Report messages filter configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            ELSE {
                $ACLName = ($InterfaceConfig | Select-String -Pattern "ip igmp access-group").ToString().Split([char[]]"") | Select-Object -Last 1
                $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
                IF (!$ACLExtended) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "IGMP or MLD Report messages filter ACL $ACLName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify if the ACL $ACLName is filtering IGMP or MLD Report messages to allow hosts to join only those multicast groups from sources that have been approved and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "ACL $ACLName entries:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($ACLConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $Exception = $True
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

Function Get-V220466 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220466
        STIG ID    : CISC-RT-000880
        Rule ID    : SV-220466r856246_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000122
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
        DiscussMD5 : F0A9052C3E50AC28479DCE04559A2802
        CheckMD5   : F276BE4D9553761E58FD60C87207D6C5
        FixMD5     : 1BFF69A15A654C1D9E50B5F36E4C7ADB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF (!($ShowRunningConfig | Select-String -Pattern "ip igmp limit")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "'ip igmp limit nn' is not configured on this device on a global basis nor on each host-facing interface." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
        $OpenFinding = $True
    }
    ELSE {
        IF ($ShowRunningConfig | Select-String -Pattern "^ip igmp limit") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "'ip igmp limit nn' is configured on this device on a global basis." | Out-String
            $FindingDetails += "" | Out-String
            $Status = "NotAFinding"
        }
        ELSE {
            $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*Loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
            ForEach ($Interface in $Interfaces) {
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                IF (!($InterfaceConfig -like "ip igmp limit*")) {
                    # Add non-compliant interface to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review the device configuration to verify that IGMP limits are configured on each host-facing interface." | Out-String
                    $FindingDetails += "Interfaces without 'ip igmp limit nn' configured:" | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                Else {
                    # Add compliant interface to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Compliant Interfaces:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($Interface | Out-String).Trim()
                    $FindingDetails += "" | Out-String
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

Function Get-V220467 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220467
        STIG ID    : CISC-RT-000890
        Rule ID    : SV-220467r945856_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000123
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to set the shortest-path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.
        DiscussMD5 : 02B2146B12646781C62D35A85E35FE5F
        CheckMD5   : 6916F2EDF5C5E15BCFC81A39D2BDA740
        FixMD5     : C3DC6921E6BAF5838C5F23D4FF9D09D5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    IF (!($ShowRunningConfig | Select-String -Pattern "ip pim rp-address")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "PIM ASM is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        IF (!($ShowRunningConfig | Select-String -Pattern "ip pim spt-threshold infinity")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "'ip pim spt-threshold infinity' is not configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
        ELSE {
            $PimSpt = $ShowRunningConfig | Select-String -Pattern "ip pim spt-threshold infinity"
            $FindingDetails += "" | Out-String
            $FindingDetails += ($PimSpt[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
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

Function Get-V220471 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220471
        STIG ID    : CISC-RT-000310
        Rule ID    : SV-220471r945858_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-NET-000205-RTR-000014
        Rule Title : The Cisco perimeter switch must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).
        DiscussMD5 : F955831C8AE1AF2B4B09AEDDA2F9987E
        CheckMD5   : 82D1CC36EC9523710CB1B60E2BA10080
        FixMD5     : 528FA24F27BB64F484C8BABAC6D49EA7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $UnverifiedInterfaces = @()
    $VerifiedACLInterfaces = @()
    $urpfInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ip verify unicast source reachable-via rx") {
            $urpfInterfaces += $Interface
        }
        elseif ($InterfaceConfig -like "ip access-group * in") {
            $VerifiedACLInterfaces += $Interface
        }
        else {
            $UnverifiedInterfaces += $Interface
        }
    }

    if ($urpfInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces have uRPF configured to restrict the device from accepting outbound IP packets that contain an illegitimate address in the source address field." | Out-String
        $FindingDetails += "-------------------- uRPF Compliant Interfaces --------------------" | Out-String
        ForEach ($int in $urpfInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }

    if ($VerifiedACLInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces have an in ACL configured. Verify if the interface is internal and if so, that the associated ACL restricts the device from accepting outbound IP packets that contain an illegitimate address in the source address field." | Out-String
        $FindingDetails += "-------------------- Interfaces with Egress ACLs Applied --------------------" | Out-String
        ForEach ($int in $VerifiedACLInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }

    if ($UnverifiedInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces have no 'ip access-group * in' ACLs configured. Review the device configuration and verify that an egress ACL or uRPF is configured on any internal interfaces to restrict the device from accepting any outbound IP packet that contains an illegitimate address in the source field." | Out-String
        $FindingDetails += "-------------------- Unverified Interfaces --------------------" | Out-String
        ForEach ($int in $UnverifiedInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
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

Function Get-V220472 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220472
        STIG ID    : CISC-RT-000350
        Rule ID    : SV-220472r945859_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000205-RTR-000015
        Rule Title : The Cisco perimeter switch must be configured to block all packets with any IP options.
        DiscussMD5 : 941923D93D4666FE1805050E1E891CF1
        CheckMD5   : 8804AEE6ED961B7D01B7E16BFD5583C5
        FixMD5     : B0D2184601090DAB8342DE37A1B71231
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $CompliantACLs = @()

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        IF ($AccessListConfig -like "deny ip any any option any-options") {
            $CompliantACLs += $AccessList
        }
    }

    IF ($ShowRunningConfig -contains "ip options ignore") {
        $Status = "NotAFinding"
    }
    elseif ($ShowRunningConfig -contains "ip options drop") {
        $Status = "NotAFinding"
    }
    elseif ($CompliantACLs.count -gt 0) {
        $FindingDetails += "The Cisco perimeter switch must be configured to block all packets with any IP options. No global configurations match this requirement but the following ACL(s) are correctly configured to block any packets containing IP options. Review the device configuration and verify that at least one appropriately configured ACL is applied to all interfaces." | Out-String
        $FindingDetails += "---------------------------------------- ACLs ----------------------------------------" | Out-String
        ForEach ($int in $CompliantACLs) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    Else {
        $FindingDetails += "The Cisco perimeter switch must be configured to block all packets with any IP options but no global configurations or compliant ACLs match this requirement. Review the switch configurations and ensure either global configurations are deployed, or an appropriate ACL is configured and applied to all interfaces, to drop any packets with IP options." | Out-String
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

Function Get-V220473 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220473
        STIG ID    : CISC-RT-000750
        Rule ID    : SV-220473r945860_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000205-RTR-000016
        Rule Title : The Cisco PE switch must be configured to ignore or drop all packets with any IP options.
        DiscussMD5 : 298524FC97370D83F186F420F32D6530
        CheckMD5   : 9811814757F2FD9C11E1FC7CB30500C0
        FixMD5     : A3F317773998A7EA62C622DF9B32B254
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -contains "ip options ignore") {
        $Status = "NotAFinding"
    }
    elseif ($ShowRunningConfig -contains "ip options drop") {
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify that all packets with IP options are globally configured to be ignored or dropped if this is a Cisco PE Switch. All Cisco PE switches must drop or ignore packets with IP options." | Out-String
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

Function Get-V237749 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237749
        STIG ID    : CISC-RT-000235
        Rule ID    : SV-237749r648775_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000100
        Rule Title : The Cisco switch must be configured to have Cisco Express Forwarding enabled.
        DiscussMD5 : B8696B21784570799B1109A78C1F44B1
        CheckMD5   : 56A443E8BCC6C62A5B7D12784CE949A1
        FixMD5     : EE009EA60B07DCBC60B2C589B589101A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OpenFinding = $False

    IF ($ShowRunningConfig -notcontains "ip cef") {
        $Status = "Open"
        $OpenFinding = $True
        $FindingDetails += "Review the switch configuration and verify that Cisco Express Forwarding (CEF) switching mode for IP version 4 ('ip cef') is globally enabled." | Out-String
        $FindingDetails += "" | Out-String
    }
    IF ($ShowRunningConfig -notcontains "ipv6 cef") {
        $Status = "Open"
        $OpenFinding = $True
        $FindingDetails += "Review the switch configuration and verify that Cisco Express Forwarding (CEF) switching mode for IP version 6 ('ipv6 cef') is globally enabled." | Out-String
        $FindingDetails += "" | Out-String
    }

    If (!$OpenFinding) {
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

Function Get-V237751 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237751
        STIG ID    : CISC-RT-000236
        Rule ID    : SV-237751r648779_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000012
        Rule Title : The Cisco switch must be configured to advertise a hop limit of at least 32 in Switch Advertisement messages for IPv6 stateless auto-configuration deployments.
        DiscussMD5 : 58951D134DA33AFAB85953208EA404A6
        CheckMD5   : 8B8017514049ED5BE0DAC47E536C76A2
        FixMD5     : 93BE30BC0230B42B3995A2C145CE21B6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -like "ipv6 hop-limit*") {
        $HopConfig = $ShowRunningConfig | Select-String -Pattern "^ipv6 hop-limit*" | Out-String
        try {
            $HopLimit = [int]$HopConfig.Substring(16)
            IF ($HopLimit -ge 32 -and $HopLimit -le 255) {
                $Status = "NotAFinding"
                $FindingDetails += "An IPv6 Hop Limit for Router Advertisement messages has been properly configured on this device." | Out-String
                $FindingDetails += $HopConfig
                $FindingDetails += "" | Out-String
            }
            Elseif ($HopLimit -le 31 -and $HopLimit -ge 1) {
                $Status = "Open"
                $FindingDetails += "An IPv6 Hop Limit configuration for Router Advertisement messages has been configured too low. Review the configuration and ensure that the ipv6 hop limit is configured to at least 32." | Out-String
                $FindingDetails += $HopConfig
                $FindingDetails += "" | Out-String
            }
            Else {
                $Status = "Not_Reviewed"
                $FindingDetails += "An IPv6 Hop Limit configuration for Router Advertisement messages has been configured incorrectly. Review the configuration and ensure that the ipv6 hop limit is configured to at least 32 and not exceeding 255." | Out-String
                $FindingDetails += $HopConfig
                $FindingDetails += "" | Out-String
            }
        }
        catch {
            $Status = "Not_Reviewed"
            $FindingDetails += "Something is wrong with this configuration. Verify that the ipv6 hop limit for Router Advertisement messages has been correctly configured to at least 32." | Out-String
            $FindingDetails += $HopConfig
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding" | Out-String
        $FindingDetails += "An IPv6 Hop Limit for Router Advertisement messages has not been configured on this device." | Out-String
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

Function Get-V237755 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237755
        STIG ID    : CISC-RT-000237
        Rule ID    : SV-237755r648786_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000013
        Rule Title : The Cisco switch must not be configured to use IPv6 Site Local Unicast addresses.
        DiscussMD5 : 5905FE5CC4A0A6775A24A1662EC96B2A
        CheckMD5   : 3FA746B50BEFA7C7B6F947ED022BE066
        FixMD5     : B0247A832C4A04C9E67F5DB16B6DBA82
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ipv6_present = $False

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ipv6 address*") { 
            $ipv6_present = $True
            if ($InterfaceConfig -like "*FEC0::/10") {
                $OpenFinding = $True
                $Status = "Open"
                $FindingDetails += "Review the configuration below and verify that this interface is only using only authorized IPv6 addresses. IPv6 Site Local Unicast addresses are not authorized." | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    Elseif (!$OpenFinding) { 
        $Status = "NotAFinding."
        $FindingDetails += "No IPv6 Site Local Unicast addresses are configured on this device." | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V237758 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237758
        STIG ID    : CISC-RT-000391
        Rule ID    : SV-237758r648791_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000014
        Rule Title : The Cisco perimeter switch must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.
        DiscussMD5 : 38D1C8FFBC0B7B3BB01BC9B0E6A2D5A1
        CheckMD5   : 612FA6D7F739655E3870A0948812B49B
        FixMD5     : CF19E209F64554198A517B27CF77E367
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ipv6_present = $False

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ipv6 address*") { 
            $ipv6_present = $True
            if ($InterfaceConfig -notcontains "ipv6 nd ra suppress") {
                $OpenFinding = $True
                $Status = "Open"
                $FindingDetails += "Review the switch configuration below and verify that Router Advertisements are suppressed on all external IPv6-enabled interfaces." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
            }
        }
    }
    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    Elseif (!$OpenFinding) { 
        $Status = "NotAFinding."
        $FindingDetails += "Router Advertisements are surpressed on all external IPv6 interfaces." | Out-String
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

Function Get-V237761 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237761
        STIG ID    : CISC-RT-000392
        Rule ID    : SV-237761r950991_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000200
        Rule Title : The Cisco perimeter switch must be configured to drop IPv6 undetermined transport packets.
        DiscussMD5 : 6F5EC21E86DCCDD4BDAC9197F76B8722
        CheckMD5   : 60D00A3941A24B25B535BB6E276A5F83
        FixMD5     : A9965D928711DE268807DA30FD158498
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list"
    $CompliantAcls = @()
    $CompliantInterfaces = @()
    $UncompliantInterfaces = @()
    $ipv6_present = $False

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $aclCompliant = $True

        IF ($AccessListConfig -notcontains "deny ipv6 any any log undetermined-transport") {
            $aclCompliant = $False
        }

        If ($aclCompliant) {
            $AccessListName = ($AccessList -split " ")[2]
            $CompliantAcls += $AccessListName
        }
    }
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ipv6 address*") { 
            $CompliantInterface = $False
            $ipv6_present = $True

            forEach ($acl in $CompliantAcls) {
                if ($InterfaceConfig -contains "ipv6 traffic-filter $acl in") {
                    $CompliantInterface = $True
                    break
                }
            }
            if ($CompliantInterface) {
                $CompliantInterfaces += $Interface
            }
            else {
                $UncompliantInterfaces += $Interface
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces are configured on this device. This requirement does not apply." | Out-String
        $FindingDetails += "" | Out-String
    }
    elseif (!$CompliantAcls.count -gt 0){
        $Status = "Not_Reviewed"
        $FindingDetails += "There are IPv6 interfaces but no ACLs found on the device that drop IPv6 undetermined transport packets." | Out-String
        $FindingDetails += "Review the interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The following IPv6 interfaces are configured with a compliant ACL that drops IPv6 undetermined transport packets." | Out-String
            $FindingDetails += "---------------  Compliant Interfaces ---------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        if ($UnCompliantInterfaces.count -gt 0) {
            $Status = "Not_Reviewed"
            $FindingDetails += "The following IPv6 interfaces are not configured with a compliant ACL for this requirement. Verify that an inbound IPv6 ACL has been configured for all external IPv6 interfaces that drops IPv6 undetermined transport packets." | Out-String
            $FindingDetails += "---------------  Compliant ACLs ---------------" | Out-String
            ForEach ($acl in $CompliantAcls) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------  Uncompliant Interfaces ---------------" | Out-String
            ForEach ($int in $UnCompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "All IPv6 interfaces are configured with a compliant ACL that drops IPv6 undetermined transport packets." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V237763 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237763
        STIG ID    : CISC-RT-000393
        Rule ID    : SV-237763r856665_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000201
        Rule Title : The Cisco perimeter switch must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3-255.
        DiscussMD5 : 023F228796EF907D709583F948A41B48
        CheckMD5   : D4A35A9FFB627246D311D35106C8AB02
        FixMD5     : 93EA9F8098AA5A194DCF72D591160D85
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ipv6_present = $False
    $BadAcls = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ipv6 address*") { 
            $ipv6_present = $True

            if ($InterfaceConfig -like "ipv6 traffic-filter * in") {
                $acls = $InterfaceConfig | Select-String -Pattern "^ipv6 traffic-filter .* in"
                foreach ($acl in $acls) {
                    $AccessListName = ($acl -split " ")[2]
                    $AccessListConfig = Get-Section $ShowRunningConfig "ipv6 access-list $AccessListName".ToString()
                    # Match on any AccessListConfig configuration that isn't routing type 2 (This is a finding)
                    if ($AccessListConfig -like "permit ipv6 * routing-type *") {
                        if ($AccessListConfig -match "permit ipv6 .* routing-type [3-9]+" -or $AccessListConfig -match "permit ipv6 .* routing-type [0-1]+" -or $AccessListConfig -match "permit ipv6 .* routing-type 2.+"){
                            $OpenFinding = $True
                            $FindingDetails += "This interface acl allows a non type 2 routing type header. Only routing headers of type 2 are authorized. Review the interface and ACL configuration below and remediate this requirement." | Out-String
                            $FindingDetails += $Interface | Out-String
                            $FindingDetails += $InterfaceConfig | Out-String
                            $FindingDetails += $acl | Out-String
                            $FindingDetails += $AccessListConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $BadAcls += $acl
                            break
                        }
                        # Type 2 routing header is permitted but others are not explicitly denied. (This is a finding.)
                        elseif ($AccessListConfig -notcontains "deny ipv6 any any log routing") {
                            $OpenFinding = $True
                            $FindingDetails += "This assigned acl allows a routing header type 2 but does not explicity deny all other routing header types. Review the interface and ACL configuration below and apply the configuration 'deny ipv6 any any log routing' to the acl to explicitly deny all other routing header types." | Out-String
                            $FindingDetails += $Interface | Out-String
                            $FindingDetails += $InterfaceConfig | Out-String
                            $FindingDetails += $acl | Out-String
                            $FindingDetails += $AccessListConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $BadAcls += $acl
                            break
                        }
                    }
                    elseif ($AccessListConfig -notcontains "deny ipv6 any any log routing") {
                        $FindingDetails += "ACL: '$AccessListName' assigned does not permit any  header types but also does not explicitly block all unauthorized router header types. Verify that the interface contains an ACL that drops IPv6 packets with a Routing Header type 0, 1, or 3-255." | Out-String
                        $FindingDetails += $Interface | Out-String
                        $FindingDetails += $InterfaceConfig | Out-String
                        $FindingDetails += $acl | Out-String
                        $FindingDetails += $AccessListConfig | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
            }
            else {
                $FindingDetails += "This IPv6 interface has no ACLs configured. Review the router configuration to determine if it is configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255, as applicable to this interface." | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $FindingDetails += "" | Out-String
                $Status = "Not_Reviewed"
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "Not_Applicable"
        $FindingDetails += "No IPv6 interfaces on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    Elseif ($OpenFinding) { 
        $Status = "Open"
        $FindingDetails += "The following ACLs are not properly configured to drop IPv6 packets with Routing Header of type 0, 1, or 3-255." | Out-String
        foreach ($acl in $BadAcls){
            $FindingDetails += $acl.ToString() | Out-String
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

Function Get-V237765 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237765
        STIG ID    : CISC-RT-000394
        Rule ID    : SV-237765r856667_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000202
        Rule Title : The Cisco perimeter switch must be configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values.
        DiscussMD5 : 7C33E23B97008FAECA65F0592154BD8A
        CheckMD5   : D99D3C0EC3A3BE055877AF1DA3A09A9F
        FixMD5     : 8D4C9E3D4D96A85EB88F2CD791E814F8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list"
    $CompliantAcls = @()
    $CompliantInterfaces = @()
    $UncompliantInterfaces = @()
    $ipv6_present = $False

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $aclCompliant = $True

        IF ($AccessListConfig -notcontains "deny hbh any any dest-option-type 4 log") {
            $aclCompliant = $False
        }
        elseif ($AccessListConfig -notcontains "deny hbh any any dest-option-type 195 log") {
            $aclCompliant = $False
        }
        elseif ($AccessListConfig -notcontains "deny hbh any any dest-option-type home-address log") {
            $aclCompliant = $False
        }

        If ($aclCompliant) {
            $AccessListName = ($AccessList -split " ")[2]
            $CompliantAcls += $AccessListName
        }
    }
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ipv6 address*") { 
            $CompliantInterface = $False
            $ipv6_present = $True

            forEach ($acl in $CompliantAcls) {
                if ($InterfaceConfig -contains "ipv6 traffic-filter $acl in") {
                    $CompliantInterface = $True
                    break
                }
            }
            if ($CompliantInterface) {
                $CompliantInterfaces += $Interface
            }
            else {
                $UncompliantInterfaces += $Interface
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces are configured on this device. This requirement does not apply." | Out-String
        $FindingDetails += "" | Out-String
    }
    elseif (!$CompliantAcls.count -gt 0){
        $Status = "Not_Reviewed"
        $FindingDetails += "There are IPv6 interfaces but no ACLs found on the device that drop IPv6 packets containing a Hop-by-Hop header with option type values of 0x04 (Tunnel Encapsulation Limit), 0xC9 (Home Address Destination), or 0xC3 (NSAP Address)." | Out-String
        $FindingDetails += "Review the switch configuration to determine if it is compliant with this requirement." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The following IPv6 interfaces are configured with a compliant ACL." | Out-String
            $FindingDetails += "---------------  Compliant Interfaces ---------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        if ($UnCompliantInterfaces.count -gt 0) {
            $Status = "Not_Reviewed"
            $FindingDetails += "The following IPv6 interfaces are not configured with a compliant ACL for this requirement. Verify that an inbound IPv6 ACL that drops IPv6 packets containing a Hop-by-Hop header with option type values of 0x04 (Tunnel Encapsulation Limit), 0xC9 (Home Address Destination), or 0xC3 (NSAP Address) has been configured for all external IPv6 interfaces." | Out-String
            $FindingDetails += "---------------  Compliant ACLs ---------------" | Out-String
            ForEach ($acl in $CompliantAcls) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------  Uncompliant Interfaces ---------------" | Out-String
            ForEach ($int in $UnCompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        else {
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

Function Get-V237771 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237771
        STIG ID    : CISC-RT-000395
        Rule ID    : SV-237771r856669_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000203
        Rule Title : The Cisco perimeter switch must be configured to drop IPv6 packets containing a Destination Option header with invalid option type values.
        DiscussMD5 : 78F792CD8713130D6E190E2BAD4D9105
        CheckMD5   : 91722F531FA1A14039A688948501E68C
        FixMD5     : E847A2C84CA6A08CFD2FFE4A94B13D02
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list"
    $CompliantAcls = @()
    $CompliantInterfaces = @()
    $UncompliantInterfaces = @()
    $ipv6_present = $False

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $aclCompliant = $True

        IF ($AccessListConfig -notcontains "deny 60 any any dest-option-type 5 log") {
            $aclCompliant = $False
        }
        elseif ($AccessListConfig -notcontains "deny 60 any any dest-option-type 194 log") {
            $aclCompliant = $False
        }

        If ($aclCompliant) {
            $AccessListName = ($AccessList -split " ")[2]
            $CompliantAcls += $AccessListName
        }
    }
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ipv6 address*") { 
            $CompliantInterface = $False
            $ipv6_present = $True

            forEach ($acl in $CompliantAcls) {
                if ($InterfaceConfig -contains "ipv6 traffic-filter $acl in") {
                    $CompliantInterface = $True
                    break
                }
            }
            if ($CompliantInterface) {
                $CompliantInterfaces += $Interface
            }
            else {
                $UncompliantInterfaces += $Interface
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces are configured on this device. This requirement does not apply." | Out-String
        $FindingDetails += "" | Out-String
    }
    elseif (!$CompliantAcls.count -gt 0){
        $Status = "Not_Reviewed"
        $FindingDetails += "There are IPv6 interfaces but no ACLs found on the device that drop IPv6 packets containing a Destination Option header with option type values of 0x05 (Switch Alert) or 0xC2 (Jumbo Payload)." | Out-String
        $FindingDetails += "Review the switch interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The following IPv6 interfaces are configured with a compliant ACL." | Out-String
            $FindingDetails += "---------------  Compliant Interfaces ---------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        if ($UnCompliantInterfaces.count -gt 0) {
            $Status = "Not_Reviewed"
            $FindingDetails += "The following IPv6 interfaces are not configured with a compliant ACL for this requirement. Verify that an inbound IPv6 ACL that drops IPv6 packets containing a Destination Option header with option type values of 0x05 (Switch Alert) or 0xC2 (Jumbo Payload) has been configured for all external IPv6 interfaces." | Out-String
            $FindingDetails += "---------------  Compliant ACLs ---------------" | Out-String
            ForEach ($acl in $CompliantAcls) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------  Uncompliant Interfaces ---------------" | Out-String
            ForEach ($int in $UnCompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        else {
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

Function Get-V237773 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237773
        STIG ID    : CISC-RT-000396
        Rule ID    : SV-237773r856671_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000204
        Rule Title : The Cisco perimeter switch must be configured to drop IPv6 packets containing an extension header with the Endpoint Identification option.
        DiscussMD5 : E5C7A9AE4D14F4BD2F188D81435C985F
        CheckMD5   : 8A6103883597BF76CF30BA946A3ECBD3
        FixMD5     : 7F3EE100C3AD13633774D95CDEE90216
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list"
    $CompliantAcls = @()
    $CompliantInterfaces = @()
    $UncompliantInterfaces = @()
    $ipv6_present = $False

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $aclCompliant = $True

        IF ($AccessListConfig -notcontains "deny any any dest-option-type 138 log") {
            $aclCompliant = $False
        }

        If ($aclCompliant) {
            $AccessListName = ($AccessList -split " ")[2]
            $CompliantAcls += $AccessListName
        }
    }
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ipv6 address*") { 
            $CompliantInterface = $False
            $ipv6_present = $True

            forEach ($acl in $CompliantAcls) {
                if ($InterfaceConfig -contains "ipv6 traffic-filter $acl in") {
                    $CompliantInterface = $True
                    break
                }
            }
            if ($CompliantInterface) {
                $CompliantInterfaces += $Interface
            }
            else {
                $UncompliantInterfaces += $Interface
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces are configured on this device. This requirement does not apply." | Out-String
        $FindingDetails += "" | Out-String
    }
    elseif (!$CompliantAcls.count -gt 0){
        $Status = "Not_Reviewed"
        $FindingDetails += "There are IPv6 interfaces but no ACLs found on the device that drop IPv6 packets containing an extension header option type value of 0x8A (decimal value: 138) (Endpoint Identification) regardless of whether it appears in a Hop-by-Hop or Destination Option header." | Out-String
        $FindingDetails += "Review the interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The following IPv6 interfaces are configured with a compliant ACL that drops IPv6 packets containing an extension header option type value of 0x8A (decimal value: 138) (Endpoint Identification)." | Out-String
            $FindingDetails += "---------------  Compliant Interfaces ---------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        if ($UnCompliantInterfaces.count -gt 0) {
            $Status = "Not_Reviewed"
            $FindingDetails += "The following IPv6 interfaces are not configured with a compliant ACL for this requirement. Verify that an inbound IPv6 ACL has been configured for all external IPv6 interfaces that drops IPv6 packets containing an extension header option type value of 0x8A (decimal value: 138) (Endpoint Identification), regardless of whether it appears in a Hop-by-Hop or Destination Option header." | Out-String
            $FindingDetails += "---------------  Compliant ACLs ---------------" | Out-String
            ForEach ($acl in $CompliantAcls) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------  Uncompliant Interfaces ---------------" | Out-String
            ForEach ($int in $UnCompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        else {
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

Function Get-V237775 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237775
        STIG ID    : CISC-RT-000397
        Rule ID    : SV-237775r856673_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000205
        Rule Title : The Cisco perimeter switch must be configured to drop IPv6 packets containing the NSAP address option within Destination Option header.
        DiscussMD5 : D9C7467C245639452E2AB647D504F034
        CheckMD5   : 6D6FDFB42D3E923A2D80023237FAAD74
        FixMD5     : C462C204BF4B313C768056168F893734
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list"
    $CompliantAcls = @()
    $CompliantInterfaces = @()
    $UncompliantInterfaces = @()
    $ipv6_present = $False

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $aclCompliant = $True

        IF ($AccessListConfig -notcontains "deny 60 any any dest-option-type 195 log") {
            $aclCompliant = $False
        }

        If ($aclCompliant) {
            $AccessListName = ($AccessList -split " ")[2]
            $CompliantAcls += $AccessListName
        }
    }
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ipv6 address*") { 
            $CompliantInterface = $False
            $ipv6_present = $True

            forEach ($acl in $CompliantAcls) {
                if ($InterfaceConfig -contains "ipv6 traffic-filter $acl in") {
                    $CompliantInterface = $True
                    break
                }
            }
            if ($CompliantInterface) {
                $CompliantInterfaces += $Interface
            }
            else {
                $UncompliantInterfaces += $Interface
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces are configured on this device. This requirement does not apply." | Out-String
        $FindingDetails += "" | Out-String
    }
    elseif (!$CompliantAcls.count -gt 0){
        $Status = "Not_Reviewed"
        $FindingDetails += "There are IPv6 interfaces but no ACLs found on the device that drop IPv6 packets containing the NSAP address option within Destination Option header." | Out-String
        $FindingDetails += "Review the interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The following IPv6 interfaces are configured with a compliant ACL that drops IPv6 packets containing the NSAP address option within Destination Option header." | Out-String
            $FindingDetails += "---------------  Compliant Interfaces ---------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        if ($UnCompliantInterfaces.count -gt 0) {
            $Status = "Not_Reviewed"
            $FindingDetails += "The following IPv6 interfaces are not configured with a compliant ACL for this requirement. Verify that an inbound IPv6 ACL has been configured for all external IPv6 interfaces that drops IPv6 packets containing the NSAP address option within Destination Option header." | Out-String
            $FindingDetails += "---------------  Compliant ACLs ---------------" | Out-String
            ForEach ($acl in $CompliantAcls) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------  Uncompliant Interfaces ---------------" | Out-String
            ForEach ($int in $UnCompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "All IPv6 interfaces are configured with a compliant ACL that drops IPv6 packets containing the NSAP address option within Destination Option header." | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V237777 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237777
        STIG ID    : CISC-RT-000398
        Rule ID    : SV-237777r856675_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000206
        Rule Title : The Cisco perimeter switch must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.
        DiscussMD5 : 2C86126E62F212E0E1D0BBED19FD8C89
        CheckMD5   : 86F9F60DBC8757B95EC90EC037710275
        FixMD5     : 66ABC4C493A0EFF73A530AA622908688
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list"
    $CompliantAcls = @()
    $CompliantInterfaces = @()
    $UncompliantInterfaces = @()
    $ipv6_present = $False

    $HeaderTypes = @('2', '3', '6', '9', '10', '11', '12', '13', '14', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '36', '37', '39', '40', '41', '42', '43', '44', '45', '46', '47', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '100', '101', '102', '103', '104', '105', '106', '107', '108', '109', '110', '111', '112', '113', '114', '115', '116', '117', '118', '119', '120', '121', '122', '123', '124', '125', '126', '127', '128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138', '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '149', '150', '151', '152', '153', '154', '155', '156', '157', '158', '159', '160', '161', '162', '163', '164', '165', '166', '167', '168', '169', '170', '171', '172', '173', '174', '175', '176', '177', '178', '179', '180', '181', '182', '183', '184', '185', '186', '187', '188', '189', '190', '191', '192', '193', '194', '195', '196', '197', '198', '199', '200', '201', '202', '203', '204', '205', '206', '207', '208', '209', '210', '211', '212', '213', '214', '215', '216', '217', '218', '219', '220', '221', '222', '223', '224', '225', '226', '227', '228', '229', '230', '231', '232', '233', '234', '235', '236', '237', '238', '239', '240', '241', '242', '243', '244', '245', '246', '247', '248', '249', '250', '251', '252', '253', '254', '255')

    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $aclCompliant = $True

        #Write-Output $AccessListConfig
        forEach ($type in $HeaderTypes){
            IF ($AccessListConfig -notcontains "deny any any dest-option-type $type") {
                $aclCompliant = $False
                break
            }
        }

        If ($aclCompliant) {
            $AccessListName = ($AccessList -split " ")[2]
            $CompliantAcls += $AccessListName
        }
    }
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()

        if ($InterfaceConfig -like "ipv6 address*") { 
            $CompliantInterface = $False
            $ipv6_present = $True

            forEach ($acl in $CompliantAcls) {
                if ($InterfaceConfig -contains "ipv6 traffic-filter $acl in") {
                    $CompliantInterface = $True
                    break
                }
            }
            if ($CompliantInterface) {
                $CompliantInterfaces += $Interface
            }
            else {
                $UncompliantInterfaces += $Interface
            }
        }
    }

    if (!$ipv6_present) {
        $Status = "NotAFinding"
        $FindingDetails += "No IPv6 interfaces are configured on this device. This requirement does not apply." | Out-String
        $FindingDetails += "" | Out-String
    }
    elseif (!$CompliantAcls.count -gt 0){
        $Status = "Not_Reviewed"
        $FindingDetails += "There are IPv6 interfaces but no ACLs found on the device that drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type." | Out-String
        $FindingDetails += "Review the switch interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        if ($CompliantInterfaces.count -gt 0) {
            $FindingDetails += "The following IPv6 interfaces are configured with a compliant ACL that drops IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type." | Out-String
            $FindingDetails += "---------------  Compliant Interfaces ---------------" | Out-String
            ForEach ($int in $CompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        if ($UnCompliantInterfaces.count -gt 0) {
            $Status = "Not_Reviewed"
            $FindingDetails += "The following IPv6 interfaces are not configured with a compliant ACL for this requirement. Verify that an inbound IPv6 ACL has been configured for all external IPv6 interfaces that drops IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type." | Out-String
            $FindingDetails += "---------------  Compliant ACLs ---------------" | Out-String
            ForEach ($acl in $CompliantAcls) {
                $FindingDetails += $acl.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "---------------  Uncompliant Interfaces ---------------" | Out-String
            ForEach ($int in $UnCompliantInterfaces) {
                $FindingDetails += $int.ToString() | Out-String
            }
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "All IPv6 interfaces are configured with a compliant ACL that drops IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type." | Out-String
            $FindingDetails += "" | Out-String
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

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBeA/0kS7IJRqIR
# 1yIeGdwQKJTZa+DkVi5MhWXbI2VAO6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCAv7o/NgDEXStxMJxvddnuiscT7Wk8O0FC4AaPo6JQfmzANBgkqhkiG9w0BAQEF
# AASCAQBHVp2BxqwlIfhmVRjge3MhH1DQ3XO8D6IWItEIlDVvge+71BtTOxfd6ozi
# HI6Q7+O7DwxHZHFvbtPBoOLs4t1C9oqz0Xx/0ju1D/LsEBOiuIOkI6q2jwTOkg39
# 1boUetGI7VQDmRSJ0C/w1NPC1IFSApJ2Ala1uRge5ETLAN739dXYTSO/B62XCS4t
# tOTdoYWUG0H53kIAOWGHEv6xKhHOcc8QxXebScjoMhrs1uMmapUVVaMr4v3BGwKK
# 6TA1p6FbTKIMeFYQXh4bRAQmgctnFR81J3IZrpe74Sazd2wUzuE1oc+LPTUEct0n
# dV68ACt0a33KLjzqK3YQj/P7uf5uoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTYzNVowLwYJKoZIhvcNAQkEMSIEIDUnY1Vfr1kHT37zIRM9+irwjqB5
# JXyfR3dzJZUjybwMMA0GCSqGSIb3DQEBAQUABIICAFlhvtlOz0aAw0OEtC+UqjCa
# CesJ8/HtBEEQf01n83222B6XoYM0e/HeZTxRSaYzIkCpGzeQVsPa/hfgUtr5An1l
# +Qfo5Mc0CO8mjeR/PNA9+3d8ozwcsab54Y0oG8aFHYbFJ4Lkx5NuT33T/qGL6KY1
# 7ztJeln8BYAMxu99ohnVm1ufR9YyL6kqRL7MWHoAsdOR1eNyGBhBUJUxpCrf6i19
# w1QBxXd24BBL/+emi6o9dzey4JRY8o3oT65C+vO8/otE1Gj1tmARrzvKWD1Mx3nw
# jbQBsUHX5yar9WFvs474CSKDB2wDV1GptHmV1b7xmahXhffgMciplbgwo1kaYbQd
# VH3CQX48Gko0OYkgFv4hba8/mkxqa5Ukf+zjzXCjFmy8FxxFJxv7NNvYJ6ZgpGwL
# vVmmxJQvYOLzQn/p2RF2ALPpSNO+WMyBIeHAGpx3NVPg48H/LXIKa0hBUkkx/AUz
# Vo0+MoYMogDVZX7UZFLJm1zcnF40XgKw2S8h3Q5kF7w387/AUFujyaRnncs4fa1+
# 8+jO5gvnwEiPnPbsxsT/9vqTmwKFCvUwgC/3H1zdeVHbjrShXfbvLP0DeBfI4kJ9
# grVWgw+P6tfjqQH7p6GWCHZE4RYkRNT00l1BLjyPIxAB+AS/brDg3NSRphYl17HD
# FDcU/Vam4BoReX/dxn4x
# SIG # End signature block
