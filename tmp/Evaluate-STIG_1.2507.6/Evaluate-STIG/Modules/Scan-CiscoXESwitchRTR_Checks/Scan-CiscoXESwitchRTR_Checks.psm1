##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XE Switch RTR
# Version:  V3R2
# Class:    UNCLASSIFIED
# Updated:  10/7/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V220986 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220986
        STIG ID    : CISC-RT-000010
        Rule ID    : SV-220986r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000001
        Rule Title : The Cisco switch must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.
        DiscussMD5 : 2627A00D35CBD072B0577A5CF3B6CD2B
        CheckMD5   : CA45AB4036617423659DF501564215E9
        FixMD5     : 9B546D72DE84DE61C6F8F3852DD06110
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*" -AND $_ -notlike "*Vlan*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "ip access-group * in")) {
            # Add interface with an inbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below interface requires an Access Control List (ACL) to allow or deny traffic for specific source and destination addresses as well as ports and protocols and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "Interface without an inbound ACL configured:" | Out-String
            $FindingDetails += "--------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            $ACLName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            IF (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound extended ACL $ACLName under $Interface is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify that the extended ACL $ACLName under $Interface is configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "ACL $ACLName entries:" | Out-String
                $FindingDetails += "-------------------------" | Out-String
                $FindingDetails += ($ACLConfig | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
    }

    # Get Vlan interface configuration.
    $VlanInterfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -like "*Vlan*"}
    ForEach ($VlanInterface in $VlanInterfaces) {
        $VlanInterfaceConfig = Get-Section $ShowRunningConfig $VlanInterface.ToString()
        IF (!($VlanInterfaceConfig -like "ip access-group * out")) {
            # Add Vlan interface with an outbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below Vlan interface requires an Access Control List (ACL) to allow or deny traffic for specific source and destination addresses as well as ports and protocols and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "Vlan interface without an outbound ACL configured:" | Out-String
            $FindingDetails += "--------------------------------------------------" | Out-String
            $FindingDetails += ($VlanInterface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            $VlanACLName = ($VlanInterfaceConfig | Select-String -Pattern "ip access-group .* out").ToString().Split([char[]]"") | Select-Object -Index 2
            $VlanACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $VlanACLName`$"
            IF (!$VlanACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Outbound extended ACL $VlanACLName under $VlanInterface is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $VlanACLConfig = Get-Section $ShowRunningConfig $VlanACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify that the extended ACL $VlanACLName under $VlanInterface is configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "ACL $VlanACLName entries:" | Out-String
                $FindingDetails += "-------------------------" | Out-String
                $FindingDetails += ($VlanACLConfig | Out-String).Trim()
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

Function Get-V220990 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220990
        STIG ID    : CISC-RT-000050
        Rule ID    : SV-220990r929064_rule
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
        $RouterIsis = $ShowRunningConfig | Select-String -Pattern "^router isis*"
        $RouterIsisConfig = Get-Section $ShowRunningConfig $RouterIsis.ToString()
        # Check if IS-IS authentication is configured
        $IsisAuth = $RouterIsisConfig | Select-String -Pattern "authentication key-chain.*"
        $IsisKeyChainName = ($RouterIsisConfig | Select-String -Pattern "authentication key-chain.*" | Out-String).Trim().Split([char[]]"")[-1]
        IF ($IsisAuth -AND $KeyChainAuth) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "IS-IS authentication using FIPS 198-1 algorithms is configured on this device, make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "---------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $RouterIsis | Out-String
            $FindingDetails += $RouterIsisConfig | Out-String
            IF (!($ShowRunningConfig | Select-String -Pattern "^key chain $IsisKeyChainName")) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Key Chain $IsisKeyChainName is not configured on this device. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
            }
            $Exception = $True
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "IS-IS authentication using FIPS 198-1 algorithms is not configured on this device. This is a finding." | Out-String
            $FindingDetails += "---------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $RouterIsis | Out-String
            $FindingDetails += $RouterIsisConfig | Out-String
            $OpenFinding = $True
        }
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

Function Get-V220991 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220991
        STIG ID    : CISC-RT-000060
        Rule ID    : SV-220991r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000007
        Rule Title : The Cisco switch must be configured to have all inactive layer 3 interfaces disabled.
        DiscussMD5 : 82D4CA9E3480119EF25CFC5004CA471B
        CheckMD5   : A19615ADF319B6C938A82CFD4CD1D186
        FixMD5     : 2ECDAABDB18D67EDFADAD8CCB240424B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V220994 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220994
        STIG ID    : CISC-RT-000090
        Rule ID    : SV-220994r856401_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000109
        Rule Title : The Cisco switch must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.
        DiscussMD5 : DE8491522A4956F725339F3D14CCB5A5
        CheckMD5   : 8422DD9C77A7AE24BF2B1EB530779FCC
        FixMD5     : 3D1DA785D9F7D5DABC07A7378A563E3E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $OpenFinding = $True
    }

    $BootConfig = $ShowRunningConfig | Select-String -Pattern "^boot"
    ForEach ($Item in $BootConfig) {
        IF ($Item.ToString() -contains "boot-start-marker" -or $Item.ToString() -contains "boot-end-marker" -or $Item.ToString() -like "boot network *") {
                # Add non-compliant configuration to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Review the device configuration to verify that auto-configuration is not configured on this device." | Out-String
                $FindingDetails += "Non-Compliant Configuration:" | Out-String
                $FindingDetails += "----------------------------" | Out-String
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
                $FindingDetails += "----------------------------" | Out-String
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

Function Get-V220995 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220995
        STIG ID    : CISC-RT-000120
        Rule ID    : SV-220995r1107540_rule
        CCI ID     : CCI-001097, CCI-002385, CCI-004866
        Rule Name  : SRG-NET-000362-RTR-000110
        Rule Title : The Cisco switch must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by employing control plane protection.
        DiscussMD5 : B5F6E45D5BC4A26AA0640B36C1A997AB
        CheckMD5   : 593584DAAF53A7FCEAAD7C70A40B9399
        FixMD5     : 9AF57860FCE8FFAEDEC0095E1B6EB8AE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V220998 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220998
        STIG ID    : CISC-RT-000150
        Rule ID    : SV-220998r856403_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000111
        Rule Title : The Cisco switch must be configured to have Gratuitous ARP disabled on all external interfaces.
        DiscussMD5 : 4079563A47158A2AC9D218FA97C791BA
        CheckMD5   : 957D2EE6963D40652B5377C8D1200EEF
        FixMD5     : 713C352C0B237960CA689F00F88E1A60
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    IF ($ShowRunningConfig -contains "no ip gratuitous-arps") {
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify that gratuitous-arps is globally disabled." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V220999 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220999
        STIG ID    : CISC-RT-000160
        Rule ID    : SV-220999r856404_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000112
        Rule Title : The Cisco switch must be configured to have IP directed broadcast disabled on all interfaces.
        DiscussMD5 : 31D7FBCAA33E64F05C8AE92E97F99A9E
        CheckMD5   : 79B55F548A19165D4334A88183812D28
        FixMD5     : 0F2FF97AFAF72B46B07EEE94F1CC7507
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221000 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221000
        STIG ID    : CISC-RT-000170
        Rule ID    : SV-221000r856405_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000113
        Rule Title : The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
        DiscussMD5 : AA3A075D2F7E7680BEECE67D356055DA
        CheckMD5   : 724D9ACDDC7438082590016661673745
        FixMD5     : B54492A23A3775B054B9EA12A40FB1CB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221001 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221001
        STIG ID    : CISC-RT-000180
        Rule ID    : SV-221001r856406_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000114
        Rule Title : The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) mask reply messages disabled on all external interfaces.
        DiscussMD5 : 06C6F1BE37F5426916FCDA003136A622
        CheckMD5   : 4A1ABCE6B08D9C67D296EF590E226407
        FixMD5     : 029B08F4D2E9ED78C69159C78ED9EBDD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221002 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221002
        STIG ID    : CISC-RT-000190
        Rule ID    : SV-221002r856407_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000115
        Rule Title : The Cisco switch must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.
        DiscussMD5 : 9EDE1F6BC31DD8CE1502AD5F7592EFD8
        CheckMD5   : 2754B0C1645BFABBD4B692692715F764
        FixMD5     : 16CE7E94A86D57A7E8AD667893DA9BA4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221003 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221003
        STIG ID    : CISC-RT-000200
        Rule ID    : SV-221003r622190_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-NET-000078-RTR-000001
        Rule Title : The Cisco switch must be configured to log all packets that have been dropped at interfaces via an ACL.
        DiscussMD5 : FE94D3A3F2DBEE19BA50B5E322FE11F4
        CheckMD5   : 1E581656D60E48BABC1181A6EF10FFD3
        FixMD5     : E1C42C33D2B685D636027E92F9DCD10F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "-------------------------------------------" | Out-String
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

Function Get-V221004 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221004
        STIG ID    : CISC-RT-000210
        Rule ID    : SV-221004r622190_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-NET-000076-RTR-000001
        Rule Title : The Cisco switch must be configured to produce audit records containing information to establish where the events occurred.
        DiscussMD5 : 5EB63DA363AD02FDA6364550A83BCD02
        CheckMD5   : 5FE7D7CABDADED286983AD7A2D9DD52E
        FixMD5     : 7823036447AA2E032974EDD4A90050F9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        IF (!($AccessListConfig -like "deny[ ]*ip any any log-input")) {
            # Add non-compliant Access List to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the device configuration to verify that ACLs log-input dropped packets." | Out-String
            $FindingDetails += "ACL not logging-input dropped packets:" | Out-String
            $FindingDetails += "--------------------------------------" | Out-String
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

Function Get-V221005 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221005
        STIG ID    : CISC-RT-000220
        Rule ID    : SV-221005r622190_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-NET-000077-RTR-000001
        Rule Title : The Cisco switch must be configured to produce audit records containing information to establish the source of the events.
        DiscussMD5 : 43B48607F27628D3CE3E18F07250F3B8
        CheckMD5   : 2CE2509577D6D18D65D568DEB7E25799
        FixMD5     : 7823036447AA2E032974EDD4A90050F9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Get extended Access Lists
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $AccessListConfig = ($AccessListConfig -split "[\r\n]+")
        # Add non-compliant ACEs to DenyRules
        ForEach ($Rule in $AccessListConfig) {
            IF (($Rule -like "deny*") -AND !($Rule -like "deny[ ]* log-input")) {
                $DenyRules += "" | Out-String
                $DenyRules += $Rule
            }
        }
        IF ($DenyRules) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the device configuration to verify that ACLs log-input dropped packets." | Out-String
            $FindingDetails += "ACL not logging-input dropped packets:" | Out-String
            $FindingDetails += "--------------------------------------" | Out-String
            $FindingDetails += ($AccessList.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($DenyRules | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
            Clear-Variable -Name "DenyRules"
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

Function Get-V221006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221006
        STIG ID    : CISC-RT-000230
        Rule ID    : SV-221006r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000001
        Rule Title : The Cisco switch must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.
        DiscussMD5 : A5534A3D5856DF9C28AC602819D621B6
        CheckMD5   : B2F5B029011605E74C87F6256FDA31FD
        FixMD5     : B6F0C6C5CEA9CD1ED307AEFB64E85262
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $LineAux = $ShowRunningConfig | Select-String -Pattern "line aux"
    IF ($LineAux) {
        $LineAuxConfig = Get-Section $ShowRunningConfig $LineAux.ToString()
        IF (!(Get-Section $ShowRunningConfig $LineAux[0].ToString() | Select-String -Pattern "no exec")) {
            $FindingDetails += "'no exec' is not configured under 'line aux':" | Out-String
            $FindingDetails += ($LineAux[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LineAuxConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "'no exec' is configured under 'line aux':" | Out-String
            $FindingDetails += ($LineAux[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LineAuxConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "'line aux' is not available on this device." | Out-String
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

Function Get-V221007 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221007
        STIG ID    : CISC-RT-000240
        Rule ID    : SV-221007r622190_rule
        CCI ID     : CCI-001109
        Rule Name  : SRG-NET-000202-RTR-000001
        Rule Title : The Cisco perimeter switch must be configured to deny network traffic by default and allow network traffic by exception.
        DiscussMD5 : BD6C5D26E27B8378AECB288BE03FB0BA
        CheckMD5   : 16F32D7AF23F0F6797EF645346C19B4B
        FixMD5     : 11602B89411F7EDF4FBFA22B28231EC9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $ACLName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            IF (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound extended ACL $ACLName under $Interface is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify that the extended ACL $ACLName under $Interface is configured to allow specific ports and protocols and deny all other traffic and make finding determination based on STIG check guidance." | Out-String
                IF (!($ACLConfig -like "deny[ ]*ip any any log-input")) {
                    $FindingDetails += "ACL $ACLName missing 'deny ip any any log-input' entry." | Out-String
                }
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

Function Get-V221008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221008
        STIG ID    : CISC-RT-000250
        Rule ID    : SV-221008r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000002
        Rule Title : The Cisco perimeter switch must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.
        DiscussMD5 : 7B12A94F29411F2A04A973527CEE8F9E
        CheckMD5   : B80564E0C4C6228FA7258105B00827CE
        FixMD5     : ABAA5BDC16F2A048959119D5342B6282
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            IF ($InterfaceConfig | Select-String -Pattern "ip access-group .* in") {
                $ACLInName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
                $IPACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLInName`$"
                IF (!$IPACL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound extended ACL $ACLInName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $IPACL.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify that the inbound extended ACL $ACLInName under $Interface is configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols, and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "ACL $ACLInName entries:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($ACLConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
            }
            IF ($InterfaceConfig | Select-String -Pattern "ip access-group .* out") {
                $ACLOutName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* out").ToString().Split([char[]]"") | Select-Object -Index 2
                $IPACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLOutName`$"
                IF (!$IPACL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Outbound extended ACL $ACLOutName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $IPACL.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify that the outbound extended ACL $ACLOutName under $Interface is configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols, and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V221009 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221009
        STIG ID    : CISC-RT-000260
        Rule ID    : SV-221009r856408_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000109
        Rule Title : The Cisco perimeter switch must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
        DiscussMD5 : 9E59E8507CA5444C61ADBB01991CE2A5
        CheckMD5   : BFB9195BE473E5CD2586AC0E9D8BE969
        FixMD5     : 72D1449554E08ADCE0B6262D89DFA3DA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "Review the below extended ACL configuration to verify that it allows only incoming communications from authorized sources to be routed to authorized destinations and make finding determination based on STIG check guidance." | Out-String
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
            $FindingDetails += "Interface without an inbound extended ACL configured:" | Out-String
            $FindingDetails += "-----------------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $ACLInName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
            $IPACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLInName`$"
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interface with an inbound extended ACL configured:" | Out-String
            $FindingDetails += "--------------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
            IF (!$IPACL) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound extended ACL $ACLInName under $Interface is not configured." | Out-String
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

Function Get-V221010 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221010
        STIG ID    : CISC-RT-000270
        Rule ID    : SV-221010r863263_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000110
        Rule Title : The Cisco perimeter switch must be configured to block inbound packets with source Bogon IP address prefixes.
        DiscussMD5 : FF2A4B7629939398BC463DF86378208A
        CheckMD5   : 76FD4270C4D6A42BC3624C5ECF970F55
        FixMD5     : 4BD28E68009BEBA365132351699D5196
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221011 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221011
        STIG ID    : CISC-RT-000310
        Rule ID    : SV-221011r945858_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-NET-000205-RTR-000014
        Rule Title : The Cisco perimeter switch must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).
        DiscussMD5 : BA90E01D1101968C0B7A8B9F767969E3
        CheckMD5   : C9399DE2254C90EFF3038895CA575B51
        FixMD5     : 07F836D32091AAD4719E632ED6EEBC8A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221012 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221012
        STIG ID    : CISC-RT-000320
        Rule ID    : SV-221012r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000003
        Rule Title : The Cisco perimeter switch must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.
        DiscussMD5 : 872F88D12AA903D5B55AB9E43F14A0C7
        CheckMD5   : 585D80C753C82E738DB4234437D35AEC
        FixMD5     : 1B01F4BBC3A8D213831AD558E21E1272
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221013 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221013
        STIG ID    : CISC-RT-000330
        Rule ID    : SV-221013r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000004
        Rule Title : The Cisco perimeter switch must be configured to filter ingress traffic at the external interface on an inbound direction.
        DiscussMD5 : 1B5C959D3CA0527E1C271C30B753C58F
        CheckMD5   : F6295466FB7D1CECDCF99C468FE33276
        FixMD5     : 3F2BF47D81538B34AD393DEB9BA8C9EB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221014 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221014
        STIG ID    : CISC-RT-000340
        Rule ID    : SV-221014r622190_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000005
        Rule Title : The Cisco perimeter switch must be configured to filter egress traffic at the internal interface on an inbound direction.
        DiscussMD5 : 1B5C959D3CA0527E1C271C30B753C58F
        CheckMD5   : FA36F432842AE3E9EFB41A810879F834
        FixMD5     : 08E60B4E9C6E00382DFE992B9A900378
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221015 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221015
        STIG ID    : CISC-RT-000350
        Rule ID    : SV-221015r945859_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000205-RTR-000015
        Rule Title : The Cisco perimeter switch must be configured to block all packets with any IP options.
        DiscussMD5 : 941923D93D4666FE1805050E1E891CF1
        CheckMD5   : BB99DB31BAE207E94616CC01A2988A69
        FixMD5     : C9DA4C938DA4BB05CC1D0D33D9A28F36
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221016 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221016
        STIG ID    : CISC-RT-000360
        Rule ID    : SV-221016r856411_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter switch must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
        DiscussMD5 : 9686FAA1FFFDDD9061691F27E8E6CBAF
        CheckMD5   : BC083C36FDE29C76C3751AC4E7BDF83E
        FixMD5     : 671341D858253EA6C08B8B43F6FB98D5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*" -AND $_ -notlike "*Vlan*"}
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -like "no lldp transmit")) {
                # Add non-compliant interface to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below is an external interface and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without 'no lldp transmit' configured:" | Out-String
                $FindingDetails += "------------------------------------------------" | Out-String
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

Function Get-V221017 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221017
        STIG ID    : CISC-RT-000370
        Rule ID    : SV-221017r856412_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter switch must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.
        DiscussMD5 : B622A1DBC9427DFC1F0592B380D90509
        CheckMD5   : 975CF017B5DA194AF9C37B33A31CE4D6
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
    $OpenFinding = $False

    IF ($ShowRunningConfig | Select-String -Pattern "^no cdp run") {
        $FindingDetails += "" | Out-String
        $FindingDetails += "CDP is not enabled on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get interfaces configuration.
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*" -AND $_ -notlike "*Vlan*" -AND $_ -notlike "*Port-channel*"}
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -like "no cdp enable")) {
                # Add non-compliant interface to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below is an external interface and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without 'no cdp enabled' configured:" | Out-String
                $FindingDetails += "----------------------------------------------" | Out-String
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

Function Get-V221018 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221018
        STIG ID    : CISC-RT-000380
        Rule ID    : SV-221018r856413_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000112
        Rule Title : The Cisco perimeter switch must be configured to have Proxy ARP disabled on all external interfaces.
        DiscussMD5 : 8BAFD16B3A596CD096CA9698F1242E73
        CheckMD5   : 5965D9FB10EAED20CF31C4DBF927F137
        FixMD5     : B4CB5A96DE5205A779898C883430D6D2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "no ip proxy-arp")) {
            # Add non-compliant interface to inventory
            $NonCompliantInt += ($Interface | Out-String).Trim()
            $OpenFinding = $True
        }
        Else {
            # Add compliant interface to inventory
            $CompliantInt += ($Interface | Out-String).Trim()
        }
    }

    IF ($NonCompliantInt) {
        $OpenFinding = $True
        $FindingDetails += "Review the device configuration to verify that 'no ip proxy-arp' is enabled on all external interfaces:" | Out-String
        $FindingDetails += "Interfaces without 'no ip proxy-arp' enabled:" | Out-String
        $FindingDetails += "---------------------------------------------" | Out-String
        ForEach ($Interface in $NonCompliantInt) {
            $FindingDetails += $Interface | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    IF ($CompliantInt) {
        $FindingDetails += "Compliant Interfaces:" | Out-String
        $FindingDetails += "---------------------" | Out-String
        ForEach ($Interface in $CompliantInt) {
            $FindingDetails += $Interface | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V221019 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221019
        STIG ID    : CISC-RT-000390
        Rule ID    : SV-221019r945857_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000364-RTR-000113
        Rule Title : The Cisco perimeter switch must be configured to block all outbound management traffic.
        DiscussMD5 : A869964F5D48C9EF4C880FFA61D569BD
        CheckMD5   : E0CAE2592B63CC31E10232C187B22177
        FixMD5     : 9F5461A27B956338B02E12C4B26DC7B8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        IF (!($InterfaceConfig -like "ip access-group * out")) {
            # Add interface with PIM but without an inbound ACL to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below is an external interface and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "Interface without an outbound ACL configured:" | Out-String
            $FindingDetails += "---------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            $ACLName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* out").ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            IF (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Outbound extended ACL $ACLName under $Interface is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify that the extended ACL $ACLName under $Interface is configured to block all management traffic and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V221020 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221020
        STIG ID    : CISC-RT-000450
        Rule ID    : SV-221020r991945_rule
        CCI ID     : CCI-001097, CCI-004891
        Rule Name  : SRG-NET-000205-RTR-000012
        Rule Title : The Cisco switch must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface.
        DiscussMD5 : E19B70837C37C18058E6A6F2087AE72E
        CheckMD5   : 28995F5C92A32A0CCFFCC0267C8B367D
        FixMD5     : 5E785B4C3517C738CB58BB4C2AB26F65
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221021 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221021
        STIG ID    : CISC-RT-000470
        Rule ID    : SV-221021r856414_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000124
        Rule Title : The Cisco BGP switch must be configured to enable the Generalized TTL Security Mechanism (GTSM).
        DiscussMD5 : E3DF9D64A043828876EDDDFE19180192
        CheckMD5   : 946B0B8FCD07AAB7E98DB8C7A6B46199
        FixMD5     : C9D762A2441C519F93F8571D3A02C6F1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get main BGP table configuration.
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
        $IP = @()
        $BgpConfig = @()
        ForEach ($Entry in $RouterBgpConfig) {
            $NewBgpConfig += $Entry | Out-String
            # Get IP addresses from main BGP table.
            IF ($Entry | Select-String -Pattern "remote-as*") {
                $IP += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Replace("neighbor ", "").Split([char[]]"")[0]
            }
            ELSEIF ($Entry | Select-String -Pattern "address-family ipv4") {
                Break
            }
        }
        IF ($NewBgpConfig) {
            $NewBgpConfig = ($NewBgpConfig -split "[\r\n]+")
            # Check for TTL security from every BGP neighbor on the main BGP table.
            IF ($IP) {
                ForEach ($Entry in $IP) {
                    IF (!($NewBgpConfig | Select-String -Pattern "neighbor $Entry ttl-security hops 1$") -AND !($NewBgpConfig | Select-String -Pattern "neighbor $Entry remote-as $BgpAS")) {
                        # Add non-compliant BGP Neighbors to FindingDetails
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the device configuration to verify that all external BGP neighbors and Peer Groups have TTL Security properly configured." | Out-String
                        $FindingDetails += "eBGP neighbor or Peer Group with TTL Security not configured or not equal to 1:" | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
                        IF ($NewBgpConfig | Select-String -Pattern "neighbor $Entry ttl-security hops") {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += (($NewBgpConfig | Select-String -Pattern "neighbor $Entry ttl-security hops") | Out-String).Trim()
                        }
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
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
        # Check for TTL security from every BGP neighbor on each VRF.
        $IPVrf = @()
        ForEach ($Entry in $RouterBgpVrfConfig) {
            # Get config from BGP VRF.
            $NewBgpVrfConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "remote-as*") {
                # Get IP addresses from BGP VRFs.
                $IPVrf += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Replace("neighbor ", "").Split([char[]]"")[0]
            }
            ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                ForEach ($Entry in $IPVrf) {
                    IF (!($NewBgpVrfConfig | Select-String -Pattern "neighbor $Entry ttl-security hops 1$") -AND !($NewBgpVrfConfig | Select-String -Pattern "neighbor $Entry remote-as $BgpAS")) {
                        # Add non-compliant BGP VRF Neighbors to FindingDetails
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the device configuration to verify that all external BGP neighbors and Peer Groups in VRFs have TTL Security properly configured." | Out-String
                        $FindingDetails += "eBGP neighbor or Peer Group in VRF $Vrf with no TTL Security configured or not equal to 1:" | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
                        IF ($NewBgpVrfConfig | Select-String -Pattern "neighbor $Entry ttl-security hops") {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += (($NewBgpVrfConfig | Select-String -Pattern "neighbor $Entry ttl-security hops") | Out-String).Trim()
                        }
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
                IF ($NewBgpVrfConfig) {
                    Clear-Variable -Name "NewBgpVrfConfig"
                }
                IF ($IPVrf) {
                    Clear-Variable -Name "IPVrf"
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221022 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221022
        STIG ID    : CISC-RT-000480
        Rule ID    : SV-221022r945862_rule
        CCI ID     : CCI-000366, CCI-002205
        Rule Name  : SRG-NET-000230-RTR-000002
        Rule Title : The Cisco BGP switch must be configured to use a unique key for each autonomous system (AS) that it peers with.
        DiscussMD5 : 61A61BCDF3CC1AF638D5627970244406
        CheckMD5   : D9924D70A1FA528B2AC91F99D750A5F9
        FixMD5     : AE293F17013AC14A44562EF4C258AF9C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get main BGP table configuration.
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        $IP = @()
        $ASList = @()
        $BgpConfig = @()
        ForEach ($Entry in $RouterBgpConfig) {
            $NewBgpConfig += $Entry | Out-String
            # Get IP addresses from main BGP table.
            IF ($Entry | Select-String -Pattern "remote-as*") {
                $IP += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Replace("neighbor ", "").Split([char[]]"")[0]
                # Get Autonomous Systems.
                $ASList += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Split([char[]]"")[-1]
            }
            ELSEIF ($Entry | Select-String -Pattern "address-family ipv4") {
                Break
            }
        }
        IF ($NewBgpConfig) {
            $NewBgpConfig = ($NewBgpConfig -split "[\r\n]+")
            # Check every BGP neighbor from the main BGP table for password configuration.
            IF ($IP) {
                ForEach ($Entry in $IP) {
                    $EbgpAS = (($NewBgpConfig | Select-String -Pattern "neighbor $Entry remote-as*" | Out-String).Trim()).Split([char[]]"")[-1]
                    IF ($BgpAS -ne $EbgpAS) {
                        IF (!($NewBgpConfig | Select-String -Pattern "neighbor $Entry password")) {
                            # Add non-compliant BGP Neighbors to FindingDetails
                            $FindingDetails += "" | Out-String
                            IF (($ASList | Get-Unique).Count -gt 1) {
                                $FindingDetails += "Review the device configuration to verify that all external BGP neighbors and Peer Groups peering with multiple AS have different passwords." | Out-String
                            }
                            ELSE {
                                $FindingDetails += "Review the device configuration to verify that all external BGP neighbors and Peer Groups have a password." | Out-String
                            }
                            $FindingDetails += "BGP neighbor or Peer Group with no password:" | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                        ELSE {
                            IF (($ASList | Get-Unique).Count -gt 1) {
                                # Add BGP Neighbors with passwords to FindingDetails (show-tech file does not provide the BGP passwords).
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Review the device configuration to verify that all external BGP neighbors and Peer Groups peering with multiple AS have different passwords." | Out-String
                                $FindingDetails += "BGP neighbor or Peer Group with password:" | Out-String
                                $FindingDetails += "-----------------------------------------" | Out-String
                                $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                    }
                }
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
        # Check every BGP neighbor from each VRF for password configuration.
        $IPVrf = @()
        $ASListVrf = @()
        ForEach ($Entry in $RouterBgpVrfConfig) {
            # Get config from BGP VRF.
            $NewBgpVrfConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "remote-as*") {
                # Get IP addresses from BGP VRF.
                $IPVrf += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Replace("neighbor ", "").Split([char[]]"")[0]
                $IPVrf += "" | Out-String
                # Get Autonomous Systems.
                $ASListVrf += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Split([char[]]"")[-1]
                $ASListVrf += "" | Out-String
            }
            ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                $IPVrf = ($IPVrf -split "[\r\n]+") | Where-Object { $_ -ne "" }
                $ASListVrf = ($ASListVrf -split "[\r\n]+") | Where-Object { $_ -ne "" }
                $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                ForEach ($Item in $IPVrf) {
                    $EbgpVrfAS = (($NewBgpVrfConfig | Select-String -Pattern "neighbor $Item remote-as*" | Out-String).Trim()).Split([char[]]"")[-1]
                    IF ($BgpAS -ne $EbgpVrfAS) {
                        IF (!($NewBgpVrfConfig | Select-String -Pattern "neighbor $Item password")) {
                            # Add non-compliant BGP VRF Neighbors to FindingDetails
                            $FindingDetails += "" | Out-String
                            IF (($ASListVrf | Get-Unique).Count -gt 1) {
                                $FindingDetails += "Review the device configuration to verify that all external BGP VRF neighbors and Peer Groups peering with multiple AS have different passwords." | Out-String
                            }
                            ELSE {
                                $FindingDetails += "Review the device configuration to verify that all external BGP VRF neighbors and Peer Groups have a password." | Out-String
                            }
                            $FindingDetails += "BGP neighbor or Peer Group in VRF $Vrf with no password:" | Out-String
                            $FindingDetails += "--------------------------------------------------------" | Out-String
                            $FindingDetails += ("neighbor $Item" | Out-String).Trim()
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                        ELSE {
                            IF (($ASListVrf | Get-Unique).Count -gt 1) {
                                # Add BGP VRF Neighbors with passwords to FindingDetails (show-tech file does not provide the BGP passwords).
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Review the device configuration to verify that all external BGP VRF neighbors and Peer Groups peering with multiple AS have different passwords." | Out-String
                                $FindingDetails += "BGP neighbor or Peer Group in VRF $Vrf with password:" | Out-String
                                $FindingDetails += "-----------------------------------------------------" | Out-String
                                $FindingDetails += ("neighbor $Item" | Out-String).Trim()
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                    }
                }
                IF ($NewBgpVrfConfig) {
                    Clear-Variable -Name "NewBgpVrfConfig"
                }
                IF ($IPVrf) {
                    Clear-Variable -Name "IPVrf"
                }
                IF ($ASListVrf) {
                    Clear-Variable -Name "ASListVrf"
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221023 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221023
        STIG ID    : CISC-RT-000490
        Rule ID    : SV-221023r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000002
        Rule Title : The Cisco BGP switch must be configured to reject inbound route advertisements for any Bogon prefixes.
        DiscussMD5 : FE9D220A578DA4091F65B58176564E96
        CheckMD5   : 6FF218AAFE50B1BD83CE3DC9F23EFEFF
        FixMD5     : D3AB539BAE5DDC75049AD3C7227DFA81
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Check if Prefix Lists with Bogon prefixes are configured
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .* deny 0.0.0.0/8 le 32")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Prefix List for Bogon prefixes is not properly configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get Prefix List Names
            $PrefixLists = ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .* deny 0.0.0.0/8 le 32")
            $PrefixListNames = @()
            ForEach ($PrefixList in $PrefixLists) {
                $PrefixListNames += ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
            }
            # Get Prefix List Configs
            $PrefixListConfig = @()
            $BgpNeighbor = @()
            $NewBgpConfig = @()
            ForEach ($PrefixListName in $PrefixListNames) {
                $PrefixListConfig += ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PrefixListName .*" | Out-String)
                $PrefixListConfig = ($PrefixListConfig -split "[\r\n]+") | Where-Object { $_ -ne "" }
                # Check if remaining Bogon prefixes are configured in the Prefix List.
                IF (!($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 10.0.0.0/8 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 100.64.0.0/10 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 127.0.0.0/8 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 169.254.0.0/16 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 172.16.0.0/12 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 192.0.2.0/24 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 192.88.99.0/24 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 192.168.0.0/16 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 198.18.0.0/15 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 198.51.100.0/24 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 203.0.113.0/24 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 224.0.0.0/4 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* deny 240.0.0.0/4 le 32") -OR !($PrefixListConfig | Select-String -Pattern "ip prefix-list .* permit 0.0.0.0/0 ge 8`$")) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The below Prefix List $PrefixListName is not properly configured for Bogon prefixes on this device:" | Out-String
                    $FindingDetails += "---------------------------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $PrefixListConfig | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Get main BGP table configuration.
                    $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
                    $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
                    $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
                    ForEach ($Entry in $RouterBgpConfig) {
                        $NewBgpConfig += $Entry | Out-String
                        # Get BGP neighbors from main BGP table.
                        IF ($Entry | Select-String -Pattern "remote-as*") {
                            $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                        }
                        ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                            Break
                        }
                    }
                    IF ($NewBgpConfig) {
                        ForEach ($Entry in $BgpNeighbor) {
                            $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                            $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                            # eBGP neighbors
                            IF ($BgpAS -ne $EbgpAS) {
                                IF (!($NewBgpConfig | Select-String -Pattern "neighbor $IP prefix-list $PrefixListName in") -AND !($NewBgpConfig | Select-String -Pattern "neighbor $IP route-map .* in")) {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Prefix List $PrefixListName or route map is not properly configured on neighbor $IP in main BGP Table." | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                }
                                ELSE {
                                    IF ($NewBgpConfig | Select-String -Pattern "neighbor $IP route-map .* in") {
                                        $RouteMapConfig = @()
                                        $RouteMapName = ((($NewBgpConfig | Select-String -Pattern "neighbor $IP route-map .* in" | Out-String).Trim())).Split([char[]]"")[-2]
                                        $RouteMaps = $ShowRunningConfig | Select-String -Pattern "^route-map $RouteMapName permit"
                                        IF (!($RouteMaps)) {
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "Route-map $RouteMapName applied to neighbor $IP in main BGP Table is not configured to permit prefix-filter $PrefixListName." | Out-String
                                            $FindingDetails += "" | Out-String
                                            $OpenFinding = $True
                                        }
                                        ELSE {
                                            ForEach ($RouteMap in $RouteMaps) {
                                                $RouteMapConfig += Get-Section $ShowRunningConfig $RouteMap.ToString()
                                            }
                                            IF (!($RouteMapConfig | Select-String -Pattern "match ip address prefix-list $PrefixListName$")) {
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "Route-map $RouteMapName applied to neighbor $IP in main BGP Table is not properly configured for Bogon prefixes." | Out-String
                                                $FindingDetails += "Permit statements." | Out-String
                                                $FindingDetails += "------------------" | Out-String
                                                $FindingDetails += $RouteMapConfig | Out-String
                                                $FindingDetails += "" | Out-String
                                                $OpenFinding = $True
                                            }
                                            ELSE {
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "Route-map $RouteMapName applied to neighbor $IP in main BGP Table is properly configured for Bogon prefixes." | Out-String
                                                $FindingDetails += "" | Out-String
                                            }
                                        }
                                        IF ($RouteMapConfig) {
                                            Clear-Variable -Name "RouteMapConfig"
                                        }
                                    }
                                    IF ($NewBgpConfig | Select-String -Pattern "neighbor $IP prefix-list $PrefixListName in") {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "Prefix List $PrefixListName applied to neighbor $IP in main BGP Table is properly configured for Bogon prefixes." | Out-String
                                        $FindingDetails += "" | Out-String
                                    }
                                    ELSE {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "Prefix List $PrefixListName configured for Bogon prefixes, is not applied to neighbor $IP in main BGP Table." | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                    }
                                }
                            }
                        }
                    }
                    # Get BGP VRFs configuration.
                    $BgpVrfNeighbor = @()
                    $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
                    IF ($RouterBgpVrf) {
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
                        # Get neighbors from BGP VRFs.
                        ForEach ($Entry in $RouterBgpVrfConfig) {
                            # Get config from BGP VRF.
                            $NewBgpVrfConfig += $Entry | Out-String
                            IF ($Entry | Select-String -Pattern "remote-as*") {
                                # Get neighbors from BGP VRFs
                                $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                                $BgpVrfNeighbor += "" | Out-String
                            }
                            ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                                $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                                $BgpVrfNeighbor = ($BgpVrfNeighbor -split "[\r\n]+") | Where-Object { $_ -ne "" }
                                $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                                ForEach ($Entry in $BgpVrfNeighbor) {
                                    $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                                    $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                                    # eBGP VRF neighbors
                                    IF ($BgpAS -ne $EbgpVrfAS) {
                                        IF (!($NewBgpVrfConfig | Select-String -Pattern "neighbor $IPVrf prefix-list $PrefixListName in") -AND !($NewBgpVrfConfig | Select-String -Pattern "neighbor $IPVrf route-map .* in")) {
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "Prefix List $PrefixListName or route map is not properly configured on neighbor $IPVrf in BGP VRF $Vrf." | Out-String
                                            $FindingDetails += "" | Out-String
                                            $OpenFinding = $True
                                        }
                                        ELSE {
                                            IF ($NewBgpVrfConfig | Select-String -Pattern "neighbor $IPVrf route-map .* in") {
                                                $RouteMapVrfConfig = @()
                                                $RouteMapVrfName = ((($NewBgpVrfConfig | Select-String -Pattern "neighbor $IPVrf route-map .* in" | Out-String).Trim())).Split([char[]]"")[-2]
                                                $RouteMapsVrf = $ShowRunningConfig | Select-String -Pattern "^route-map $RouteMapVrfName permit"
                                                IF (!($RouteMapsVrf)) {
                                                    $FindingDetails += "" | Out-String
                                                    $FindingDetails += "Route-map $RouteMapVrfName applied to neighbor $IPVrf in BGP VRF $Vrf is not configured to permit prefix-filter $PrefixListName." | Out-String
                                                    $FindingDetails += "" | Out-String
                                                    $OpenFinding = $True
                                                }
                                                ELSE {
                                                    ForEach ($RouteMapVrf in $RouteMapsVrf) {
                                                        $RouteMapVrfConfig += Get-Section $ShowRunningConfig $RouteMapVrf.ToString()
                                                    }
                                                    IF (!($RouteMapVrfConfig | Select-String -Pattern "match ip address prefix-list $PrefixListName$")) {
                                                        $FindingDetails += "" | Out-String
                                                        $FindingDetails += "Route-map $RouteMapVrfName applied to neighbor $IPVrf in BGP VRF $Vrf is not properly configured for Bogon prefixes." | Out-String
                                                        $FindingDetails += "Permit statements." | Out-String
                                                        $FindingDetails += "------------------" | Out-String
                                                        $FindingDetails += $RouteMapVrfConfig | Out-String
                                                        $FindingDetails += "" | Out-String
                                                        $OpenFinding = $True
                                                    }
                                                    ELSE {
                                                        $FindingDetails += "" | Out-String
                                                        $FindingDetails += "Route-map $RouteMapVrfName applied to neighbor $IPVrf in BGP VRF $Vrf is properly configured for Bogon prefixes." | Out-String
                                                        $FindingDetails += "" | Out-String
                                                    }
                                                }
                                                IF ($RouteMapVrfConfig) {
                                                    Clear-Variable -Name "RouteMapVrfConfig"
                                                }
                                            }
                                            IF ($NewBgpVrfConfig | Select-String -Pattern "neighbor $IPVrf prefix-list $PrefixListName in") {
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "Prefix List $PrefixListName applied to neighbor $IPVrf in BGP VRF $Vrf is properly configured for Bogon prefixes." | Out-String
                                                $FindingDetails += "" | Out-String
                                            }
                                            ELSE {
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "Prefix List $PrefixListName configured for Bogon prefixes, is not applied to neighbor $IPVrf in BGP VRF $Vrf." | Out-String
                                                $FindingDetails += "" | Out-String
                                                $OpenFinding = $True
                                            }
                                        }
                                    }
                                }
                                IF ($NewBgpVrfConfig) {
                                    Clear-Variable -Name "NewBgpVrfConfig"
                                }
                                IF ($BgpVrfNeighbor) {
                                    Clear-Variable -Name "BgpVrfNeighbor"
                                }
                                IF ($IPVrf) {
                                    Clear-Variable -Name "IPVrf"
                                }
                                IF ($Vrf) {
                                    Clear-Variable -Name "Vrf"
                                }
                                IF ($EbgpVrfAS) {
                                    Clear-Variable -Name "EbgpVrfAS"
                                }
                                continue
                            }
                        }
                    }
                }
                IF ($PrefixListConfig) {
                    Clear-Variable -Name "PrefixListConfig"
                }
                IF ($BgpNeighbor) {
                    Clear-Variable -Name "BgpNeighbor"
                }
                IF ($NewBgpConfig) {
                    Clear-Variable -Name "NewBgpConfig"
                }
                IF ($BgpVrfNeighbor) {
                    Clear-Variable -Name "BgpVrfNeighbor"
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

Function Get-V221024 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221024
        STIG ID    : CISC-RT-000500
        Rule ID    : SV-221024r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000003
        Rule Title : The Cisco BGP switch must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).
        DiscussMD5 : A76D5E2E8B1184183E2E2B4C5DB07411
        CheckMD5   : EC3A260940B1E2DFB27D224290C8FF03
        FixMD5     : A1FF560EA024CEE48E4D7DAC33ECA0A5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Check if Prefix Lists are configured
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Prefix Lists are not configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get Prefix List Names
            $PrefixLists = ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")
            $PrefixListNames = @()
            ForEach ($PrefixList in $PrefixLists) {
                $NewPrefixList = ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                IF ($NewPrefixList -notin $PrefixListNames) {
                    $PrefixListNames += ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                }
            }
            # Get Prefix List Configs
            $PrefixListConfig = @()
            $BgpNeighbor = @()
            $BgpNeighborPL = @()
            $NewBgpConfig = @()
            ForEach ($PrefixListName in $PrefixListNames) {
                $PrefixListConfig += ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PrefixListName .*" | Out-String)
            }
            # Check if Prefix List have prefixes belonging to the local AS.
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below Prefix Lists are configured containing prefixes belonging to the local AS and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $PrefixListConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True

            # Get main BGP table configuration.
            $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
            $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
            $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
            ForEach ($Entry in $RouterBgpConfig) {
                $NewBgpConfig += $Entry | Out-String
                # Get BGP neighbors from main BGP table.
                IF ($Entry | Select-String -Pattern "remote-as*") {
                    $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                    $BgpNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                    Break
                }
            }
            IF ($NewBgpConfig) {
                ForEach ($Entry in $BgpNeighbor) {
                    $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                    $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                    # eBGP neighbors
                    IF ($BgpAS -ne $EbgpAS) {
                        IF ($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in") {
                            $NewBgpNeighborPL += $BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in" | Out-String
                            $NewPrefixListName = (($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                            IF (!($PrefixListNames | Select-String -Pattern "$NewPrefixListName")) {
                                $MissingPrefixLists += ($NewPrefixListName | Out-String).Trim()
                                $MissingPrefixLists += "" | Out-String
                            }
                        }
                        ELSE {
                            $NewBgpNeighborWithoutPL += $Entry | Out-String
                        }
                    }
                }
                IF ($NewBgpNeighborPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound prefix lists have been applied to the below external peers in the main BGP Table:" | Out-String
                    $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborPL | Out-String
                    $FindingDetails += "" | Out-String
                    IF ($MissingPrefixLists) {
                        $FindingDetails += "The below prefix lists from the main BGP Table are not configured on this device:" | Out-String
                        $FindingDetails += "---------------------------------------------------------------------------------" | Out-String
                        $FindingDetails += $MissingPrefixLists | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                IF ($NewBgpNeighborWithoutPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound prefix lists have not been applied to the below external peers in the main BGP Table, make finding determination based on STIG check guidance:" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborWithoutPL | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            # Get BGP VRFs configuration.
            $BgpVrfNeighbor = @()
            $BgpVrfNeighborPL = @()
            $NewBgpVrfNeighborPL = @()
            $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
            IF ($RouterBgpVrf) {
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
                # Get neighbors from BGP VRFs.
                ForEach ($Entry in $RouterBgpVrfConfig) {
                    # Get config from BGP VRF.
                    $NewBgpVrfConfig += $Entry | Out-String
                    IF ($Entry | Select-String -Pattern "remote-as*") {
                        # Get neighbors from BGP VRFs
                        $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                        $BgpVrfNeighbor += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                        $BgpVrfNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                        $BgpVrfNeighborPL += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                        $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                        $BgpVrfNeighbor = ($BgpVrfNeighbor -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $BgpVrfNeighborPL = ($BgpVrfNeighborPL -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                        ForEach ($Entry in $BgpVrfNeighbor) {
                            $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                            $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                            # eBGP VRF neighbors
                            IF ($BgpAS -ne $EbgpVrfAS) {
                                IF ($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in") {
                                    $NewBgpVrfNeighborPL += $BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String
                                    $NewBgpVrfNeighborPL += "" | Out-String
                                    $NewVRFPrefixListName = (($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                                    IF (!($PrefixListNames | Select-String -Pattern "$NewVRFPrefixListName")) {
                                        $MissingVrfPrefixLists += ($NewVRFPrefixListName | Out-String).Trim()
                                        $MissingVrfPrefixLists += "" | Out-String
                                    }
                                }
                                ELSE {
                                    $NewBgpVrfNeighborWithoutPL += $Entry | Out-String
                                }
                            }
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Inbound prefix lists have been applied to the below external peers in the BGP VRF ${Vrf}:" | Out-String
                            $FindingDetails += "-----------------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborPL | Out-String
                            $FindingDetails += "" | Out-String
                            IF ($MissingVrfPrefixLists) {
                                $FindingDetails += "The below prefix lists from VRF $Vrf are not configured on this device:" | Out-String
                                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
                                $FindingDetails += $MissingVrfPrefixLists | Out-String
                                $FindingDetails += "" | Out-String
                            }
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Inbound prefix lists have not been applied to the below external peers in the BGP VRF $Vrf, make finding determination based on STIG check guidance:" | Out-String
                            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborWithoutPL | Out-String
                            $FindingDetails += "" | Out-String
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborPL"
                        }
                        IF ($BgpVrfNeighbor) {
                            Clear-Variable -Name "BgpVrfNeighbor"
                        }
                        IF ($BgpVrfNeighborPL) {
                            Clear-Variable -Name "BgpVrfNeighborPL"
                        }
                        IF ($NewBgpVrfConfig) {
                            Clear-Variable -Name "NewBgpVrfConfig"
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborWithoutPL"
                        }
                        IF ($NewVRFPrefixListName) {
                            Clear-Variable -Name "NewVRFPrefixListName"
                        }
                        IF ($MissingVrfPrefixLists) {
                            Clear-Variable -Name "MissingVrfPrefixLists"
                        }
                        continue
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

Function Get-V221025 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221025
        STIG ID    : CISC-RT-000510
        Rule ID    : SV-221025r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000004
        Rule Title : The Cisco BGP switch must be configured to reject inbound route advertisements from a customer edge (CE) switch for prefixes that are not allocated to that customer.
        DiscussMD5 : FA13059A258BF151044979C7A8180604
        CheckMD5   : B0C87E41748F85B11A01C581E13138C3
        FixMD5     : 4420251B91F08048C4BE540F514B5FD0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Check if Prefix Lists are configured
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Prefix Lists are not configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get Prefix List Names
            $PrefixLists = ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")
            $PrefixListNames = @()
            ForEach ($PrefixList in $PrefixLists) {
                $NewPrefixList = ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                IF ($NewPrefixList -notin $PrefixListNames) {
                    $PrefixListNames += ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                }
            }
            # Get Prefix List Configs
            $PrefixListConfig = @()
            $BgpNeighbor = @()
            $BgpNeighborPL = @()
            $NewBgpConfig = @()
            ForEach ($PrefixListName in $PrefixListNames) {
                $PrefixListConfig += ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PrefixListName .*" | Out-String)
            }
            # Check if Prefix Lists have the correct prefixes configured.
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below Prefix Lists are configured for each customer containing prefixes belonging to each customer only and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $PrefixListConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True

            # Get main BGP table configuration.
            $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
            $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
            $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
            ForEach ($Entry in $RouterBgpConfig) {
                $NewBgpConfig += $Entry | Out-String
                # Get BGP neighbors from main BGP table.
                IF ($Entry | Select-String -Pattern "remote-as*") {
                    $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                    $BgpNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                    Break
                }
            }
            IF ($NewBgpConfig) {
                ForEach ($Entry in $BgpNeighbor) {
                    $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                    $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                    # eBGP neighbors
                    IF ($BgpAS -ne $EbgpAS) {
                        IF ($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in") {
                            $NewBgpNeighborPL += $BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in" | Out-String
                            $NewPrefixListName = (($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                            IF (!($PrefixListNames | Select-String -Pattern "$NewPrefixListName")) {
                                $MissingPrefixLists += ($NewPrefixListName | Out-String).Trim()
                                $MissingPrefixLists += "" | Out-String
                            }
                        }
                        ELSE {
                            $NewBgpNeighborWithoutPL += $Entry | Out-String
                        }
                    }
                }
                IF ($NewBgpNeighborPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound prefix lists have been applied to the below CE peers in the main BGP Table:" | Out-String
                    $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborPL | Out-String
                    $FindingDetails += "" | Out-String
                    IF ($MissingPrefixLists) {
                        $FindingDetails += "The below prefix lists from the main BGP Table are not configured on this device:" | Out-String
                        $FindingDetails += "---------------------------------------------------------------------------------" | Out-String
                        $FindingDetails += $MissingPrefixLists | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                IF ($NewBgpNeighborWithoutPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound prefix lists have not been applied to the below CE peers in the main BGP Table, make finding determination based on STIG check guidance:" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborWithoutPL | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            # Get BGP VRFs configuration.
            $BgpVrfNeighbor = @()
            $BgpVrfNeighborPL = @()
            $NewBgpVrfNeighborPL = @()
            $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
            IF ($RouterBgpVrf) {
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
                # Get neighbors from BGP VRFs.
                ForEach ($Entry in $RouterBgpVrfConfig) {
                    # Get config from BGP VRF.
                    $NewBgpVrfConfig += $Entry | Out-String
                    IF ($Entry | Select-String -Pattern "remote-as*") {
                        # Get neighbors from BGP VRFs
                        $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                        $BgpVrfNeighbor += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                        $BgpVrfNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                        $BgpVrfNeighborPL += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                        $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                        $BgpVrfNeighbor = ($BgpVrfNeighbor -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $BgpVrfNeighborPL = ($BgpVrfNeighborPL -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                        ForEach ($Entry in $BgpVrfNeighbor) {
                            $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                            $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                            # eBGP VRF neighbors
                            IF ($BgpAS -ne $EbgpVrfAS) {
                                IF ($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in") {
                                    $NewBgpVrfNeighborPL += $BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String
                                    $NewBgpVrfNeighborPL += "" | Out-String
                                    $NewVRFPrefixListName = (($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                                    IF (!($PrefixListNames | Select-String -Pattern "$NewVRFPrefixListName")) {
                                        $MissingVrfPrefixLists += ($NewVRFPrefixListName | Out-String).Trim()
                                        $MissingVrfPrefixLists += "" | Out-String
                                    }
                                }
                                ELSE {
                                    $NewBgpVrfNeighborWithoutPL += $Entry | Out-String
                                }
                            }
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Inbound prefix lists have been applied to the below CE peers in the BGP VRF ${Vrf}:" | Out-String
                            $FindingDetails += "---------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborPL | Out-String
                            $FindingDetails += "" | Out-String
                            IF ($MissingVrfPrefixLists) {
                                $FindingDetails += "The below prefix lists from VRF $Vrf are not configured on this device:" | Out-String
                                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
                                $FindingDetails += $MissingVrfPrefixLists | Out-String
                                $FindingDetails += "" | Out-String
                            }
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Inbound prefix lists have not been applied to the below CE peers in the BGP VRF $Vrf, make finding determination based on STIG check guidance:" | Out-String
                            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborWithoutPL | Out-String
                            $FindingDetails += "" | Out-String
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborPL"
                        }
                        IF ($BgpVrfNeighbor) {
                            Clear-Variable -Name "BgpVrfNeighbor"
                        }
                        IF ($BgpVrfNeighborPL) {
                            Clear-Variable -Name "BgpVrfNeighborPL"
                        }
                        IF ($NewBgpVrfConfig) {
                            Clear-Variable -Name "NewBgpVrfConfig"
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborWithoutPL"
                        }
                        IF ($NewVRFPrefixListName) {
                            Clear-Variable -Name "NewVRFPrefixListName"
                        }
                        IF ($MissingVrfPrefixLists) {
                            Clear-Variable -Name "MissingVrfPrefixLists"
                        }
                        continue
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

Function Get-V221026 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221026
        STIG ID    : CISC-RT-000520
        Rule ID    : SV-221026r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000005
        Rule Title : The Cisco BGP switch must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).
        DiscussMD5 : A16E59C5485D1D3DA46E7A9BEC8E6E30
        CheckMD5   : 77356A37A846D680006945AE57F4EC98
        FixMD5     : 614D1198B132A4C7FDEA7F8840F862FD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Check if Prefix Lists are configured
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Prefix Lists are not configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get Prefix List Names
            $PrefixLists = ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")
            $PrefixListNames = @()
            ForEach ($PrefixList in $PrefixLists) {
                $NewPrefixList = ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                IF ($NewPrefixList -notin $PrefixListNames) {
                    $PrefixListNames += ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                }
            }
            # Get Prefix List Configs
            $PrefixListConfig = @()
            $BgpNeighbor = @()
            $BgpNeighborPL = @()
            $NewBgpConfig = @()
            ForEach ($PrefixListName in $PrefixListNames) {
                $PrefixListConfig += ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PrefixListName .*" | Out-String)
            }
            # Check if Prefix Lists have the correct prefixes configured.
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below Prefix Lists are configured containing prefixes belonging to customers as well as the local AS and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $PrefixListConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True

            # Get main BGP table configuration.
            $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
            $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
            $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
            ForEach ($Entry in $RouterBgpConfig) {
                $NewBgpConfig += $Entry | Out-String
                # Get BGP neighbors from main BGP table.
                IF ($Entry | Select-String -Pattern "remote-as*") {
                    $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                    $BgpNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                    Break
                }
            }
            IF ($NewBgpConfig) {
                ForEach ($Entry in $BgpNeighbor) {
                    $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                    $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                    # eBGP neighbors
                    IF ($BgpAS -ne $EbgpAS) {
                        IF ($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* out") {
                            $NewBgpNeighborPL += $BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* out" | Out-String
                            $NewPrefixListName = (($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* out" | Out-String).Trim()).Split([char[]]"")[-2]
                            IF (!($PrefixListNames | Select-String -Pattern "$NewPrefixListName")) {
                                $MissingPrefixLists += ($NewPrefixListName | Out-String).Trim()
                                $MissingPrefixLists += "" | Out-String
                            }
                        }
                        ELSE {
                            $NewBgpNeighborWithoutPL += $Entry | Out-String
                        }
                    }
                }
                IF ($NewBgpNeighborPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Outbound prefix lists have been applied to the below CE peers in the main BGP Table:" | Out-String
                    $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborPL | Out-String
                    $FindingDetails += "" | Out-String
                    IF ($MissingPrefixLists) {
                        $FindingDetails += "The below prefix lists from the main BGP Table are not configured on this device:" | Out-String
                        $FindingDetails += "---------------------------------------------------------------------------------" | Out-String
                        $FindingDetails += $MissingPrefixLists | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                IF ($NewBgpNeighborWithoutPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Outbound prefix lists have not been applied to the below CE peers in the main BGP Table, make finding determination based on STIG check guidance:" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborWithoutPL | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            # Get BGP VRFs configuration.
            $BgpVrfNeighbor = @()
            $BgpVrfNeighborPL = @()
            $NewBgpVrfNeighborPL = @()
            $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
            IF ($RouterBgpVrf) {
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
                # Get neighbors from BGP VRFs.
                ForEach ($Entry in $RouterBgpVrfConfig) {
                    # Get config from BGP VRF.
                    $NewBgpVrfConfig += $Entry | Out-String
                    IF ($Entry | Select-String -Pattern "remote-as*") {
                        # Get neighbors from BGP VRFs
                        $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                        $BgpVrfNeighbor += "" | Out-String
                        }
                    ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                        $BgpVrfNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                        $BgpVrfNeighborPL += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                        $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                        $BgpVrfNeighbor = ($BgpVrfNeighbor -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $BgpVrfNeighborPL = ($BgpVrfNeighborPL -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                        ForEach ($Entry in $BgpVrfNeighbor) {
                            $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                            $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                            # eBGP VRF neighbors
                            IF ($BgpAS -ne $EbgpVrfAS) {
                                IF ($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* out") {
                                    $NewBgpVrfNeighborPL += ($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* out" | Out-String).Trim()
                                    $NewBgpVrfNeighborPL += "" | Out-String
                                    $NewVRFPrefixListName = (($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* out" | Out-String).Trim()).Split([char[]]"")[-2]
                                    IF (!($PrefixListNames | Select-String -Pattern "$NewVRFPrefixListName")) {
                                        $MissingVrfPrefixLists += ($NewVRFPrefixListName | Out-String).Trim()
                                        $MissingVrfPrefixLists += "" | Out-String
                                    }
                                }
                                ELSE {
                                    $NewBgpVrfNeighborWithoutPL += $Entry | Out-String
                                }
                            }
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Outbound prefix lists have been applied to the below CE peers in the BGP VRF ${Vrf}:" | Out-String
                            $FindingDetails += "---------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborPL | Out-String
                            $FindingDetails += "" | Out-String
                            IF ($MissingVrfPrefixLists)
                            {
                                $FindingDetails += "The below prefix lists from VRF $Vrf are not configured on this device:" | Out-String
                                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
                                $FindingDetails += $MissingVrfPrefixLists | Out-String
                                $FindingDetails += "" | Out-String
                            }
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Outbound prefix lists have not been applied to the below CE peers in the BGP VRF $Vrf, make finding determination based on STIG check guidance:" | Out-String
                            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborWithoutPL | Out-String
                            $FindingDetails += "" | Out-String
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborPL"
                        }
                        IF ($BgpVrfNeighbor) {
                            Clear-Variable -Name "BgpVrfNeighbor"
                        }
                        IF ($BgpVrfNeighborPL) {
                            Clear-Variable -Name "BgpVrfNeighborPL"
                        }
                        IF ($NewBgpVrfConfig) {
                            Clear-Variable -Name "NewBgpVrfConfig"
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborWithoutPL"
                        }
                        IF ($NewVRFPrefixListName) {
                            Clear-Variable -Name "NewVRFPrefixListName"
                        }
                        IF ($MissingVrfPrefixLists) {
                            Clear-Variable -Name "MissingVrfPrefixLists"
                        }
                        continue
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

Function Get-V221027 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221027
        STIG ID    : CISC-RT-000530
        Rule ID    : SV-221027r929070_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000006
        Rule Title : The Cisco BGP switch must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
        DiscussMD5 : 57BE822E9BB95C09988F37CAAA6A9564
        CheckMD5   : FE2C4332A5B319F2E92605A8381040D8
        FixMD5     : 1C0A84DD92D2F992C1B202A722C2B5AD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Check if Prefix Lists are configured
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Prefix Lists are not configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get Prefix List Names
            $PrefixLists = ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")
            $PrefixListNames = @()
            ForEach ($PrefixList in $PrefixLists) {
                $NewPrefixList = ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                IF ($NewPrefixList -notin $PrefixListNames) {
                    $PrefixListNames += ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                }
            }
            # Get Prefix List Configs
            $PrefixListConfig = @()
            $BgpNeighbor = @()
            $BgpNeighborPL = @()
            $NewBgpConfig = @()
            ForEach ($PrefixListName in $PrefixListNames) {
                $PrefixListConfig += ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PrefixListName .*" | Out-String)
            }
            # Check if Prefix Lists have the correct prefixes configured.
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below Prefix Lists are configured containing prefixes belonging to the IP core and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $PrefixListConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True

            # Get main BGP table configuration.
            $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
            $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
            $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
            ForEach ($Entry in $RouterBgpConfig) {
                $NewBgpConfig += $Entry | Out-String
                # Get BGP neighbors from main BGP table.
                IF ($Entry | Select-String -Pattern "remote-as*") {
                    $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                    $BgpNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                    Break
                }
            }
            IF ($NewBgpConfig) {
                ForEach ($Entry in $BgpNeighbor) {
                    $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                    $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                    # eBGP neighbors
                    IF ($BgpAS -ne $EbgpAS) {
                        IF ($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* out") {
                            $NewBgpNeighborPL += $BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* out" | Out-String
                            $NewPrefixListName = (($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* out" | Out-String).Trim()).Split([char[]]"")[-2]
                            IF (!($PrefixListNames | Select-String -Pattern "$NewPrefixListName")) {
                                $MissingPrefixLists += ($NewPrefixListName | Out-String).Trim()
                                $MissingPrefixLists += "" | Out-String
                            }
                        }
                        ELSE {
                            $NewBgpNeighborWithoutPL += $Entry | Out-String
                        }
                    }
                }
                IF ($NewBgpNeighborPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Outbound prefix lists have been applied to the below external peers in the main BGP Table:" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborPL | Out-String
                    $FindingDetails += "" | Out-String
                    IF ($MissingPrefixLists) {
                        $FindingDetails += "The below prefix lists from the main BGP Table are not configured on this device:" | Out-String
                        $FindingDetails += "---------------------------------------------------------------------------------" | Out-String
                        $FindingDetails += $MissingPrefixLists | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                IF ($NewBgpNeighborWithoutPL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Outbound prefix lists have not been applied to the below external peers in the main BGP Table, make finding determination based on STIG check guidance:" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $NewBgpNeighborWithoutPL | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            # Get BGP VRFs configuration.
            $BgpVrfNeighbor = @()
            $BgpVrfNeighborPL = @()
            $NewBgpVrfNeighborPL = @()
            $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
            IF ($RouterBgpVrf) {
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
                # Get neighbors from BGP VRFs.
                ForEach ($Entry in $RouterBgpVrfConfig) {
                    # Get config from BGP VRF.
                    $NewBgpVrfConfig += $Entry | Out-String
                    IF ($Entry | Select-String -Pattern "remote-as*") {
                        # Get neighbors from BGP VRFs
                        $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                        $BgpVrfNeighbor += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                        $BgpVrfNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                        $BgpVrfNeighborPL += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                        $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                        $BgpVrfNeighbor = ($BgpVrfNeighbor -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $BgpVrfNeighborPL = ($BgpVrfNeighborPL -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                        ForEach ($Entry in $BgpVrfNeighbor) {
                            $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                            $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                            # eBGP VRF neighbors
                            IF ($BgpAS -ne $EbgpVrfAS) {
                                IF ($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* out") {
                                    $NewBgpVrfNeighborPL += ($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* out" | Out-String).Trim()
                                    $NewBgpVrfNeighborPL += "" | Out-String
                                    $NewVRFPrefixListName = (($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* out" | Out-String).Trim()).Split([char[]]"")[-2]
                                    IF (!($PrefixListNames | Select-String -Pattern "$NewVRFPrefixListName")) {
                                        $MissingVrfPrefixLists += ($NewVRFPrefixListName | Out-String).Trim()
                                        $MissingVrfPrefixLists += "" | Out-String
                                    }
                                }
                                ELSE {
                                    $NewBgpVrfNeighborWithoutPL += $Entry | Out-String
                                }
                            }
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Outbound prefix lists have been applied to the below external peers in the BGP VRF ${Vrf}:" | Out-String
                            $FindingDetails += "------------------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborPL | Out-String
                            $FindingDetails += "" | Out-String
                            IF ($MissingVrfPrefixLists) {
                                $FindingDetails += "The below prefix lists from VRF $Vrf are not configured on this device:" | Out-String
                                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
                                $FindingDetails += $MissingVrfPrefixLists | Out-String
                                $FindingDetails += "" | Out-String
                            }
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Outbound prefix lists have not been applied to the below external peers in the BGP VRF $Vrf, make finding determination based on STIG check guidance:" | Out-String
                            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $NewBgpVrfNeighborWithoutPL | Out-String
                            $FindingDetails += "" | Out-String
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborPL"
                        }
                        IF ($BgpVrfNeighbor) {
                            Clear-Variable -Name "BgpVrfNeighbor"
                        }
                        IF ($BgpVrfNeighborPL) {
                            Clear-Variable -Name "BgpVrfNeighborPL"
                        }
                        IF ($NewBgpVrfConfig) {
                            Clear-Variable -Name "NewBgpVrfConfig"
                        }
                        IF ($NewBgpVrfNeighborWithoutPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborWithoutPL"
                        }
                        IF ($NewVRFPrefixListName) {
                            Clear-Variable -Name "NewVRFPrefixListName"
                        }
                        IF ($MissingVrfPrefixLists) {
                            Clear-Variable -Name "MissingVrfPrefixLists"
                        }
                        continue
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

Function Get-V221028 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221028
        STIG ID    : CISC-RT-000540
        Rule ID    : SV-221028r945854_rule
        CCI ID     : CCI-000032
        Rule Name  : SRG-NET-000018-RTR-000006
        Rule Title : The Cisco BGP switch must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.
        DiscussMD5 : B5D96C29D20CE698CC60089EFE326DFE
        CheckMD5   : 0E0A426F98D0D6B8CA61952811D7B8BD
        FixMD5     : 619FC31D39AD76B43345F9238DEA965D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get BGP configuration
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        # Check if 'no bgp enforce-first-as' is configured
        IF (!($RouterBgpConfig | Select-String -Pattern "no bgp enforce-first-as")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute." | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute." | Out-String
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

Function Get-V221029 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221029
        STIG ID    : CISC-RT-000550
        Rule ID    : SV-221029r945855_rule
        CCI ID     : CCI-000032
        Rule Name  : SRG-NET-000018-RTR-000010
        Rule Title : The Cisco BGP switch must be configured to reject route advertisements from CE switches with an originating AS in the AS_PATH attribute that does not belong to that customer.
        DiscussMD5 : B8CBE53922094CD5BEBF32CFC3E25868
        CheckMD5   : 4E7412045935BC9E77A113C7DBE7A28B
        FixMD5     : 937AD11F1896374211186780F2B835A1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Check if as-path access-lists are configured
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip as-path access-list .*")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "AS-Path access lists are not configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get as-path access-lists Names
            $ASPathACLs = ($ShowRunningConfig | Select-String -Pattern "^ip as-path access-list .*")
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below AS-Path ACLs are configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "-----------------------------------------------------------------------------" | Out-String
            $FindingDetails += $ASPathACLs | Out-String
            $FindingDetails += "" | Out-String

            # Get main BGP table configuration.
            $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
            $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
            $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
            $BgpNeighbor = @()
            $BgpNeighborFL = @()
            $NewBgpConfig = @()
            ForEach ($Entry in $RouterBgpConfig) {
                $NewBgpConfig += $Entry | Out-String
                # Get BGP neighbors from main BGP table.
                IF ($Entry | Select-String -Pattern "remote-as*") {
                    $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                }
                # Get BGP neighbors with filter-list
                ELSEIF ($Entry | Select-String -Pattern "filter-list*") {
                    $BgpNeighborFL += ($Entry | Select-String -Pattern "filter-list*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                    Break
                }
            }
            IF ($NewBgpConfig) {
                $NewBgpNeighborFL = @()
                ForEach ($Entry in $BgpNeighbor) {
                    $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                    $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                    # For BGP neighbors with filter-list configured
                    IF ($BgpAS -ne $EbgpAS) {
                        IF ($BgpNeighborFL | Select-String -Pattern "$IP filter-list .* in") {
                            $NewBgpNeighborFL += $BgpNeighborFL | Select-String -Pattern "$IP filter-list .* in" | Out-String
                            $FL = (($BgpNeighborFL | Select-String -Pattern "$IP filter-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                            IF ($ShowRunningConfig | Select-String -Pattern "^ip as-path access-list $FL") {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Verify if the below AS-Path ACL is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer and make finding determination based on STIG check guidance:" | Out-String
                                $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                                $FindingDetails += $Entry | Out-String
                                $FindingDetails += $BgpNeighborFL | Select-String -Pattern "$IP filter-list .* in" | Out-String
                                $FindingDetails += "" | Out-String
                                $Exception = $True
                            }
                            ELSE {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "AS-Path ACL $FL is not configured on this device on the BGP Table, make finding determination based on STIG check guidance:" | Out-String
                                $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                                $FindingDetails += $BgpNeighborFL | Select-String -Pattern "$IP filter-list .* in" | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        # For BGP neighbors without filter-list configured
                        ELSE {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "The below BGP neighbor is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, make finding determination based on STIG check guidance:" | Out-String
                            $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $Entry | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
            }

            # Get BGP VRFs configuration.
            $BgpVrfNeighbor = @()
            $BgpVrfNeighborFL = @()
            $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
            IF ($RouterBgpVrf) {
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
                # Get neighbors from BGP VRFs.
                ForEach ($Entry in $RouterBgpVrfConfig) {
                    # Get config from BGP VRF.
                    $NewBgpVrfConfig += $Entry | Out-String
                    # Get neighbors from BGP VRFs
                    IF ($Entry | Select-String -Pattern "remote-as*") {
                        $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                        $BgpVrfNeighbor += "" | Out-String
                    }
                    # Get BGP VRFs neighbors with filter-list
                    ELSEIF ($Entry | Select-String -Pattern "filter-list*") {
                        $BgpVrfNeighborFL += ($Entry | Select-String -Pattern "filter-list*" | Out-String).Trim()
                        $BgpVrfNeighborFL += "" | Out-String
                    }
                    ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                        $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                        $BgpVrfNeighbor = ($BgpVrfNeighbor -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $BgpVrfNeighborFL = ($BgpVrfNeighborFL -split "[\r\n]+") | Where-Object { $_ -ne "" }
                        $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                        ForEach ($Entry in $BgpVrfNeighbor) {
                            $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                            $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                            # eBGP VRF neighbors
                            IF ($BgpAS -ne $EbgpVrfAS) {
                                IF ($BgpVrfNeighborFL | Select-String -Pattern "$IPVrf filter-list .* in") {
                                    $NewBgpVrfNeighborFL += $BgpVrfNeighborFL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String
                                    $FLVrf = (($BgpVrfNeighborFL | Select-String -Pattern "$IPVrf filter-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                                    IF ($ShowRunningConfig | Select-String -Pattern "^ip as-path access-list $FLVrf") {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "Verify if the below AS-Path ACL under VRF $Vrf neighbor is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer and make finding determination based on STIG check guidance:" | Out-String
                                        $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                                        $FindingDetails += $Entry | Out-String
                                        $FindingDetails += $BgpVrfNeighborFL | Select-String -Pattern "$IPVrf filter-list .* in" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $Exception = $True
                                    }
                                    ELSE {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "AS-Path ACL $FLVrf is not configured on this device under VRF $Vrf, make finding determination based on STIG check guidance:" | Out-String
                                        $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                                        $FindingDetails += $BgpVrfNeighborFL | Select-String -Pattern "$IPVrf filter-list .* in" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                    }
                                }
                                # For eBGP neighbors without filter-list configured
                                ELSE {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "The below BGP VRF $Vrf neighbor is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, make finding determination based on STIG check guidance:" | Out-String
                                    $FindingDetails += "-----------------------------------------------------------------------------------" | Out-String
                                    $FindingDetails += $Entry | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                }
                            }
                        }
                        IF ($BgpVrfNeighbor) {
                            Clear-Variable -Name "BgpVrfNeighbor"
                        }
                        IF ($BgpVrfNeighborFL) {
                            Clear-Variable -Name "BgpVrfNeighborFL"
                        }
                        IF ($NewBgpVrfConfig) {
                            Clear-Variable -Name "NewBgpVrfConfig"
                        }
                        continue
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

Function Get-V221030 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221030
        STIG ID    : CISC-RT-000560
        Rule ID    : SV-221030r856416_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000117
        Rule Title : The Cisco BGP switch must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.
        DiscussMD5 : C5D60DCF41DC5B8036FDAB3831BD4F0A
        CheckMD5   : F1B6EDBB81FAAAE8C1FEF804D4454A87
        FixMD5     : 6FCD1DA44A9186C0FF113B6CDF051EB3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get main BGP table configuration.
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        $BgpNeighbor = @()
        ForEach ($Entry in $RouterBgpConfig) {
            $NewBgpConfig += $Entry | Out-String
            # Get BGP neighbors from main BGP table.
            IF ($Entry | Select-String -Pattern "remote-as*") {
                $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
            }
            ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                Break
            }
        }
        IF ($NewBgpConfig) {
            ForEach ($Entry in $BgpNeighbor) {
                $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                # iBGP neighbors
                IF ($BgpAS -eq $EbgpAS) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The below is an iBGP neighbor in main BGP Table:" | Out-String
                    $FindingDetails += "------------------------------------------------" | Out-String
                    $FindingDetails += ($Entry | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                # eBGP neighbors
                ELSE {
                    IF (!($NewBgpConfig | Select-String -Pattern "neighbor $IP maximum-prefix*")) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "The below eBGP neighbor in main BGP Table is not configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks:" | Out-String
                        $FindingDetails += "---------------------------------------------" | Out-String
                        $FindingDetails += ($Entry | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "The below eBGP neighbor in main BGP Table is configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks:" | Out-String
                        $FindingDetails += "---------------------------------------------" | Out-String
                        $FindingDetails += ($Entry | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                    }
                }
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

        # Check for maximum prefixes feature from every BGP neighbor on each VRF
        $BgpVrfNeighbor = @()
        ForEach ($Entry in $RouterBgpVrfConfig) {
            # Get config from BGP VRF.
            $NewBgpVrfConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "remote-as*") {
                # Get neighbors from BGP VRFs
                $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                $BgpVrfNeighbor += "" | Out-String
            }
            ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                $BgpVrfNeighbor = ($BgpVrfNeighbor -split "[\r\n]+") | Where-Object { $_ -ne "" }
                $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                ForEach ($Entry in $BgpVrfNeighbor) {
                    $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                    $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                    # iBGP neighbors
                    IF ($BgpAS -eq $EbgpVrfAS) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "The below is an iBGP neighbor in VRF ${Vrf}:" | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += ($Entry | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                    }
                    # eBGP neighbors
                    ELSE {
                        IF (!($NewBgpVrfConfig | Select-String -Pattern "neighbor $IPVrf maximum-prefix*")) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "The below eBGP neighbor in VRF $Vrf is not configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks:" | Out-String
                            $FindingDetails += "---------------------------------------------" | Out-String
                            $FindingDetails += ($Entry | Out-String).Trim()
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                        ELSE {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "The below eBGP neighbor in VRF $Vrf is configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks:" | Out-String
                            $FindingDetails += "---------------------------------------------" | Out-String
                            $FindingDetails += ($Entry | Out-String).Trim()
                            $FindingDetails += "" | Out-String
                        }
                    }
                }
                IF ($NewBgpVrfConfig) {
                    Clear-Variable -Name "NewBgpVrfConfig"
                }
                IF ($BgpVrfNeighbor) {
                    Clear-Variable -Name "BgpVrfNeighbor"
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221031 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221031
        STIG ID    : CISC-RT-000570
        Rule ID    : SV-221031r856417_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000118
        Rule Title : The Cisco BGP switch must be configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer.
        DiscussMD5 : AD6B66503D532C747FCB411805893714
        CheckMD5   : 9D022A327F586574188F88D662A251CE
        FixMD5     : 2D63325285F520A80E39A17A59992EAB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Check if Prefix Lists are configured
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Prefix Lists are not configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get Prefix List Names
            $PrefixLists = ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list .*")
            $PrefixListNames = @()
            ForEach ($PrefixList in $PrefixLists) {
                $NewPrefixList = ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                IF ($NewPrefixList -notin $PrefixListNames) {
                    $PrefixListNames += ((($PrefixList | Out-String).Trim())).Split([char[]]"")[2]
                }
            }
            # Get Prefix List Configs
            $PrefixListConfig = @()
            $CompliantPrefixList = @()
            $CompliantPrefixListName = @()
            $BgpNeighbor = @()
            $BgpNeighborPL = @()
            $NewBgpConfig = @()
            ForEach ($PrefixListName in $PrefixListNames) {
                $CompliantPrefixList += ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PrefixListName .*" | Out-String)
                $PrefixListConfig += $CompliantPrefixList | Out-String
                # Check if a Prefix List has been configured to reject prefixes longer than /24.
                IF (($CompliantPrefixList | Select-String -Pattern "$PrefixListName seq .* permit 0.0.0.0/0 ge 8 le 24") -AND ($CompliantPrefixList | Select-String -Pattern "$PrefixListName seq .* deny 0.0.0.0/0 le 32")) {
                    $CompliantPrefixListName += ($PrefixListName | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The below Prefix List has been configured to reject prefixes longer than /24:" | Out-String
                    $FindingDetails += "-----------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $CompliantPrefixList | Out-String
                    $FindingDetails += "" | Out-String
                }
                ELSE {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The below Prefix List has not been configured to reject prefixes longer than /24, make finding determination based on STIG check guidance::" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                    $FindingDetails += $CompliantPrefixList | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
                IF ($CompliantPrefixList) {
                    Clear-Variable -Name "CompliantPrefixList"
                }
            }

            # Get main BGP table configuration.
            $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
            $BgpAS = ((($ShowRunningConfig | Select-String -Pattern "^router bgp*" | Out-String).Trim())).Split([char[]]"")[-1]
            $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
            ForEach ($Entry in $RouterBgpConfig) {
                $NewBgpConfig += $Entry | Out-String
                # Get BGP neighbors from main BGP table.
                IF ($Entry | Select-String -Pattern "remote-as*") {
                    $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                    $BgpNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                }
                ELSEIF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                    Break
                }
            }
            IF ($NewBgpConfig) {
                ForEach ($Entry in $BgpNeighbor) {
                    $EbgpAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                    $IP = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                    # eBGP neighbors
                    IF ($BgpAS -ne $EbgpAS) {
                        IF ($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in") {
                            $PL = (($BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                            IF ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PL") {
                                IF ($PL -in $CompliantPrefixListName) {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Prefix List $PL is configured to reject prefixes longer than /24 on the main BGP Table:" | Out-String
                                    $FindingDetails += "----------------------------------------------------------------" | Out-String
                                    $FindingDetails += $Entry | Out-String
                                    $FindingDetails += $BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in" | Out-String
                                    $FindingDetails += "" | Out-String
                                }
                                ELSE {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Prefix List $PL is not configured to reject prefixes longer than /24 on the main BGP Table, make finding determination based on STIG check guidance:" | Out-String
                                    $FindingDetails += "----------------------------------------------------------------------------------------" | Out-String
                                    $FindingDetails += $Entry | Out-String
                                    $FindingDetails += $BgpNeighborPL | Select-String -Pattern "$IP prefix-list .* in" | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                }
                            }
                            ELSE {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Prefix List $PL under neighbor $IP is not configured on this device, make finding determination based on STIG check guidance." | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        ELSE {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Inbound prefix list has not been applied to the below external peer on the main BGP Table, make finding determination based on STIG check guidance:" | Out-String
                            $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                            $FindingDetails += $Entry | Out-String
                            $FindingDetails += "" | Out-String
                            $Exception = $True
                        }
                    }
                }
            }

            # Get BGP VRFs configuration.
            $BgpVrfNeighbor = @()
            $BgpVrfNeighborPL = @()
            $RouterBgpVrf = $ShowRunningConfig | Select-String -Pattern "address-family ipv4 vrf \w+`$"
            IF ($RouterBgpVrf) {
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
                # Get neighbors from BGP VRFs.
                ForEach ($Entry in $RouterBgpVrfConfig) {
                    # Get config from BGP VRF.
                    $NewBgpVrfConfig += $Entry | Out-String
                    # Get neighbors from BGP VRFs
                    IF ($Entry | Select-String -Pattern "remote-as*") {
                        $BgpVrfNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
                    }
                    # Get Prefix Lists from BGP VRFs
                    ELSEIF ($Entry | Select-String -Pattern "prefix-list*") {
                        $BgpVrfNeighborPL += ($Entry | Select-String -Pattern "prefix-list*" | Out-String).Trim()
                    }
                    ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                        $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                        $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                        ForEach ($Entry in $BgpVrfNeighbor) {
                            $EbgpVrfAS = (($Entry | Out-String).Trim()).Split([char[]]"")[-1]
                            $IPVrf = (($Entry | Out-String).Trim()).Split([char[]]"")[1]
                            # eBGP VRF neighbors
                            IF ($BgpAS -ne $EbgpVrfAS) {
                                IF ($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in") {
                                    $NewBgpVrfNeighborPL += $BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String
                                    $PLVrf = (($BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String).Trim()).Split([char[]]"")[-2]
                                    IF ($ShowRunningConfig | Select-String -Pattern "^ip prefix-list $PLVrf") {
                                        IF ($PLVrf -in $CompliantPrefixListName) {
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "Prefix List $PLVrf is configured to reject prefixes longer than /24 in VRF $Vrf :" | Out-String
                                            $FindingDetails += "----------------------------------------------------------------" | Out-String
                                            $FindingDetails += $Entry | Out-String
                                            $FindingDetails += $BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String
                                            $FindingDetails += "" | Out-String
                                        }
                                        ELSE {
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "Prefix List $PLVrf is not configured to reject prefixes longer than /24 in VRF $Vrf, make finding determination based on STIG check guidance:" | Out-String
                                            $FindingDetails += "----------------------------------------------------------------------------------------" | Out-String
                                            $FindingDetails += $Entry | Out-String
                                            $FindingDetails += $BgpVrfNeighborPL | Select-String -Pattern "$IPVrf prefix-list .* in" | Out-String
                                            $FindingDetails += "" | Out-String
                                            $OpenFinding = $True
                                        }
                                    }
                                    ELSE {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "Prefix List $PL under neighbor $IPVrf and vrf $Vrf is not configured on this device, make finding determination based on STIG check guidance." | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                    }
                                }
                                ELSE {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Inbound prefix list has not been applied to the below external peer in BGP VRF $Vrf, make finding determination based on STIG check guidance:" | Out-String
                                    $FindingDetails += "------------------------------------------------------------------------------------" | Out-String
                                    $FindingDetails += $Entry | Out-String
                                    $FindingDetails += "" | Out-String
                                    $Exception = $True
                                }
                            }
                        }
                        IF ($NewBgpVrfNeighborPL) {
                            Clear-Variable -Name "NewBgpVrfNeighborPL"
                        }
                        IF ($BgpVrfNeighbor) {
                            Clear-Variable -Name "BgpVrfNeighbor"
                        }
                        IF ($BgpVrfNeighborPL) {
                            Clear-Variable -Name "BgpVrfNeighborPL"
                        }
                        IF ($NewBgpVrfConfig) {
                            Clear-Variable -Name "NewBgpVrfConfig"
                        }
                        continue
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

Function Get-V221032 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221032
        STIG ID    : CISC-RT-000580
        Rule ID    : SV-221032r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000001
        Rule Title : The Cisco BGP switch must be configured to use its loopback address as the source address for iBGP peering sessions.
        DiscussMD5 : 449C92AAFBA3B644AE1AAB37458095D4
        CheckMD5   : 8101BB741BF21E137FA3419AA3A89B2E
        FixMD5     : 79C862C2C01DD89A6822363A3A846BC3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get main BGP table configuration.
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $ASNumber = ($RouterBgp | Out-String).Trim().Split([char[]]"")[-1]
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        $IP = @()
        ForEach ($Entry in $RouterBgpConfig) {
            $NewBgpConfig += $Entry | Out-String
            # Get IP addresses from main BGP table.
            IF ($Entry | Select-String -Pattern "remote-as*") {
                $IP += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Replace("neighbor ", "").Split([char[]]"")[0]
            }
            ELSEIF ($Entry | Select-String -Pattern "address-family ipv4") {
                Break
            }
        }
        IF ($NewBgpConfig) {
            $NewBgpConfig = ($NewBgpConfig -split "[\r\n]+")
            # Check for loopback address as the source address for all iBGP peering.
            IF ($IP) {
                ForEach ($Entry in $IP) {
                    IF (($NewBgpConfig | Select-String -Pattern "neighbor $Entry remote-as*" | Out-String).Trim().Split([char[]]"")[-1] -eq $ASNumber) {
                        IF (!($ShowRunningConfig | Select-String -Pattern "^interface Loopback*")) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "A Loopback address has to be configured for iBGP sessions." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                            Break
                        }
                        ELSEIF (!($NewBgpConfig | Select-String -Pattern "neighbor $Entry update-source Loopback*")) {
                            # iBGP neighbor does not have a loopback interface as the source address in the main BGP table.
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Loopback interface is not used as the source address for this iBGP session." | Out-String
                            $FindingDetails += "BGP neighbor or Peer Group on main BGP table with no update-source Loopback configured:" | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
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
        # Check for loopback address as the source address for all iBGP peering on each VRF.
        $IPVrf = @()
        ForEach ($Entry in $RouterBgpVrfConfig) {
            # Get config from BGP VRF.
            $NewBgpVrfConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "remote-as*") {
                # Get IP addresses from BGP VRFs.
                $IPVrf += ((($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim())).Replace("neighbor ", "").Split([char[]]"")[0]
            }
            ELSEIF ($Entry | Select-String -Pattern "exit-address-family") {
                $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                ForEach ($Entry in $IPVrf) {
                    IF (($NewBgpVrfConfig | Select-String -Pattern "neighbor $Entry remote-as*" | Out-String).Trim().Split([char[]]"")[-1] -eq $ASNumber) {
                        IF (!($ShowRunningConfig | Select-String -Pattern "^interface Loopback*")) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "A Loopback address has to be configured for VRF iBGP sessions." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                            Break
                        }
                        ELSEIF (!($NewBgpVrfConfig | Select-String -Pattern "neighbor $Entry update-source Loopback*")) {
                            # iBGP neighbor does not have a loopback interface as the source address in the VRF.
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Loopback interface is not used as the source address for this iBGP session." | Out-String
                            $FindingDetails += "BGP neighbor or Peer Group in VRF $Vrf with no update-source Loopback configured:" | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                IF ($NewBgpVrfConfig) {
                    Clear-Variable -Name "NewBgpVrfConfig"
                }
                IF ($IPVrf) {
                    Clear-Variable -Name "IPVrf"
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221033 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221033
        STIG ID    : CISC-RT-000590
        Rule ID    : SV-221033r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000002
        Rule Title : The Cisco MPLS switch must be configured to use its loopback address as the source address for LDP peering sessions.
        DiscussMD5 : 3C77CB3CF291324AE98B55B661280BF3
        CheckMD5   : 89D19DD91FA0ED0AFB3AE079EF4BC200
        FixMD5     : 7DFD9B70FABC2B072CDC7C13539BE492
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF ($ShowRunningConfig -like "mpls ldp router-id*") {
        $mlps = $ShowRunningConfig | Select-String -Pattern "^mpls ldp router-id"
        IF ($ShowRunningConfig -like "mpls ldp router-id Loopback*") {
            $loopback = ($mlps -split " ")[3]
            $InterfaceConfig = Get-Section $ShowRunningConfig "interface $loopback".ToString()
            if ($InterfaceConfig -like "ip address * 255.255.255.255") {
                $FindingDetails += "Interface $loopback is configured to use their loopback address as the source address for LDP peering sessions." | Out-String
                $FindingDetails += $mlps | Out-String
                $FindingDetails += $loopback | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $Status = "NotAFinding"
            }
            else {
                $FindingDetails += "The device is configured to use the $loopback interface for LDP peering but the interface does not have an IP address assigned. Review the device configuration and reconfigure the loopback interface with an address." | Out-String
                $FindingDetails += $mlps | Out-String
                $FindingDetails += $loopback | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += "Review the device configuration and reconfigure the loopback interface address as the source address for LDP peering sessions." | Out-String
            $FindingDetails += $mlps | Out-String
            $Status = "Open"
        }
    }
    Else {
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -like "*loopback*"}
        $LoopbackConfigured = $False

        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            if ($InterfaceConfig -like "ip address * 255.255.255.255") {
                $LoopbackConfigured = $True
                break
            }
        }
        if ($LoopbackConfigured){
            $FindingDetails += "A loopback interface is configured with an IP address but LDP peering has not been assigned to the interface. Configure the device to use their loopback address as the source address for LDP peering sessions. Loopback interfaces configured with IP addresses:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $Interfaces | Out-String
            $Status = "Open"
        }
        else {
            $FindingDetails += "The device has no loopback interfaces configured with IP addresses configured for LDP peering sessions. Configure the device to use their loopback address as the source address for LDP peering sessions. Loopback interfaces:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $Interfaces | Out-String
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

Function Get-V221034 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221034
        STIG ID    : CISC-RT-000600
        Rule ID    : SV-221034r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000003
        Rule Title : The Cisco MPLS switch must be configured to synchronize Interior Gateway Protocol (IGP) and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.
        DiscussMD5 : D8500082C1560247999392BA72362BD9
        CheckMD5   : D5F38823B3ECD37628CC7170506955F4
        FixMD5     : FE4A2AB719DBB0676C904BA7A7AF824D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ospf = $ShowRunningConfig | Select-String -Pattern "^router ospf"
    $isis = $ShowRunningConfig | Select-String -Pattern "^router isis"

    if ($ospf.count -gt 0){
        $ospfConfig = Get-Section $ShowRunningConfig $ospf.ToString()
        if ($ospfConfig -contains "mpls ldp sync"){
            $Status = "NotAFinding"
            $FindingDetails += "The device's OSPF configuration is configured such that LDP will synchronize with the link-state routing protocol." | Out-String
            $ShowRunningConfig += "" | Out-String
        }
        else {
            $Status = "Open"
            $FindingDetails += "The device's OSPF configuration is not configured such that LDP will synchronize with the link-state routing protocol. Configure the MPLS switch to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange." | Out-String
            $ShowRunningConfig += "" | Out-String
        }
    }
    elseif ($isis.count -gt 0){
        $isisConfig = Get-Section $ShowRunningConfig $isis.ToString()
        if ($isisConfig -contains "mpls ldp sync"){
            $Status = "NotAFinding"
            $FindingDetails += "The device's ISIS configuration is configured such that LDP will synchronize with the link-state routing protocol." | Out-String
            $ShowRunningConfig += "" | Out-String
        }
        else {
            $Status = "Open"
            $FindingDetails += "The device's ISIS configuration is not configured such that LDP will synchronize with the link-state routing protocol. Configure the MPLS switch to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange." | Out-String
            $ShowRunningConfig += "" | Out-String
        }
    }
    else {
        $Status = "Not_Reviewed"
        $FindingDetails += "No OSPF or ISIS configuration found on device. Review the configuration and configure the MPLS switch to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange." | Out-String
        $ShowRunningConfig += "" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221035 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221035
        STIG ID    : CISC-RT-000610
        Rule ID    : SV-221035r622190_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000001
        Rule Title : The MPLS switch with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core switches.
        DiscussMD5 : 6B92EF223D6008EB0C5A1B898B383900
        CheckMD5   : 2D36BE00E32B02C0C5D338E4A9F2AB1F
        FixMD5     : 7ED41FE83EFEDDFCE1FA20D3E73B031C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $mlpsPresent = $False

    IF (!($ShowRunningConfig -contains "mpls traffic-eng tunnels")) {
        $Status = "NotAFinding"
        $FindingDetails += "MPLS TE is not enabled on this device."
        $FindingDetails += "" | Out-String
    }
    Else {
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            if ($InterfaceConfig -contains "mpls traffic-eng tunnels" -and $InterfaceConfig -contains "mpls ip") {
                $mlpsPresent = $True
                if ($InterfaceConfig -like "ip rsvp signaling rate-limit period * burst * maxsize * limit *") {
                    $signalConfig = $InterfaceConfig | Select-String -Pattern "^ip rsvp signaling rate-limit period"
                    $FindingDetails += "RSVP-TE is enabled on this interface and it does rate limits RSVP messages based on the link speed and input queue size. Verify the rate limit is set according to the link speed and input queue size of adjacent core switches." | Out-String
                    $FindingDetails += $signalConfig | Out-String
                    $FindingDetails += $Interface | Out-String
                    $FindingDetails += $InterfaceConfig | Out-String
                    $FindingDetails += "" | Out-String
                }
                else {
                    $OpenFinding = $True
                    $FindingDetails += "RSVP-TE is enabled on this interface but rate limiting doesn't appear to be configured properly. Configure the device to rate limit RSVP messages on this interface." | Out-String
                    $FindingDetails += $Interface | Out-String
                    $FindingDetails += $InterfaceConfig | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
        if (!$mlpsPresent) {
            $OpenFinding = $True
            $FindingDetails += "MPLS TE is enabled on this device globally but does not appear to be configured correctly on any interfaces. Configure the device to rate limit RSVP messages per interface." | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ($OpenFinding) {
        $FindingDetails += "Review the device configuration to determine RSVP messages are rate limited." | Out-String
        $FindingDetails += ""
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

Function Get-V221036 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221036
        STIG ID    : CISC-RT-000620
        Rule ID    : SV-221036r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000004
        Rule Title : The Cisco MPLS switch must be configured to have TTL Propagation disabled.
        DiscussMD5 : B938F7130B2D2CDF3A39139DE41C42E3
        CheckMD5   : F9DD8A5B19D2BF3CA7471F1A361E47EF
        FixMD5     : 171614A6EE84567EC129D563FC233645
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF ($ShowRunningConfig -contains "no mpls ip propagate-ttl") {
        $FindingDetails += "TTL Propagation is disabled." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
        $FindingDetails += "TTL Propagation is not disabled." | Out-String
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

Function Get-V221037 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221037
        STIG ID    : CISC-RT-000630
        Rule ID    : SV-221037r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000005
        Rule Title : The Cisco PE switch must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.
        DiscussMD5 : DC0F4C0B031776948852D1FAAA3328A8
        CheckMD5   : 7E820E7D3D1A469CE89C6FA393F1BE4E
        FixMD5     : B645FED0585AFC26075B79909F5D4116
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $vrfNotPresent = @()
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ip vrf forwarding *") {
            $FindingDetails += "This interface has 'ip vrf forwarding' configured on this device." | Out-String
            $FindingDetails += "Review the design plan for deploying MPLS/L3VPN and compare to the interface below. Verify if this is a CE-facing interface with 'ip vrf forwarding' properly defined." | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Not_Reviewed"
        }
        else {
            $vrfNotPresent += $Interface.ToString() | Out-String
        }
    }

    If ($vrfNotPresent.Count -gt 0) {
        $FindingDetails += "The following interfaces do not have a VRF defined." | Out-String
        $FindingDetails += "Review the design plan for deploying MPLS/L3VPN and verify if any are CE-facing interfaces that a VRF should be defined for." | Out-String
        foreach ($Interface in $vrfNotPresent) {
            $FindingDetails += $Interface
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

Function Get-V221038 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221038
        STIG ID    : CISC-RT-000640
        Rule ID    : SV-221038r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000006
        Rule Title : The Cisco PE switch must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).
        DiscussMD5 : 09644BAFE76C8F8C9E3877598D74478B
        CheckMD5   : FD825813B4F94A9E2874145114A1D13B
        FixMD5     : 84003A59C36D17B14E770D933F9AFB6F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $VRFs = $ShowRunningConfig | Select-String -Pattern "^ip vrf"
    $rtNotPresent = @()

    IF ($VRFs.count -gt 0){
        ForEach ($vrf in $VRFs) {
            $vrfConfig = Get-Section $ShowRunningConfig $vrf.ToString()

            if ($vrfConfig -like "route-target *") {
                $FindingDetails += "This VRF has a Route Target configured on this device." | Out-String
                $FindingDetails += "Review the design plan for MPLS/L3VPN and verify that the correct RT is configured for the VRF configuration below." | Out-String
                $FindingDetails += $vrf | Out-String
                $FindingDetails += $vrfConfig | Out-String
                $FindingDetails += "" | Out-String
                $Status = "Not_Reviewed"
            }
            else {
                $rtNotPresent += $vrf.ToString() | Out-String
            }
        }
    }
    else {
        $FindingDetails += "The following device has no VRFs configured." | Out-String
        $FindingDetails += "Review the design plan for MPLS/L3VPN to determine if any VRFs should be configured for the device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Applicable"
    }

    If ($rtNotPresent.Count -gt 0) {
        $FindingDetails += "The following VRFs do not have a Route Target defined." | Out-String
        $FindingDetails += "Review the design plan for deploying MPLS/L3VPN and verify these are configured as intended." | Out-String
        foreach ($rt in $rtNotPresent) {
            $FindingDetails += $rt
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

Function Get-V221039 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221039
        STIG ID    : CISC-RT-000650
        Rule ID    : SV-221039r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000007
        Rule Title : The Cisco PE switch must be configured to have each VRF with the appropriate Route Distinguisher (RD).
        DiscussMD5 : 427EFF97FA5DC842A4D8C07798624B27
        CheckMD5   : A8B5A5B15EDA68231CDDE827B20515B3
        FixMD5     : C65E84A35A862011DF5A3CE999D6D2BC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $VRFs = $ShowRunningConfig | Select-String -Pattern "^ip vrf"
    $rdNotPresent = @()

    IF ($VRFs.count -gt 0){
        ForEach ($vrf in $VRFs) {
            $vrfConfig = Get-Section $ShowRunningConfig $vrf.ToString()

            if ($vrfConfig -like "rd *") {
                $FindingDetails += "This VRF has a Route Distinguisher (RD) configured on this device." | Out-String
                $FindingDetails += "Review the design plan for MPLS/L3VPN and verify that the correct RD is configured for the VRF configuration below." | Out-String
                $FindingDetails += $vrf | Out-String
                $FindingDetails += $vrfConfig | Out-String
                $FindingDetails += "" | Out-String
                $Status = "Not_Reviewed"
            }
            else {
                $rdNotPresent += $vrf.ToString() | Out-String
            }
        }
    }
    else {
        $FindingDetails += "The following device has no VRFs configured." | Out-String
        $FindingDetails += "Review the design plan for MPLS/L3VPN to determine if any VRFs should be configured for the device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Applicable"
    }

    If ($rdNotPresent.Count -gt 0) {
        $FindingDetails += "The following VRFs do not have a Route Distinguisher (RD) defined." | Out-String
        $FindingDetails += "Review the design plan for deploying MPLS/L3VPN and verify these are configured as intended." | Out-String
        foreach ($rt in $rdNotPresent) {
            $FindingDetails += $rt
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

Function Get-V221040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221040
        STIG ID    : CISC-RT-000660
        Rule ID    : SV-221040r863378_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-NET-000343-RTR-000001
        Rule Title : The Cisco PE switch providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.
        DiscussMD5 : 401526A9698D4F512F1C1B337678FB98
        CheckMD5   : 20E2E4753064EBC79C6A6BB47D66B605
        FixMD5     : E3C5CFC164843A4B33660C737C045932
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221041 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221041
        STIG ID    : CISC-RT-000670
        Rule ID    : SV-221041r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000008
        Rule Title : The Cisco PE switch providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate virtual circuit identification (VC ID) for each attachment circuit.
        DiscussMD5 : 2047CDF6B77B2A6B75A792EE8377D609
        CheckMD5   : D3BD7DB10C95F0F8563351646EB613F0
        FixMD5     : 45E6DA47629809E03349EBA58B16E89A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $VCIDs = @()
    $VPWS = $False

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "xconnect * encapsulation mpls") {
            $VPWS = $True
            $xConfig = $InterfaceConfig | Select-String -Pattern "^xconnect \d+\.\d+\.\d+\.\d+ .* encapsulation mpls"
            $vcid = ($xConfig -split " ")[2]

            If ($VCIDs -contains $vcid){
                $OpenFinding = $True
                $FindingDetails += "Interface contains duplicate VCID. Assign globally unique VC IDs for each virtual circuit and configure the attachment circuits with the appropriate VC ID." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
            }
            else {
                $FindingDetails += "Interface contains VCID. Review the interface configuration below and verify that the correct and unique VCID has been configured on both devices for the appropriate attachment circuit." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
            }
            $VCIDs += $vcid
        }
    }

    If ($OpenFinding){
        $Status = "Open"
    }
    elseif (!$VPWS) {
        $FindingDetails += "MPLS Virtual Private Wire Service (VPWS) is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Applicable"
    }
    else {
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

Function Get-V221042 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221042
        STIG ID    : CISC-RT-000680
        Rule ID    : SV-221042r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000009
        Rule Title : The Cisco PE switch providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.
        DiscussMD5 : 825A21B16CDC91AA7B1CDBCDAD513A72
        CheckMD5   : 89B088A8270F1F6BD006E0E213E2552F
        FixMD5     : 41BBF0CBE57A068F9DE7EB75609D9809
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $VFInstances = $ShowRunningConfig | Select-String -Pattern "^l2 vfi.*"
    $OpenFinding = $False
    $VPNIDs = @()

    if ($VFInstances.count -gt 0){
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            if ($InterfaceConfig -like "service instance*") {
                #Interface is linked to a VFI
                if ($InterfaceConfig -like "bridge-domain*") {
                    #Interface has an associated bridge-domain
                    $domain = (($InterfaceConfig | Select-String -Pattern "^bridge-domain") -split " ")[1] #extract the domain number
                    $domainMatched = $False
                    foreach ($vfi in $VFInstances) {
                        # Iterate over VFI to check for matches
                        $VFIConfig = Get-Section $ShowRunningConfig $vfi.ToString()
                        if ($VFIConfig -like "bridge-domain*") {
                            #Check if vfi has a bridge domain associated
                            $VFIdomain = (($VFIConfig | Select-String -Pattern "^bridge-domain") -split " ")[1] #extract vfi bridge domain number
                            if ($VFIdomain -contains $domain){
                                $domainMatched = $True
                                #This VFI matches our interface
                                if ($VFIConfig -like "vpn id *") {
                                    #VFI has a proper VPN ID
                                    $VpnID = (($VFIConfig | Select-String -Pattern "^vpn id") -split " ")[2] #extract vpn id
                                    if ($VPNIDs -contains $VpnID) {
                                        #check to see if vpn id is globally unique
                                        $OpenFinding = $True
                                        $FindingDetails += "The Interface ($Interface) is associated to a VFI ($vfi) configured with a 'non-globally' unique VPN ID ($VpnID). All Virtual Forwarding Instances (VFI) must be configured with a 'globally' unique VPN ID." | Out-String
                                        $FindingDetails += "" | Out-String
                                    }
                                    else {
                                        # Interface and associated VPN are valid and unique.
                                        $VPNIDs += $VpnID
                                        continue
                                    }
                                }
                                else {
                                    $FindingDetails += "The Interface ($Interface) is associated to a VFI ($vfi) but the VFI is not configured with a globally unique VPN ID. All Virtual Forwarding Instances (VFI) must be configured with a globally unique VPN ID." | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                }
                            }
                        }
                    }
                    if (!($domainMatched)) {
                        $FindingDetails += "The Interface ($Interface) has been configured with an attachment circuit (service instance *) but is not bound to a properly configured matching VFI via a bridge domain. Interfaces with configured attachment circuits (service instance * ethernet) must be appropriately bound to an existing Virtual Forwarding Instance (VFI) that is properly configured with a bridge domain and globally unique VPN ID." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
                else {
                    $FindingDetails += "The Interface ($Interface) is configured with a customer attachment circuit (service instance *) but not associated to an appropriately configured bridge domain (bridge-domain *). All interfaces configured with attachment circuits must be associated to a properly configured VFI with a globally unique VPN ID and assigned bridge-domain." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    elseif ($VFInstances.count -eq 0) {
        $FindingDetails += "No VFI configurations exist on this device. STIG not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "NotAFinding"
    }
    else {
        $FindingDetails += "All interfaces with attachment circuits are associated to appropriately configured Virtual Forwarding Instances (VFIs)." | Out-String
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

Function Get-V221043 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221043
        STIG ID    : CISC-RT-000690
        Rule ID    : SV-221043r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000010
        Rule Title : The Cisco PE switch must be configured to enforce the split-horizon rule for all pseudowires within a Virtual Private LAN Services (VPLS) bridge domain.
        DiscussMD5 : CA07F1E4E61066CBFA1A5B24069F814B
        CheckMD5   : D0027067F2D836180032FF9F695CA6A7
        FixMD5     : 113549FF777CB120F63E9E7436ACB8D3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $VFInstances = $ShowRunningConfig | Select-String -Pattern "^l2 vfi.*"
    $NonCompliantVFI = @()

    foreach ($vfi in $VFInstances){
        $VFIConfig = Get-Section $ShowRunningConfig $vfi.ToString()
        if ($VFIConfig -like "neighbor * encapsulation mpls no-split-horizon*") {
            $NonCompliantVFI += $vfi
        }
    }

    if ($NonCompliantVFI.count -gt 0) {
        $FindingDetails += "The following Virtual Forwarding Instances (VFIs) have 'split horizon' disabled for 'neighbor' configuration. Enable split horizon for all VFI configurations with the following command:('neighbor X.X.X.X encapsulation mpls') on all PE switches deploying VPLS in a full-mesh configuration." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "---------- Non Compliant Virtual Forward Instances (VFIs) ----------" | Out-String
        foreach ($nvfi in $NonCompliantVFI) {
            $FindingDetails += $nvfi.ToString() | Out-String
        }
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

Function Get-V221044 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221044
        STIG ID    : CISC-RT-000700
        Rule ID    : SV-221044r622190_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000002
        Rule Title : The Cisco PE switch providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.
        DiscussMD5 : 90BB27F85C57CD268FDA0B7D9EEFF566
        CheckMD5   : 7819E46BBE900834F530A1D47A4BCECF
        FixMD5     : D5F0E5AB3EB61CB7B9F43D853EAFFF3F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OpenFinding = $False
    $NonCompliantInterfaces = @()
    $CompliantInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "service instance*") {
            if ($InterfaceConfig -like "bridge-domain*") {
                if ($InterfaceConfig -like "storm-control broadcast cir *") {
                    $CompliantInterfaces += $Interface
                }
                else {
                    $NonCompliantInterfaces += $Interface
                    $OpenFinding = $True
                }
            }
            else {
                $NonCompliantInterfaces += $Interface
                $OpenFinding = $True
            }
        }

    }

    if ($OpenFinding) {
        $FindingDetails += "The following interfaces have bridge domains configured but lack sufficient storm control threshold configurations. Configure storm control for each CE-facing interface providing Virtual Private LAN Services (VPLS)." | Out-String
        $FindingDetails += "" | Out-String
        Foreach ($int in $NonCompliantInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $Status = "Open"
    }
    else {
        $FindingDetails += "No interfaces with bridge domains were detected." | Out-String
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

Function Get-V221045 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221045
        STIG ID    : CISC-RT-000710
        Rule ID    : SV-221045r856419_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000119
        Rule Title : The Cisco PE switch must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.
        DiscussMD5 : 6D93EE9D6B47AEE77CB69F2BE0DC346B
        CheckMD5   : FA35107CCF01971A71EE9C809F66108B
        FixMD5     : 4795531DA1E99678D064FE9F4A5BC6DF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $BridgeDomains = $ShowRunningConfig | Select-String -Pattern "^bridge-domain"
    $NonCompliantBridgeDomains = @()

    if ($BridgeDomains.Count -lt 1) {
        $Status = "NotAFinding"
        $FindingDetails += "No Virtual Private LAN Services (VPLS) bridge domain exists so no limit on the number of MAC addresses it can learn are currently required in this configuration." | Out-String
        $FindingDetails += ""
    }
    else {
        ForEach ($domain in $BridgeDomains){
            $BridgeDomainConfig = Get-Section $ShowRunningConfig $domain.ToString()
            if (!($BridgeDomainConfig -like "no ip igmp snooping*")) {
                $NonCompliantBridgeDomains += $domain
            }
        }

    }

    if ($NonCompliantBridgeDomains.count -gt 0) {
        $FindingDetails += "The following Virtual Private LAN Services (VPLS) bridge domains do not have a limit for the number of MAC addresses it can learn properly configured." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------- Non Compliant Bridge Domains -------------" | Out-String
        ForEach ($domain in $NonCompliantBridgeDomains){
            $FindingDetails += $domain.ToString() | Out-String
        }
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

Function Get-V221046 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221046
        STIG ID    : CISC-RT-000720
        Rule ID    : SV-221046r622190_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-NET-000192-RTR-000002
        Rule Title : The Cisco PE switch must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.
        DiscussMD5 : 978A5A385B3BF033EBBD96BEBF47D43A
        CheckMD5   : 4217C9F1E5BF08AC48F69BADB0942DC1
        FixMD5     : 70555D930C4F3BA09C4E64472BE6C880
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $BridgeDomains = $ShowRunningConfig | Select-String -Pattern "^bridge-domain"
    $NonCompliantBridgeDomains = @()

    if ($BridgeDomains.Count -lt 1) {
        $Status = "NotAFinding"
        $FindingDetails += "No Virtual Private LAN Services (VPLS) bridge domain exists so no limit on the number of MAC addresses it can learn are currently required in this configuration." | Out-String
        $FindingDetails += ""
    }
    else {
        ForEach ($domain in $BridgeDomains){
            $BridgeDomainConfig = Get-Section $ShowRunningConfig $domain.ToString()
            if (!($BridgeDomainConfig -like "mac limit maximum addresses*")) {
                $NonCompliantBridgeDomains += $domain
            }
        }

    }

    if ($NonCompliantBridgeDomains.count -gt 0) {
        $FindingDetails += "The following Virtual Private LAN Services (VPLS) bridge domains do not have a limit for the number of MAC addresses it can learn properly configured." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------- Non Compliant Bridge Domains -------------" | Out-String
        ForEach ($domain in $NonCompliantBridgeDomains){
            $FindingDetails += $domain.ToString() | Out-String
        }
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

Function Get-V221047 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221047
        STIG ID    : CISC-RT-000730
        Rule ID    : SV-221047r622190_rule
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

Function Get-V221048 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221048
        STIG ID    : CISC-RT-000740
        Rule ID    : SV-221048r622190_rule
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

Function Get-V221049 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221049
        STIG ID    : CISC-RT-000750
        Rule ID    : SV-221049r945860_rule
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

Function Get-V221050 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221050
        STIG ID    : CISC-RT-000760
        Rule ID    : SV-221050r917445_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000113
        Rule Title : The Cisco PE switch must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : 3ED253A8C7E48F6B7785F67864C65759
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

Function Get-V221051 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221051
        STIG ID    : CISC-RT-000770
        Rule ID    : SV-221051r917448_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000114
        Rule Title : The Cisco P switch must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : 3ED253A8C7E48F6B7785F67864C65759
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

Function Get-V221052 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221052
        STIG ID    : CISC-RT-000780
        Rule ID    : SV-221052r622190_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000112
        Rule Title : The Cisco switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.
        DiscussMD5 : F5E8F727DE225728A2565FF8E60E3B0A
        CheckMD5   : 81B7AF0BC45C864ACC5E655C28357F3B
        FixMD5     : A9CCCAEDA09F0892E82F48811D9BA127
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map"
    $PolicyMaps = $ShowRunningConfig | Select-String -Pattern "^policy-map"
    $ClassMapNames = @()
    $VerifiedPolicies = $False

    if ($ClassMaps.count -eq 0) {
        $FindingDetails += "No class map has been configured on this device. Verify that a class map has been configured with a 'match ip *' applied and that the designated class map has been applied to a policy-map with any additional 'bandwith percent #' configurations required." | Out-String
        $FindingDetails += "This device must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    elseif ($PolicyMaps.count -eq 0) {
        $FindingDetails += "No policy map has been configured on this device. Review the device configuration and remediate." | Out-String
        $FindingDetails += "This device must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
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
                            $FindingDetails += "Review the configuration below and verify that the device is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
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
            $FindingDetails += "Class maps have been found in this device configuration but lack the proper 'match ip *' configuration. Review this device to determine if it is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
    }

    if (!$VerifiedPolicies) {
        $FindingDetails += "No compliant QoS policies have been identified for this requirement. Review this device to determine if it is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
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

Function Get-V221053 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221053
        STIG ID    : CISC-RT-000790
        Rule ID    : SV-221053r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000003
        Rule Title : The Cisco multicast switch must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.
        DiscussMD5 : FDA087E6DA2563A2C50197901527B8E2
        CheckMD5   : EA167FCCDE880CCEABFD3B00F13160BB
        FixMD5     : 48684F1D2BFB609904C8B66BA8FFCCFB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221054 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221054
        STIG ID    : CISC-RT-000800
        Rule ID    : SV-221054r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000004
        Rule Title : The Cisco multicast switch must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.
        DiscussMD5 : C631995CEC6B6258C0A0097B8032491A
        CheckMD5   : 6DDF7FD0704D59EB839017B1A0467493
        FixMD5     : D7BE7E2195E639A053CCC23AC438E55A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "------------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip pim neighbor-filter*")) {
                # Add interface with PIM but without a neighbor ACL to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "The below interface configured with PIM requires a neighbor ACL configured:" | Out-String
                $FindingDetails += "---------------------------------------------------------------------------" | Out-String
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
                        $FindingDetails += "Standard ACL $ACLName entries:" | Out-String
                        $FindingDetails += "------------------------------" | Out-String
                        $FindingDetails += ($ACLConfig | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    ForEach ($Item in $ACLConfig) {
                        IF ($Item -like "permit*") {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Review the configured ACL under $Interface for filtering PIM neighbors and make finding determination based on STIG check guidance." | Out-String
                            $FindingDetails += "PIM Neighbor ACL $ACLName permit statements:" | Out-String
                            $FindingDetails += "--------------------------------------------" | Out-String
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

Function Get-V221055 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221055
        STIG ID    : CISC-RT-000810
        Rule ID    : SV-221055r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000005
        Rule Title : The Cisco multicast edge switch must be configured to establish boundaries for administratively scoped multicast traffic.
        DiscussMD5 : 62F442656F21941DAB2FF8599EB32308
        CheckMD5   : 002DD0497C4BC5BA0EB0804BEFE545AC
        FixMD5     : 3B42764F7F2A4A2343764BAF3B93004C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "------------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip multicast boundary*")) {
                # Add interface with PIM but without a multicast boundary to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if any of the below interfaces are part of the multicast edge and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without multicast boundary configured:" | Out-String
                $FindingDetails += "------------------------------------------------" | Out-String
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
                    IF (!($ACLConfig -like "deny 239.0.0.0 0.255.255.255*") -or $ACLConfig -like "permit any") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the configured ACL $ACLName under $Interface to verify that admin-scope multicast traffic is blocked and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "Standard ACL $ACLName entries:" | Out-String
                        $FindingDetails += "------------------------------" | Out-String
                        $FindingDetails += ($ACLConfig | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Standard ACL $ACLName under $Interface is blocking admin-scope multicast traffic." | Out-String
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

Function Get-V221056 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221056
        STIG ID    : CISC-RT-000820
        Rule ID    : SV-221056r863379_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000120
        Rule Title : The Cisco multicast Rendezvous Point (RP) switch must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.
        DiscussMD5 : DD7CF19375DDF25E220DFCAEB60BD84A
        CheckMD5   : 83F96EB98F84934F1AD28399D1F4AF20
        FixMD5     : 3C63288B8DD8B4242927CFEC869D0C20
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Verify if an RP is configured.
    IF (!($ShowRunningConfig | Select-String -Pattern "^ip pim rp-address")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no RPs configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip pim accept-register list*")) {
            # Add missing filter for PIM register to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured with a policy to filter PIM register messages for any undesirable multicast groups and sources (missing 'ip pim accept-register list ACL')." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get ACL Name
            $ACLName = ($ShowRunningConfig | Select-String -Pattern "^ip pim accept-register list").ToString().Split([char[]]"") | Select-Object -Last 1
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            # Verify if ACL is configured
            IF (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "ACL $ACLName used to filter PIM register messages for any undesirable multicast groups and sources is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the ACL $ACLName is filtering PIM register messages for any undesirable multicast groups and sources and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "ACL $ACLName entries:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += ($ACLConfig | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        IF (!($ShowRunningConfig | Select-String -Pattern "ip pim register-rate-limit")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured to rate limit the number of PIM register messages (missing 'ip pim register-rate-limit nn')." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        Else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is configured to rate limit the number of PIM register messages." | Out-String
            $FindingDetails += "" | Out-String
        }
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
                IF (!($InterfaceConfig -like "ip access-group * in")) {
                    # Add interface with PIM but without an inbound ACL to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify if the below interface is used for MSDP peering and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "Interface without an inbound ACL configured:" | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
                ELSE {
                    $ACLName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
                    IF (!$ACLExtended) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Inbound extended ACL $ACLName under $Interface is not configured." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    ELSE {
                        # Add ACL entries to FindingDetails
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Verify that extended ACL $ACLName under $Interface restricts MSDP peerings to only known sources and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "ACL $ACLName entries:" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += ($ACLConfig | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                        $Exception = $True
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

Function Get-V221057 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221057
        STIG ID    : CISC-RT-000830
        Rule ID    : SV-221057r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000013
        Rule Title : The Cisco multicast Rendezvous Point (RP) switch must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated switch (DR) for any undesirable multicast groups and sources.
        DiscussMD5 : AFBA9F976485DD6E345D358C87F4D9A7
        CheckMD5   : BBF1385D7443E3D33602A73D0D7122EC
        FixMD5     : BBE45D1FAF6AD55C32F09138CCCA873C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Verify if an RP is configured.
    IF (!($ShowRunningConfig | Select-String -Pattern "^ip pim rp-address")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no RPs configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip pim accept-register list*")) {
            # Add missing filter for PIM register to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not configured with a policy to filter PIM register messages for any undesirable multicast groups and sources (missing 'ip pim accept-register list ACL')." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get ACL Name
            $ACLName = ($ShowRunningConfig | Select-String -Pattern "^ip pim accept-register list").ToString().Split([char[]]"") | Select-Object -Last 1
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            # Verify if ACL is configured
            IF (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Extended ACL $ACLName used to filter PIM register messages for any undesirable multicast groups and sources is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the extended ACL $ACLName is filtering PIM register messages received from a multicast DR for any undesirable multicast groups and sources and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V221058 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221058
        STIG ID    : CISC-RT-000840
        Rule ID    : SV-221058r622190_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000014
        Rule Title : The Cisco multicast Rendezvous Point (RP) switch must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Cisco switch (DR) for any undesirable multicast groups.
        DiscussMD5 : 886093DB12B8C178DBD7B6AB20443EE9
        CheckMD5   : E3F6DDF1AF022DF262D146012DCB3F3D
        FixMD5     : 1F2E4D93F1BE970C45727217F078AD26
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Verify if an RP is configured.
    IF (!($ShowRunningConfig | Select-String -Pattern "^ip pim rp-address")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no RPs configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $RPAddress = ($ShowRunningConfig | Select-String -Pattern "^ip pim rp-address").ToString().Split([char[]]"") | Select-Object -Index 3
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip pim accept-rp $RPAddress")) {
            # Add missing filter for PIM join messages to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The RP $RPAddress is not configured with a policy to filter PIM join messages for any undesirable multicast groups (missing 'ip pim accept-rp $RPAddress ACL')." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Get ACL Name
            $ACLName = ($ShowRunningConfig | Select-String -Pattern "^ip pim accept-rp $RPAddress").ToString().Split([char[]]"") | Select-Object -Last 1
            $ACLStandard = $ShowRunningConfig | Select-String -Pattern "^ip access-list standard $ACLName"
            # Verify if ACL is configured
            IF (!$ACLStandard) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Standard ACL $ACLName used to filter PIM join messages for any undesirable multicast groups is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLStandard.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the standard ACL $ACLName is filtering PIM join messages received from a DR for any undesirable multicast groups and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V221059 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221059
        STIG ID    : CISC-RT-000850
        Rule ID    : SV-221059r856422_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000121
        Rule Title : The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.
        DiscussMD5 : 3939FE094EF11D9C37F634F47CAE8EB0
        CheckMD5   : B61F38AB3B1E2CFDDB08B244AA6DADDE
        FixMD5     : 154947E1F20767CBCEB3E24664E584BD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    IF ($ShowRunningConfig | Select-String -Pattern "ip pim rp-address") {
        $PimRate = $ShowRunningConfig | Select-String -Pattern "ip pim register-rate-limit"
        IF (!$PimRate) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is not rate limiting the number of PIM register messages." | Out-String
            $FindingDetails += "'ip pim register-rate-limit' is not configured." | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device is rate limiting the number of PIM register messages:" | Out-String
            $FindingDetails += ($PimRate[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "PIM RP is not configured on this device." | Out-String
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

Function Get-V221060 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221060
        STIG ID    : CISC-RT-000860
        Rule ID    : SV-221060r863380_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000114
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.
        DiscussMD5 : BC62F6A539A6B3CDB8D915307F15609E
        CheckMD5   : FE062640E1AD6E0F850FC68D30138BC1
        FixMD5     : ECC46F4815A26B521CF33862E2FC1298
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V221061 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221061
        STIG ID    : CISC-RT-000870
        Rule ID    : SV-221061r863381_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000115
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.
        DiscussMD5 : BC62F6A539A6B3CDB8D915307F15609E
        CheckMD5   : BD21E80F584298FBFBE9F322B13EF77C
        FixMD5     : DAD103E494D7F0822D0DBC5B8003A82B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "------------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip igmp access-group*")) {
                # Add interface with PIM but without an IGMP join filter to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below is a host facing interface and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without an IGMP or MLD Report messages filter configured:" | Out-String
                $FindingDetails += "-------------------------------------------------------------------" | Out-String
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
                    $FindingDetails += "---------------------" | Out-String
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

Function Get-V221062 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221062
        STIG ID    : CISC-RT-000880
        Rule ID    : SV-221062r856425_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000122
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
        DiscussMD5 : 2B0E4219AA504E037A04A9B60293ADCB
        CheckMD5   : 908E475E29EFF6BA437E903E311238E4
        FixMD5     : 0AAD037194CE882F30C162ACD2354D1D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip igmp limit" | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Status = "NotAFinding"
        }
        ELSE {
            $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
            ForEach ($Interface in $Interfaces) {
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                IF (!($InterfaceConfig -like "ip igmp limit*")) {
                    # Add non-compliant interface to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review the device configuration to verify that IGMP limits are configured on each host-facing interface." | Out-String
                    $FindingDetails += "Interface without 'ip igmp limit nn' configured:" | Out-String
                    $FindingDetails += "------------------------------------------------" | Out-String
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

Function Get-V221063 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221063
        STIG ID    : CISC-RT-000890
        Rule ID    : SV-221063r945856_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000123
        Rule Title : The Cisco multicast Designated switch (DR) must be configured to set the shortest-path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.
        DiscussMD5 : 507C888746404F970A477FB1964FE73E
        CheckMD5   : 305D2AE41002899A2CDAE536E1E40843
        FixMD5     : 6A0B6A2FC6E9677976FCAF050F2F70EC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "'ip pim spt-threshold infinity' is configured on this device." | Out-String
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

Function Get-V221064 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221064
        STIG ID    : CISC-RT-000900
        Rule ID    : SV-221064r856427_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000116
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to only accept MSDP packets from known MSDP peers.
        DiscussMD5 : 1A7FE31E82562B7F4C3E53AF55A331A7
        CheckMD5   : B0FCFA4D71A9EABED25090F7B8D4E291
        FixMD5     : 696FC25DC8A91C13ED3122F175167CB5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "------------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!($InterfaceConfig -like "ip access-group * in")) {
                # Add interface with PIM but without an inbound ACL to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below interface is used for MSDP peering and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Interface without an extended inbound ACL configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            ELSE {
                $ACLName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* in").ToString().Split([char[]]"") | Select-Object -Index 2
                $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
                IF (!$ACLExtended) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound extended ACL $ACLName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify that the extended ACL $ACLName under $Interface restricts MSDP peerings to only known sources and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V221065 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221065
        STIG ID    : CISC-RT-000910
        Rule ID    : SV-221065r856428_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-NET-000343-RTR-000002
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to authenticate all received MSDP packets.
        DiscussMD5 : 47F6897BB7D7E80EC4FF4ED4932B8C7D
        CheckMD5   : 4ECF94469CFDD1FC033CC2DCA27AA8B8
        FixMD5     : CDC8B2CD2984E9165EAE71B203E92E0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MsdpPeerConfig = @()
    $OpenFinding = $False

    IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp peer")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MSDP peers are not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $MsdpPeerConfig = $ShowRunningConfig | Select-String -Pattern "^ip msdp peer"
        ForEach ($Item in $MsdpPeerConfig) {
            $MsdpPeerIp = (($Item.ToString() | Select-String -Pattern "(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(.(?!$)|$)){4}").Matches.Value).Trim()
            IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp password peer $MsdpPeerIp")) {
                    # Add non-compliant peers to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review the device configuration to verify that 'ip msdp password peer' is properly configured on this device." | Out-String
                    $FindingDetails += "Non-Compliant Peer:" | Out-String
                    $FindingDetails += "-------------------" | Out-String
                    $FindingDetails += ($Item.ToString() | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
            }
            ELSE {
                # Add compliant peers to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Compliant Peer:" | Out-String
                $FindingDetails += "---------------" | Out-String
                $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip msdp password peer $MsdpPeerIp" | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($Item.ToString() | Out-String).Trim()
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221066 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221066
        STIG ID    : CISC-RT-000920
        Rule ID    : SV-221066r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000007
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.
        DiscussMD5 : 26FD0939ECAA9E74BBA47AD487FDCAC2
        CheckMD5   : 4D6923F6272FA5A8DB3EEDE4A8674615
        FixMD5     : 4AAA6DC4AA4D1A227805D53EF4A739FC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MsdpPeerConfig = @()
    $OpenFinding = $False
    $Exception = $False

    IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp peer")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MSDP peers are not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $MsdpPeerConfig = $ShowRunningConfig | Select-String -Pattern "^ip msdp peer"
        ForEach ($Item in $MsdpPeerConfig) {
            # Get MSDP peer IP address.
            $MsdpPeerIp = (($Item.ToString() | Select-String -Pattern "(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(.(?!$)|$)){4}").Matches.Value).Trim()
            IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp sa-filter in $MsdpPeerIp list")) {
                    # Add non-compliant peers to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "MSDP peers require import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses." | Out-String
                    $FindingDetails += "MSDP Peer with no ACL configured:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($Item.ToString() | Out-String).Trim().Split([char[]]"") | Select-Object -First 4
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
            }
            ELSE {
                $ACLName = ($ShowRunningConfig | Select-String -Pattern "^ip msdp sa-filter in $MsdpPeerIp list").ToString().Split([char[]]"") | Select-Object -Last 1
                $ACL = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
                IF (!$ACL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Extended ACL $ACLName required to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    $ACLConfig = Get-Section $ShowRunningConfig $ACL.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "MSDP Peer with extended ACL $ACLName configured:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($Item.ToString() | Out-String).Trim().Split([char[]]"") | Select-Object -First 4
                    $FindingDetails += "" | Out-String
                    IF ($ACLConfig | Select-String -Pattern "permit ip any any") {
                        $Exception = $True
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "'permit ip any any' configured on ACL $ACLName." | Out-String
                        $FindingDetails += "Verify if all deny statements are configured prior to 'permit ip any any' and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.3") {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += "deny ip any host 224.0.1.3" | Out-String
                            $FindingDetails += "" | Out-String
                        }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.3" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.24") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.24" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.24" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.22") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.22" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.22" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.2") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.2" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.2" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.35") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.35" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.35" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.60") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.60" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.60" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.39") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.39" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.39" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any host 224.0.1.40") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.40" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any host 224.0.1.40" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any 232.0.0.0 0.255.255.255") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any 232.0.0.0 0.255.255.255" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any 232.0.0.0 0.255.255.255" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip any 239.0.0.0 0.255.255.255") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any 239.0.0.0 0.255.255.255" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip any 239.0.0.0 0.255.255.255" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip 10.0.0.0 0.255.255.255 any") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 10.0.0.0 0.255.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 10.0.0.0 0.255.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip 127.0.0.0 0.255.255.255 any") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 127.0.0.0 0.255.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 127.0.0.0 0.255.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip 172.16.0.0 0.15.255.255 any") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 172.16.0.0 0.15.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 172.16.0.0 0.15.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    IF ($ACLConfig | Select-String -Pattern "deny ip 192.168.0.0 0.0.255.255 any") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry configured on ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 192.168.0.0 0.0.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Deny entry missing from ACL $ACLName :" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "deny ip 192.168.0.0 0.0.255.255 any" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
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

Function Get-V221067 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221067
        STIG ID    : CISC-RT-000930
        Rule ID    : SV-221067r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000008
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.
        DiscussMD5 : 4941DAD27354E7533595B49B65260840
        CheckMD5   : 5B081FC2FD2AC72E24820347CCBDE8BD
        FixMD5     : 317A1DF882A6D7BDA248CFFC186A7DD4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Verify if there are MSDP peers configured.
    IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp peer*")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no MSDP peers configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $MsdpPeers = $ShowRunningConfig | Select-String -Pattern "^ip msdp peer*"
        ForEach ($MsdpPeer in $MsdpPeers) {
            $MsdpPeer = ($MsdpPeer | Out-String).Trim().ToString().Split([char[]]"") | Select-Object -Index 3
            IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp sa-filter out $MsdpPeer list")) {
                # Add missing outbound source-active filter for MSDP peer to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below is an external MSDP peer and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "MSDP peer without an outbound source-active filter configured:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += "ip msdp peer $MsdpPeer" | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            ELSE {
                # Get ACL Name
                $ACLName = ($ShowRunningConfig | Select-String -Pattern "^ip msdp sa-filter out $MsdpPeer list").ToString().Split([char[]]"") | Select-Object -Last 1
                $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
                # Verify if ACL is configured
                IF (!$ACLExtended) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Extended ACL $ACLName used to filter source-active multicast advertisements to external MSDP peers is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review extended ACL $ACLName and verify that MSDP source-active messages being sent to MSDP peers do not leak advertisements that are local and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V221068 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221068
        STIG ID    : CISC-RT-000940
        Rule ID    : SV-221068r622190_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000009
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to limit the amount of source-active messages it accepts on a per-peer basis.
        DiscussMD5 : BC0690A42BCD932B4EB2EB9549F2C385
        CheckMD5   : 949726A3F16099CCDE90096FC918311C
        FixMD5     : 161F2E26E6EFD6A0DDA8BC4F9084D0C6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MsdpPeerConfig = @()
    $OpenFinding = $False

    IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp peer")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MSDP peers are not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $MsdpPeerConfig = $ShowRunningConfig | Select-String -Pattern "^ip msdp peer"
        ForEach ($Item in $MsdpPeerConfig) {
            $MsdpPeerIp = (($Item.ToString() | Select-String -Pattern "(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(.(?!$)|$)){4}").Matches.Value).Trim()
            IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp sa-limit $MsdpPeerIp")) {
                    # Add non-compliant peers to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review the device configuration to verify that 'ip msdp sa-limit' is properly configured on this device." | Out-String
                    $FindingDetails += "Non-Compliant Peers:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($Item.ToString() | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
            }
            ELSE {
                # Add compliant peers to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Compliant Peers:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += ($Item.ToString() | Out-String).Trim()
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221069 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221069
        STIG ID    : CISC-RT-000950
        Rule ID    : SV-221069r622190_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000011
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to use a loopback address as the source address when originating MSDP traffic.
        DiscussMD5 : 0E2721633DCE088659538C79532CE3D6
        CheckMD5   : 88D1CA191B72CCA5797A5F5C7D759BAB
        FixMD5     : C9FB9D3F6B7E659A355D605E57A22665
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MsdpPeerConfig = @()
    $OpenFinding = $False

    IF (!($ShowRunningConfig | Select-String -Pattern "^ip msdp peer")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MSDP peers are not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $MsdpPeerConfig = $ShowRunningConfig | Select-String -Pattern "^ip msdp peer"
        ForEach ($Item in $MsdpPeerConfig) {
            IF (!($Item.ToString() | Select-String -Pattern "connect-source Loopback")) {
                    # Add non-compliant peers to FindingDetails
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review the device configuration to verify that 'ip msdp peer' uses its loopback address as the source address when originating MSDP traffic." | Out-String
                    $FindingDetails += "Non-Compliant Peers:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($Item.ToString() | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
            }
            ELSE {
                # Add compliant peers to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Compliant Peers:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += ($Item.ToString() | Out-String).Trim()
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237750 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237750
        STIG ID    : CISC-RT-000235
        Rule ID    : SV-237750r648776_rule
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

Function Get-V237752 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237752
        STIG ID    : CISC-RT-000236
        Rule ID    : SV-237752r648780_rule
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

Function Get-V237756 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237756
        STIG ID    : CISC-RT-000237
        Rule ID    : SV-237756r999760_rule
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

Function Get-V237759 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237759
        STIG ID    : CISC-RT-000391
        Rule ID    : SV-237759r648792_rule
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

Function Get-V237762 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237762
        STIG ID    : CISC-RT-000392
        Rule ID    : SV-237762r950991_rule
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

Function Get-V237764 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237764
        STIG ID    : CISC-RT-000393
        Rule ID    : SV-237764r856665_rule
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

Function Get-V237766 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237766
        STIG ID    : CISC-RT-000394
        Rule ID    : SV-237766r856667_rule
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

Function Get-V237772 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237772
        STIG ID    : CISC-RT-000395
        Rule ID    : SV-237772r856669_rule
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

Function Get-V237774 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237774
        STIG ID    : CISC-RT-000396
        Rule ID    : SV-237774r856671_rule
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

Function Get-V237776 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237776
        STIG ID    : CISC-RT-000397
        Rule ID    : SV-237776r856673_rule
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

Function Get-V237778 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237778
        STIG ID    : CISC-RT-000398
        Rule ID    : SV-237778r856675_rule
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCBIqeUR+YnwzGs
# ckFrNlzaBAiqU29rQJTCN2AbgL1Aw6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCBnmtjIGnu+pPdLmgLJoGPKE4nPTz/qwGTqo69esdiPYDANBgkqhkiG9w0BAQEF
# AASCAQAcALFgpf/naTmliAha8dDqvPEjH7d43sji7VzQcOchJkvjabYvYlj4kD6O
# 8TG2G/hPC3SIXKsYViHBXxVGC5N295tkxNcSIdqNROnDzhIeFvQjBlx6I1Hx7etB
# KeEUVIZ0G+hKG5CSpEeQjht27OY51Sm41oIbByipKbHYjLiih70B3rLIC5M8cvuB
# bi+xAYUuFmO5Q5Khupyt9Tg4P/Xfp9WuWWgqY6Ne559F20dsq4iSHJ+oxupO3mKY
# sDncH5lQdgjsOYAGTEnMUOz9ZGji1dwstOoa8ozy4jxfQpGSFqKE+3QOPme8/sRb
# ZrdFXkGpbJe7Cn+wZj9wL3eUaOa9oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTYzOVowLwYJKoZIhvcNAQkEMSIEIApWVfYljbS8w7xmFHRSuhF8bCJY
# O2MJcGfRRjlmJ9BUMA0GCSqGSIb3DQEBAQUABIICAD0mgzCnFgk+qjclZqOhkjvb
# CX4SY9mcM5pM2eTXdOGPr3kwwT4gQp+GB18++AA8qNvC5zyhDvSdrp1UNYOqzkoR
# gZ4MPG790kqWFFYoYo9RMMqO6/lfmeZLMt9Tw/6WKegwRDOXFsd09c5Soh7u7Z8D
# xuDxezLta0Ai9ArWKgjI9A26qcmlmTi8vpW42zWO0bPpFmzjN5A5u5GfT7+X77ZW
# Bnxid95mgEe5ZAl1dBJQY6E+0UTWjftcHkeHbMeeXEFvXnSH27KqyFRWqKNCNAX4
# pJPqXXRixiEdCD7ar0LKYMG+J1CTtGBNjLLCyoYI3eaRtnAT3/iCb903StKx6u7I
# rRP/BvlTva06Bg9P2KLHwVt9WKWFpq3DOUgqKTwYEI42EDR5w79Af+sLl8UjRnA9
# KEEtI7LFVu1+imxR8h+p2UPounDun80OHLGE2TzqR/ar9hrhwW+o03wg4fqQHd5N
# GkpaQsU9npR4y4G1YCpJqpmRC5I2C3er0PhT/KDE+E3sKl09iv17xWjmwMP7xPd0
# QmFg70qTiQR/jtextyFsHla+z2JYO+CmDkqN/KvtqaHm/YyaxfaFXtLqehy3dOH4
# eIPM4MHiEsHyDZwIaEPyCxVGQyEVOzQUGWLyT5GvOtaClN27HnyX77e1jg3p2pZ6
# bNv+JFI8bDgfrOcYTuFD
# SIG # End signature block
