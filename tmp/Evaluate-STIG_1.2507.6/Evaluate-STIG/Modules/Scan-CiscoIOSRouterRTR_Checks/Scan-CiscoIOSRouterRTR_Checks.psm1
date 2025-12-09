##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS Router RTR
# Version:  V3R3
# Class:    UNCLASSIFIED
# Updated:  10/7/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V216551 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216551
        STIG ID    : CISC-RT-000010
        Rule ID    : SV-216551r1007821_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000001
        Rule Title : The Cisco router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.
        DiscussMD5 : 2F00D27AF1DDECB8F99F4CAFFF230C18
        CheckMD5   : CBE1B669DE1832CD0033F2D875731A36
        FixMD5     : 0A58AD13EE11A7BFBD85113ABB6B35C1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "Verify if the below interface requires an Access Control List (ACL) to allow or deny traffic for specific source and destination addresses as well as ports and protocols and make finding determination based on STIG check guidance." | Out-String
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
                $FindingDetails += "Inbound ACL $ACLName under $Interface is not configured." | Out-String
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

Function Get-V216555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216555
        STIG ID    : CISC-RT-000050
        Rule ID    : SV-216555r1007824_rule
        CCI ID     : CCI-000803, CCI-002205
        Rule Name  : SRG-NET-000168-RTR-000078
        Rule Title : The Cisco router must be configured to enable routing protocol authentication using FIPS 198-1 algorithms with keys not exceeding 180 days of lifetime.
        DiscussMD5 : 87FE0A00E795631BFE3EE27302A89E07
        CheckMD5   : 25324A65D922C766A77BC475C7BF0EE7
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

Function Get-V216556 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216556
        STIG ID    : CISC-RT-000060
        Rule ID    : SV-216556r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000007
        Rule Title : The Cisco router must be configured to have all inactive interfaces disabled.
        DiscussMD5 : CF11435C63FA613CCB396A7EA6AE337D
        CheckMD5   : 3CAA103F31C21EA846D2DCFBE8861112
        FixMD5     : 46B9F38416FABAB85922B0D3B4B125FD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "shutdown")) {
            # Add enabled (no shutdown) interface to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review if the below is an inactive interface and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "The below interface is enabled (no shutdown):" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        ELSE {
            # Add not enabled (shutdown) interface to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The below interface is not enabled (shutdown):" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
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

Function Get-V216559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216559
        STIG ID    : CISC-RT-000090
        Rule ID    : SV-216559r856180_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000109
        Rule Title : The Cisco router must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.
        DiscussMD5 : DE8491522A4956F725339F3D14CCB5A5
        CheckMD5   : 7E9C9B17E0E2FF9C95056874D7CF3124
        FixMD5     : 785F61F05EDDF071CE9002CC5E55041D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216560 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216560
        STIG ID    : CISC-RT-000120
        Rule ID    : SV-216560r991835_rule
        CCI ID     : CCI-001097, CCI-002385, CCI-004866
        Rule Name  : SRG-NET-000362-RTR-000110
        Rule Title : The Cisco router must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by employing control plane protection.
        DiscussMD5 : B5F6E45D5BC4A26AA0640B36C1A997AB
        CheckMD5   : A789B5F394A8BD45CC81BBE917BED144
        FixMD5     : CEA704850CEAF0868497BDFDA4327DF2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216563 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216563
        STIG ID    : CISC-RT-000150
        Rule ID    : SV-216563r856182_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000111
        Rule Title : The Cisco router must be configured to have Gratuitous ARP disabled on all external interfaces.
        DiscussMD5 : 4079563A47158A2AC9D218FA97C791BA
        CheckMD5   : FB6B86A59A8B6A38BE0B183D60FF48A7
        FixMD5     : 2F7265A32FAB9C9F1F9B9CE42B1CB683
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216564 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216564
        STIG ID    : CISC-RT-000160
        Rule ID    : SV-216564r856183_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000112
        Rule Title : The Cisco router must be configured to have IP directed broadcast disabled on all interfaces.
        DiscussMD5 : C7C9EC64928AFE84A2285002F4337BE9
        CheckMD5   : 72B625D85A365BED9C41E911B54D78BB
        FixMD5     : 78D937674F7D0716F8A9E756739FE2A9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216565 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216565
        STIG ID    : CISC-RT-000170
        Rule ID    : SV-216565r856184_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000113
        Rule Title : The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
        DiscussMD5 : B158847153C15A3DCED3E37EC4308D48
        CheckMD5   : C24D6223AC960853D14B195E02ECD034
        FixMD5     : 8CEB032395A602067AD93F651D28026D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $count = 0
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -notcontains "no ip unreachables") {
            $OpenFinding = $True
            $Status = "Open"
            $FindingDetails += "Review the switch configuration below and verify that 'no ip unreachables' is configured on all external interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
            $count += 1
        }
    }
    if (!$OpenFinding){ 
        $FindingDetails += "There are no interfaces with ICMP unreachable messages configured on this device."
        $Status = "NotAFinding."
    }
    else {
        $FindingDetails += "" | Out-String
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

Function Get-V216566 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216566
        STIG ID    : CISC-RT-000180
        Rule ID    : SV-216566r856185_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000114
        Rule Title : The Cisco router must be configured to have Internet Control Message Protocol (ICMP) mask reply messages disabled on all external interfaces.
        DiscussMD5 : 584565EC957CFC2E39988E08985844B8
        CheckMD5   : 85AF71547B67B2915669F762684450D2
        FixMD5     : B212809129504D96B14A83E4ECE2FE9F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216567 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216567
        STIG ID    : CISC-RT-000190
        Rule ID    : SV-216567r856186_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000115
        Rule Title : The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.
        DiscussMD5 : 28F4F11F66A3AE986F120CD52D1CD226
        CheckMD5   : 8E5DDC67FF79041D82EBD044E0419D2A
        FixMD5     : 5F2DA08DE51C4ADB75D81AEA9FC636A0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -notcontains "no ip redirects".Trim()) {
            $OpenFinding = $True
            $Status = "Open"
            $FindingDetails += "Review the switch configuration below and verify that ICMP redirects are disabled on all external interfaces." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
            $count += 1
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

Function Get-V216568 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216568
        STIG ID    : CISC-RT-000200
        Rule ID    : SV-216568r531085_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-NET-000078-RTR-000001
        Rule Title : The Cisco router must be configured to log all packets that have been dropped at interfaces via an ACL.
        DiscussMD5 : FE94D3A3F2DBEE19BA50B5E322FE11F4
        CheckMD5   : CE689B66BF9FD509C7BD81B898241073
        FixMD5     : 76C4C5360E176A186D558547E022358B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216569 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216569
        STIG ID    : CISC-RT-000210
        Rule ID    : SV-216569r531085_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-NET-000076-RTR-000001
        Rule Title : The Cisco router must be configured to produce audit records containing information to establish where the events occurred.
        DiscussMD5 : 75A86BD72D61D9A19187BA8B18FC737E
        CheckMD5   : 1F934F26F3B0F8C0C74A55F4B27A79C1
        FixMD5     : 0B2BD0BE8DD6890AD83AE8F47A2D6E85
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "ACLs not logging-input dropped packets:" | Out-String
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

Function Get-V216570 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216570
        STIG ID    : CISC-RT-000220
        Rule ID    : SV-216570r531085_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-NET-000077-RTR-000001
        Rule Title : The Cisco router must be configured to produce audit records containing information to establish the source of the events.
        DiscussMD5 : 43B48607F27628D3CE3E18F07250F3B8
        CheckMD5   : 972085C3E43A21037F01BAB13A4C824E
        FixMD5     : 0B2BD0BE8DD6890AD83AE8F47A2D6E85
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "ACLs not logging-input dropped packets:" | Out-String
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

Function Get-V216571 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216571
        STIG ID    : CISC-RT-000230
        Rule ID    : SV-216571r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000001
        Rule Title : The Cisco router must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.
        DiscussMD5 : 5107AFE69A4758707203036A80B6EC01
        CheckMD5   : 0446163BDD7CE53E4766FF4A28591537
        FixMD5     : E41F5968801E37CD47FE05A7CFBFA823
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        IF (!(Get-Section $ShowRunningConfig $LineAux[0].ToString() | Select-String -Pattern "no exec")) {
            $FindingDetails += "'no exec' is not configured under $LineAux." | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "'no exec' is configured under $LineAux." | Out-String
            $Status = "NotAFinding"
        }    
    }
    Else {
        $FindingDetails += "line aux is not configured" | Out-String
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

Function Get-V216572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216572
        STIG ID    : CISC-RT-000240
        Rule ID    : SV-216572r531085_rule
        CCI ID     : CCI-001109
        Rule Name  : SRG-NET-000202-RTR-000001
        Rule Title : The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.
        DiscussMD5 : A7866C6F77EDE7578FAA64386238B650
        CheckMD5   : 4CE21321AB192B3356DCADB2A9074DFF
        FixMD5     : 91C626E1AEC29BB698B1AA56ABD4B9F3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "Inbound ACL $ACLName under $Interface is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify that the ACL $ACLName under $Interface is configured to allow specific ports and protocols and deny all other traffic and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216573 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216573
        STIG ID    : CISC-RT-000250
        Rule ID    : SV-216573r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000002
        Rule Title : The Cisco perimeter router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.
        DiscussMD5 : 44F0EAA765E18A783388CFE0F0607DD8
        CheckMD5   : 08F64994B7F60D03A292E9D10AE94BD3
        FixMD5     : 534821DE4F271D2119F9038E8AD921DE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216574 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216574
        STIG ID    : CISC-RT-000260
        Rule ID    : SV-216574r856187_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000109
        Rule Title : The Cisco perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
        DiscussMD5 : B7A8ABE4E87430A07316D294D66EA58D
        CheckMD5   : 96F75F4DAEB10CDAE26CC93B2EF036ED
        FixMD5     : 9A1F085B8B1294CA6BCB08F2F2567B2C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "Interface with an inbound ACL configured:" | Out-String
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

Function Get-V216575 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216575
        STIG ID    : CISC-RT-000270
        Rule ID    : SV-216575r863237_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000110
        Rule Title : The Cisco perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.
        DiscussMD5 : FF2A4B7629939398BC463DF86378208A
        CheckMD5   : B13CAFA1633DE157E31E03EF21E6B2F7
        FixMD5     : 371505FA1DB0A53E2B8394927E9D1FDF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
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
    'deny ip 240.0.0.0 15.255.255.255 any log-input')
    
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended"
    $ACLList = @()
    $UncompliantInterfaces = @()
    $OpenFinding = $False

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
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($matches['content'].ToString() | Out-String)
                $ACLList += ($matches['content'].ToString() | Out-String).Trim()
            }
            else {
                $ACLList += ($matches['content'].ToString() | Out-String).Trim()
                #$ACLList += ($matches['content'].ToString() | Out-String).Trim()
                $FindingDetails += ($matches['content'].ToString() | Out-String)
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
            }
        }
    }
    else {
        $FindingDetails += "No ACLs have been properly configured to block inbound packets with source Bogon IP address prefixes." | Out-String
        $FindingDetails += "Review the router configuration to verify that an ingress Access Control List (ACL) is applied to all external interfaces and blocking packets with Bogon source addresses." | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $FindingDetails += "There are currently ACLs configured on the device to block bogon prefixes but they are not applied on the following interfaces. Verify that the inbound ACL applied to all external interfaces will block all traffic from Bogon source addresses." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($int in $UncompliantInterfaces) {
            $FindingDetails += $int | Out-String
            
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

Function Get-V216576 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216576
        STIG ID    : CISC-RT-000280
        Rule ID    : SV-216576r1050872_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000008
        Rule Title : The Cisco perimeter router must be configured to protect an enclave connected to an approved gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.
        DiscussMD5 : B4653BE058981BE5225C33F405C67F6A
        CheckMD5   : 7B68DA919EFA488B240B390C2D82EC1C
        FixMD5     : F16495AF39666B43E647FC04F691017D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "Verify if the below interface connects to an ISP and make finding determination based on STIG check guidance." | Out-String
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
                    $FindingDetails += "If $Interface connects to an ISP, verify that the inbound ACL $ACLInName is configured to allow traffic to specific destination addresses (i.e. enclave’s NIPRNet address space), and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216577 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216577
        STIG ID    : CISC-RT-000290
        Rule ID    : SV-216577r1050875_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000009
        Rule Title : The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an approved gateway service provider.
        DiscussMD5 : C52F5F28FCC7D533E1EE873DF178FB29
        CheckMD5   : 2DE35CBE1195619B93AB14A9F7AE7C82
        FixMD5     : FA81977BC448A11728DE94DA52DBC7D4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IPAddress = @()
    
    # Check if BGP is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    ELSE {
        # Get interface configuration.
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*AppGigabitEthernet*"}
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -like "ip address *")) {
                # Add L2 interface (no IP address configured) to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Layer 2 Interface:" | Out-String
                $FindingDetails += "------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            ELSE {
                $IPAddress = ($InterfaceConfig | Select-String -Pattern "ip address *")
                # Add IP address to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Determine if the below interface is BGP peering with the ISP Router." | Out-String
                $FindingDetails += "--------------------------------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                ForEach ($Item in $IPAddress) {
                    $NewIPAddress = $Item.ToString()
                    $FindingDetails += ($NewIPAddress | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                $Exception = $True
            }
        }
    
        # Get main BGP table configuration.
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        $BgpNeighbor = @()
        ForEach ($Entry in $RouterBgpConfig) {
            $NewBgpConfig += $Entry | Out-String
            # Get BGP neighbors from main BGP table.
            IF ($Entry | Select-String -Pattern "remote-as*") {
                $BgpNeighbor += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
            }
            ELSEIF ($Entry | Select-String -Pattern "address-family ipv4") {
                Break
            }
        }
        IF ($NewBgpConfig) {
            # Add BGP Neighbors to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the device configuration to verify that this device is not BGP peering with the ISP and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "BGP neighbor configuration in main BGP Table:" | Out-String
            $FindingDetails += "---------------------------------------------" | Out-String
            $FindingDetails += ($RouterBgp.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($BgpNeighbor | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    
        #Get BGP VRFs configuration.
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
        
            ForEach ($Entry in $RouterBgpVrfConfig) {
                IF ($Entry | Select-String -Pattern "address-family ipv4*") {
                    $Vrf = ($Entry | Select-String -Pattern "address-family ipv4*" | Out-String).Trim().Split([char[]]"")[-1]
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review the device configuration to verify that this device is not BGP peering with the ISP and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "BGP neighbor or Peer Group configuration in VRF ${Vrf}:" | Out-String
                    $FindingDetails += "------------------------------------------------------" | Out-String
                }
                ELSEIF ($Entry | Select-String -Pattern "remote-as*") {
                    $FindingDetails += ($Entry | Select-String -Pattern "remote-as*" | Out-String).Trim()
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

Function Get-V216578 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216578
        STIG ID    : CISC-RT-000300
        Rule ID    : SV-216578r1050878_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000010
        Rule Title : The Cisco perimeter router must be configured to not redistribute static routes to an approved gateway service provider into BGP, an IGP peering with the NIPRNet, or other autonomous systems.
        DiscussMD5 : AE066EC9821C361477F4BF1416216D93
        CheckMD5   : 090CB294174ACEB4DE7EA0384EEE5043
        FixMD5     : BDEC429C0D8F3F395DDA351A91256D5F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    # Check if OSPF is configured
    IF (!($ShowRunningConfig | Select-String -Pattern "^router ospf")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "OSPF is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String    
    }
    ELSE {
        $RouterOspf = $ShowRunningConfig | Select-String -Pattern "^router ospf*"
        $RouterOspfConfig = Get-Section $ShowRunningConfig $RouterOspf.ToString()
        # Check if OSPF static redistribution is configured
        IF (!($RouterOspfConfig | Select-String -Pattern "redistribute static")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "OSPF is not configured to redistribute static routes." | Out-String
            $FindingDetails += "" | Out-String    
        }
        ELSE {
            $FindingDetails += "" | Out-String    
            $FindingDetails += "OSPF is configured to redistribute static routes. Review the static routes and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String    
            $Exception = $True
        }
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
        # Check if EIGRP static redistribution is configured
        IF (!($RouterEigrpConfig | Select-String -Pattern "redistribute static")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "EIGRP is not configured to redistribute static routes." | Out-String
            $FindingDetails += "" | Out-String    
        }
        ELSE {
            $FindingDetails += "" | Out-String    
            $FindingDetails += "EIGRP is configured to redistribute static routes. Review the static routes and make finding determination based on STIG check guidance." | Out-String
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
        $RouterRip = $ShowRunningConfig | Select-String -Pattern "^router rip*"
        $RouterRipConfig = Get-Section $ShowRunningConfig $RouterRip.ToString()
        # Check if RIP static redistribution is configured
        IF (!($RouterRipConfig | Select-String -Pattern "redistribute static")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "RIP is not configured to redistribute static routes." | Out-String
            $FindingDetails += "" | Out-String    
        }
        ELSE {
            $FindingDetails += "" | Out-String    
            $FindingDetails += "RIP is configured to redistribute static routes. Review the static routes and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String    
            $Exception = $True
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
        $BgpNeighbor = @()
        ForEach ($Entry in $RouterBgpConfig) {
            $NewBgpConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                Break
            }
        }
        # Check if BGP static redistribution is configured in main BGP table
        IF (!($NewBgpConfig | Select-String -Pattern "redistribute static")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "BGP is not configured to redistribute static routes in main BGP Table." | Out-String
            $FindingDetails += "" | Out-String    
        }
        ELSE {
            $FindingDetails += "" | Out-String    
            $FindingDetails += "BGP is configured to redistribute static routes in main BGP Table. Review the static routes and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String    
            $Exception = $True
        }
    
        #Get BGP VRFs configuration.
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
        }
        
        ForEach ($Entry in $RouterBgpVrfConfig) {
            # Get config from BGP VRF.
            $NewBgpVrfConfig += $Entry | Out-String
            IF ($Entry | Select-String -Pattern "exit-address-family") {
                $NewBgpVrfConfig = ($NewBgpVrfConfig -split "[\r\n]+")
                $Vrf = ($NewBgpVrfConfig | Select-String -Pattern "address-family ipv4 vrf" | Out-String).Trim().Split([char[]]"")[-1]
                # Check if BGP static redistribution is configured in BGP VRF
                IF (!($NewBgpVrfConfig | Select-String -Pattern "redistribute static")) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "BGP is not configured to redistribute static routes in VRF $Vrf." | Out-String
                    $FindingDetails += "" | Out-String            
                }
                ELSE {
                    $FindingDetails += "" | Out-String    
                    $FindingDetails += "BGP is configured to redistribute static routes in VRF $Vrf. Review the static routes and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String    
                    $Exception = $True
                }
                IF ($NewBgpVrfConfig) {
                    Clear-Variable -Name "NewBgpVrfConfig"
                }
                continue
            }
        }
    }
    
    IF ($Exception) {
        # Check if there are static routes
        IF (!($ShowRunningConfig | Select-String -Pattern "^ip route*")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "There are no static routes configured on this device." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $False
        }
        ELSE {
            $StaticIp = ($ShowRunningConfig | Select-String -Pattern "^ip route*")
            $FindingDetails += "" | Out-String    
            $FindingDetails += "Review the below static routes to determine if any contain the next hop address of the alternate gateway and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($StaticIp | Out-String).Trim()
            $FindingDetails += "" | Out-String    
        }    
    }
    ELSE {
        $FindingDetails += "" | Out-String    
        $FindingDetails += "This device is not redistributing static routes into any IGP nor BGP." | Out-String
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

Function Get-V216580 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216580
        STIG ID    : CISC-RT-000320
        Rule ID    : SV-216580r1007822_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000003
        Rule Title : The Cisco perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.
        DiscussMD5 : 5427F5419DAACF78B385DB328483654D
        CheckMD5   : EDADDB4DB0D06A84F3D10C49AF0BB2F7
        FixMD5     : 241F927A985A389D696ADC162665BDE9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216581 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216581
        STIG ID    : CISC-RT-000330
        Rule ID    : SV-216581r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000004
        Rule Title : The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.
        DiscussMD5 : 242B7359B47A49AC1A5518D08E3218C0
        CheckMD5   : 8EEF12FB2BABE92DA96A158314D5F1C0
        FixMD5     : DFB4B79B42C7C3D6BA006CD1FAFCA932
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $aclPositive = @()
    $aclNegative = @()
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ip access-group * in") {
            $aclPositive += ($Interface.ToString() | Out-String).Trim()
        }
        else {
            $aclNegative += ($Interface | Out-String).Trim()
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216582 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216582
        STIG ID    : CISC-RT-000340
        Rule ID    : SV-216582r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000005
        Rule Title : The Cisco perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction.
        DiscussMD5 : 242B7359B47A49AC1A5518D08E3218C0
        CheckMD5   : 157688AB8078C1CF56B1874456FF010F
        FixMD5     : 23FA98129FCA6DF112C2D547FF4E1117
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $aclPositive = @()
    $aclNegative = @()
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ip access-group * in") {
            $aclPositive += ($Interface.ToString() | Out-String).Trim()
        }
        else {
            $aclNegative += ($Interface | Out-String).Trim()
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216584 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216584
        STIG ID    : CISC-RT-000360
        Rule ID    : SV-216584r856189_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
        DiscussMD5 : 9270173D7E9AA5C805DF67936581541B
        CheckMD5   : 3E209AB5483211DF7D92C41AAEC2F977
        FixMD5     : F014220521C453002C1231F9D38AFB72
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "--------------------------" | Out-String
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

Function Get-V216585 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216585
        STIG ID    : CISC-RT-000370
        Rule ID    : SV-216585r856190_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter router must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.
        DiscussMD5 : 5D66B0E62DE6E36DD2641D3152AE00CF
        CheckMD5   : D8EC917320AE081239D3386DA191AACA
        FixMD5     : 8A566D94A4DAFF534A23645260A055BD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            Else {
                # Add compliant interface to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Compliant Interface:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
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

Function Get-V216586 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216586
        STIG ID    : CISC-RT-000380
        Rule ID    : SV-216586r856191_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000112
        Rule Title : The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.
        DiscussMD5 : C698836D6831E473338364E5CD0F025A
        CheckMD5   : 70E1832218A6361E958496085D5BB4EC
        FixMD5     : 81294104DCD6704615740526B6F8BC82
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $NonCompliantInt += " "
            $OpenFinding = $True
        }
        Else {
            # Add compliant interface to inventory
            $CompliantInt += ($Interface | Out-String).Trim()
            $CompliantInt += " "
        }
    }

    IF ($NonCompliantInt) {
        $Status = "Open"
        $FindingDetails += "Review the device configuration to verify that 'no ip proxy-arp' is enabled on all external interfaces:" | Out-String
        $FindingDetails += "Interfaces without 'no ip proxy-arp enabled'" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        ForEach ($Interface in $NonCompliantInt) {
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String   
        }
    }
    Else {
        $FindingDetails += "Compliant Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        ForEach ($Interface in $CompliantInt) {
            $FindingDetails += "" | Out-String
            $FindingDetails += $Interface | Out-String
        }
    }

    IF (!($OpenFinding)) {
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

Function Get-V216587 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216587
        STIG ID    : CISC-RT-000390
        Rule ID    : SV-216587r945857_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000364-RTR-000113
        Rule Title : The Cisco perimeter router must be configured to block all outbound management traffic.
        DiscussMD5 : C47C470B04B9AD60043EAB341E8417A1
        CheckMD5   : 7478FDCB4151F09970EBFBFCE0B0C172
        FixMD5     : 877CB41493FBD8F5385DC460C890F313
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        ELSE {
            $ACLName = ($InterfaceConfig | Select-String -Pattern "ip access-group .* out").ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $ACLName`$"
            IF (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Outbound ACL $ACLName under $Interface is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify that the ACL $ACLName under $Interface is configured to block all management traffic and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216588 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216588
        STIG ID    : CISC-RT-000400
        Rule ID    : SV-216588r991838_rule
        CCI ID     : CCI-001097, CCI-004891
        Rule Name  : SRG-NET-000205-RTR-000009
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.
        DiscussMD5 : 406AB996463C887DB43FA08F3B651F94
        CheckMD5   : 442ABEBA95DE6CEBA007802825B20C4B
        FixMD5     : 67C7B6AA650E339BA10DDD07B18BFE08
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $CryptosIsakmpPolicies = $ShowRunningConfig | Select-String -Pattern "^crypto isakmp policy .*"
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $OpenFinding = $False
    $ApplicableInterfaces = @()
    $ValidISAKMPPolicies = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "crypto map *") {
            $ApplicableInterfaces += $Interface
        }
    }
    if ($ApplicableInterfaces.count -eq 0) {
        $FindingDetails += "-- No crypto maps applied on any interfaces. --" | Out-String
        $FindingDetails += "Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. Verify that management traffic is transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($CryptosIsakmpPolicies.count -eq 0) {
        $FindingDetails += "-- No crypto iskmp policies detected on this device. --" | Out-String
        $FindingDetails += "Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. Verify that management traffic is transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        foreach ($policy in $CryptosIsakmpPolicies) {
            $policyConfig = Get-Section $ShowRunningConfig $policy.ToString()
            if ($policyConfig -contains "hash sha256" -and $policyConfig -contains "authentication pre-share" -and $policyConfig -like "crypto isakmp key *"){
                $ValidISAKMPPolicies += $policy
            }
        }
        if ($ValidISAKMPPolicies.count -eq 0) {
            $OpenFinding = $True
            $FindingDetails += "-- No valid crypto iskmp policies configured with 'hash sha256' and 'authentication pre-share' configured on device. --" | Out-String
            $FindingDetails += "Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. Verify that management traffic is transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    
    if (!($ShowRunningConfig -like "crypto isakmp key * address *")) {
        $FindingDetails += "-- No pre-shared key or remote peer address configuration found in device configuration. --" | Out-String
        $FindingDetails += "Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. Verify that management traffic is transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    if (!($ShowRunningConfig -match "^crypto ipsec transform-set .* ah-sha256-hmac esp-aes")) {
        #not working why?
        $FindingDetails += "-- No IPSec transform set configuration detected for data encryption. --" | Out-String
        $FindingDetails += "Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. Verify that management traffic is transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    if (!$OpenFinding) {
        foreach ($Interface in $ApplicableInterfaces){
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $CMap = $InterfaceConfig | Select-String -Pattern "^crypto map *"
            $MapName = ($CMap -split " ")[2]
            $CryptoMap = $ShowRunningConfig | Select-String -Pattern "^crypto map $MapName"
            $CryptoMapConfig = Get-Section $ShowRunningConfig $CryptoMap.ToString()
            #Write-Output "Config: $CryptoMapConfig"
            $InterfaceValid = $True

            if (!$CryptoMapConfig -like "set peer *") {
                $InterfaceValid = $False
            }
            elseif (!$CryptoMapConfig -like "set transform-set *") {
                $InterfaceValid = $False
            }
            elseif (!$CryptoMapConfig -like "match address *") {
                $InterfaceValid = $False
            }

            if ($InterfaceValid) {
                $FindingDetails += "++  The interface below is configured with a valid crypto map and other required configurations appear to be in place on this device.  ++" | Out-String
                $FindingDetails += "Review the configurations below and compare with the network topology diagram to determine connectivity between the managed network and the NOC. Validate the path and interface that the management traffic traverses. Verify that management traffic is transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel. Verify the crypto map is applied to the external interface." | Out-String
                $FindingDetails += "---------------------------------------- Interface Configuration ----------------------------------------" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "---------------------------------------- Crypto Map Configuration ----------------------------------------" | Out-String
                $FindingDetails += $CryptoMap | Out-String
                $FindingDetails += $CryptoMapConfig | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "---------------------------------------- Crypto ISAKMP Configurations ----------------------------------------" | Out-String
                forEach ($policy in $ValidISAKMPPolicies){
                    $FindingDetails += $policy | Out-String
                    $policyConfig = Get-Section $ShowRunningConfig $policy.ToString()
                    $FindingDetails += $policyConfig | Out-String
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "---------------------------------------- Crypto Transform Set Configuration ----------------------------------------" | Out-String
                $Transform = $ShowRunningConfig | Select-String -Pattern "^crypto ipsec transform-set .* ah-sha256-hmac esp-aes"
                $FindingDetails += $Transform | Out-String
                $FindingDetails += "" | Out-String
                $Status = "Not_Reviewed"
            }
        }
    }
    else {
        $FindingDetails += "The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel. Current configurations do not meet this requirement." | Out-String
        $FindingDetails += "Review the device configurations and compare with the network topology diagram to determine connectivity between the managed network and the NOC. Validate the path and interface that the management traffic traverses. Verify that management traffic is transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel. Verify the crypto map is applied to the external interface." | Out-String
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

Function Get-V216589 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216589
        STIG ID    : CISC-RT-000410
        Rule ID    : SV-216589r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000010
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).
        DiscussMD5 : 9629B6535AD16F18F566C074229188BB
        CheckMD5   : FC203B8D9B38F5BAD5E39A681D53F940
        FixMD5     : 0561D667D86F6DAF9FA270F1CD13C5B1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OutboundACLInterfaces = @()
    $CryptoMapInterfaces = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        #Condition for IPsec Tunnel
        if ($InterfaceConfig -like "crypto map *") {
            $CryptoMapInterfaces += $Interface
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $CMap = $InterfaceConfig | Select-String -Pattern "^crypto map *"
            $MapName = ($CMap -split " ")[2]
            $CryptoMap = $ShowRunningConfig | Select-String -Pattern "^crypto map $MapName"
            
            if ($CryptoMap) {
                $CryptoMapConfig = Get-Section $ShowRunningConfig $CryptoMap.ToString()
                if ($CryptoMapConfig -like "match address *") {
                    $match = $CryptoMapConfig | Select-String -Pattern "^match address"
                    $AclName = ($match -split " ")[2]
                    $AccessList = $ShowRunningConfig | Select-String -Pattern "^ip access-list extended $AclName"
                    if ($AccessList) {
                        $ACLConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
                        $FindingDetails += "The following interface ($Interface) is configured with an ACL configured crypto map ($CMap) and appears to match this requirement. Review the configurations below and verify ACLs to permit only authorized management traffic into IPsec tunnels or the OOBM interface used for forwarding management of traffic to the Network Operations Center (NOC)." | Out-String
                        $FindingDetails += "---------------------------------------- Interface Configuration ----------------------------------------" | Out-String
                        $FindingDetails += $Interface | Out-String
                        $FindingDetails += $InterfaceConfig | Out-String
                        $FindingDetails += ""
                        $FindingDetails += "---------------------------------------- Crypto Map Configuration ----------------------------------------" | Out-String
                        $FindingDetails += $CryptoMap | Out-String
                        $FindingDetails += $CryptoMapConfig | Out-String
                        $FindingDetails += ""
                        $FindingDetails += "---------------------------------------- ACL Configuration ----------------------------------------" | Out-String
                        $FindingDetails += $AccessList | Out-String
                        $FindingDetails += $ACLConfig | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    else {
                        $FindingDetails += "The following interface ($Interface) is configured with an ACL configured crypto map ($CMap) but the device lacks the corresponding configured ACL associated. Review the configurations below and verify the ACL exists on the device." | Out-String
                        $FindingDetails += "---------------------------------------- Interface Configuration ----------------------------------------" | Out-String
                        $FindingDetails += $Interface | Out-String
                        $FindingDetails += $InterfaceConfig | Out-String
                        $FindingDetails += ""
                        $FindingDetails += "---------------------------------------- Crypto Map Configuration ----------------------------------------" | Out-String
                        $FindingDetails += $CryptoMap | Out-String
                        $FindingDetails += $CryptoMapConfig | Out-String
                        $FindingDetails += ""
                    }
                }
            }
            else {
                $FindingDetails += "The following interface ($Interface) is configured with a crypto map ($CMap) for an IPSec tunnel but the device lacks the corresponding configured crypto map associated. Review the configurations below and verify the an appropriately configured crypto map and corresponding ACL exists on the device." | Out-String
                $FindingDetails += "---------------------------------------- Interface Configuration ----------------------------------------" | Out-String
                $FindingDetails += $Interface | Out-String
                $FindingDetails += $InterfaceConfig | Out-String
                $FindingDetails += ""
            }
        }
        #Condition for NOC management traffic outbound ACL
        elseif ($InterfaceConfig -like "ip access-group * out") {
            $OutboundACLInterfaces += $Interface
        }
    }

    if ($OutboundACLInterfaces.count -gt 0) {
        $FindingDetails += "These interfaces contain outbound ACLs. If one of these is the OOBM interface, review the interface and its outbound ACLs and verify only management traffic is forwarded to the NOC." | Out-String
        $FindingDetails += "---------------------------------------- Interfaces ----------------------------------------" | Out-String
        ForEach ($Interface in $OutboundACLInterfaces){
            $FindingDetails += $Interface.ToString() | Out-String
        }
        $FindingDetails += ""
    }
    elseif ($CryptoMapInterfaces.count -eq 0) {
        $FindingDetails += "No interfaces containing outbound ACLs or interfaces configured with an IPSec tunnel have been detected. The Cisco out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC). Review the device configuration and verify the appropriate steps have been taken." | Out-String
        $FindingDetails += ""
    }

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

Function Get-V216590 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216590
        STIG ID    : CISC-RT-000420
        Rule ID    : SV-216590r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000011
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network.
        DiscussMD5 : CF022CD5F75841E20CC261A9AFE489E8
        CheckMD5   : 94D2FA55DA2570F5C4DB238AEC024126
        FixMD5     : 593E9E6CE82E95CEC9297FD736A21376
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OSPFList = $ShowRunningConfig | Select-String -Pattern "^router ospf"

    If ($OSPFList.count -eq 0){
        $FindingDetails += "This device has no 'router ospf' configurations. The requirement for the (OOBM) gateway router to have separate IGP instances for the managed network and management network do not apply." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Applicable"
    }
    elseif ($OSPFList.count -eq 1) {
        $FindingDetails += "This device has a single 'router ospf' configurations. The Cisco out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network. Verify that the OOBM interface is configured to have separate IGP instances for the managed network and management network, if applicable to this device." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Not_Reviewed"
    }
    else {
        $vrfs = @()
        $networks = @()
        forEach ($ospf in $OSPFList) {
            if ($ospf -like "router ospf * vrf *") {
                $OSPFConfig = Get-Section $ShowRunningConfig $ospf.ToString()
                $vrfName = ($ospf -split " ")[4]
                if ($vrfs -contains $vrfName) {
                    $FindingDetails += "This Router OSPF VRF name appears to be a duplicate name and may cause conflicts. Review the configuration breakout below and verify there is not a conflicting name schema between VRF names." | Out-String
                    $OpenFinding = $True
                    forEach ($name in $OSPFList) {
                        $FindingDetails += $name.ToString() | Out-String
                    }
                    $FindingDetails += '' | Out-String
                    $FindingDetails += "" | Out-String
                }
                
                if ($OSPFConfig -like "network * area *") {
                    $network = $OSPFConfig | Select-String -Pattern "^network .* area .*"
                    
                    if ($networks -like $network) {
                        $FindingDetails += "This network configuration of this VRF has been found in duplicate with another accessed Router OSPF VRF configuration. Verify that the router has separate IGP instances configured for the managed network and management network." | Out-String
                        $FindingDetails += "------------------------------ Current Router OSPF VRF Configuration ------------------------------" | Out-String
                        $FindingDetails += "VRF Name: $vrfName -- Network Configuration: $network" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "------------------------------ Router OSPF VRF Configurations Detected (Potential Conflicts) ------------------------------" | Out-String
                        $cnt = 0
                        foreach ($net in $networks) {
                            $dupVRF = $vrfs[$cnt]
                            $FindingDetails += "VRF Name: $dupVRF -- Network Configuration: $net" | Out-String
                            $cnt += 1
                        }
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                    }
                    $networks += $network
                }
                $vrfs += $vrfName
            }
        }
    }

    if ($OpenFinding) {
        $FindingDetails += "Review the router OSPF VRF network configurations and verify that the OOBM interface is an adjacency in the IGP domain for the management network via separate VRF. The router should be configured to have separate IGP instances for the managed network and management network." | Out-String
        $Status = "Not_Reviewed"
        Write-Output $vrfs
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216591 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216591
        STIG ID    : CISC-RT-000430
        Rule ID    : SV-216591r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000012
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.
        DiscussMD5 : B36D2655D72BDDA49C669E1A1737E380
        CheckMD5   : 92720C60A42E7C6CC5715DE8EE13836F
        FixMD5     : BEEC1D941C0275CC7389A641284BFADE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IpVrfs = @()
    $VrfConfigAll = @()
    $IpVrfs = $ShowRunningConfig | Select-String -Pattern "^ip vrf"

    IF ($IpVrfs) {
        ForEach ($IpVrf in $IpVrfs) {
            $VrfConfigAll += $IpVrf.ToString()
            $VrfConfigAll += Get-Section $ShowRunningConfig $IpVrf.ToString()
        }

        ForEach ($IpVrf in $IpVrfs) {
            $VrfConfig = @()
            $Vrf = @()
            $VrfConfig += $IpVrf.ToString() | Out-String
            $VrfConfig += Get-Section $ShowRunningConfig $IpVrf.ToString() | Out-String
            $VrfConfig = $VrfConfig.Split([Environment]::NewLine)
            ForEach ($item in $VrfConfig) {
                IF ($item -like "ip vrf*") {
                    $VrfName = ($item | Select-String -Pattern "ip vrf").ToString().Split([char[]]"") | Select-Object -Last 1
                    $Vrf += $VrfName
                }
                IF ($item -like "route-target export*") {
                    $RtExport = ($item | Select-String -Pattern "route-target export").ToString().Split([char[]]"") | Select-Object -Last 1
                    $Vrf += $RtExport
                }
                IF ($item -like "route-target import*") {
                    $RtImport = ($item | Select-String -Pattern "route-target import").ToString().Split([char[]]"") | Select-Object -Last 1
                    $Vrf += $RtImport
                }
            }

            ForEach ($line in $VrfConfigAll) {
                IF ($line -like "ip vrf*") {
                    $NewVrfName = ($line | Select-String -Pattern "ip vrf").ToString().Split([char[]]"") | Select-Object -Last 1
                }
                IF ($NewVrfName -ne $VrfName) {
                    IF ($line -like "route-target import $RtExport") {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "VRF $NewVrfName is importing Route Target $RtExport from VRF $VrfName. Make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                }
            }
            Clear-Variable -Name "Vrf"
        }
    }

    # Get OSPF VRF configuration
    IF ($ShowRunningConfig | Select-String -Pattern "^router ospf .* vrf") {
        $RouterOspf = $ShowRunningConfig | Select-String -Pattern "^router ospf .* vrf"
        $RouterOspfConfig = Get-Section $ShowRunningConfig $RouterOspf.ToString()
        $FindingDetails += "" | Out-String
        $FindingDetails += "Below is the OSPF VRF configuration on this device, make finding determination based on STIG check guidance:" | Out-String
        $FindingDetails += "------------------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += $RouterOspf | Out-String
        $FindingDetails += $RouterOspfConfig | Out-String
        $FindingDetails += "" | Out-String    
    }

    # Get BGP VRF configuration
    $IsVrf = $False
    IF ($ShowRunningConfig | Select-String -Pattern "^router bgp") {
        # Get main BGP table configuration.
        $RouterBgp = $ShowRunningConfig | Select-String -Pattern "^router bgp*"
        $RouterBgpConfig = Get-Section $ShowRunningConfig $RouterBgp.ToString()
        IF ($RouterBgpConfig) {
            ForEach ($Entry in $RouterBgpConfig) {
                $NewBgpConfig += $Entry | Out-String
                IF ($Entry | Select-String -Pattern "address-family ipv4 vrf .*") {
                    $IsVrf = $True
                }
                #Get BGP VRFs configuration.
                IF ($IsVrf) {
                    $RouterBgpVrfConfig += $Entry | Out-String
                }
            }
            IF ($RouterBgpVrfConfig) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Below is the BGP VRF configuration, make finding determination based on STIG check guidance:" | Out-String
                $FindingDetails += "--------------------------------------------------------------------------------------------" | Out-String
                $FindingDetails += $RouterBgp | Out-String
                $FindingDetails += $RouterBgpVrfConfig | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }

    # Get EIGRP VRF configuration
    IF ($ShowRunningConfig | Select-String -Pattern "^router eigrp") {
        $RouterEigrp = $ShowRunningConfig | Select-String -Pattern "^router eigrp"
        $RouterEigrpConfig = Get-Section $ShowRunningConfig $RouterEigrp.ToString()
        # Check if EIGRP VRF is configured
        IF ($RouterEigrpConfig | Select-String -Pattern "address-family ipv4 vrf") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Below is the EIGRP configuration on this device, make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "---------------------------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $RouterEigrp | Out-String
            $FindingDetails += $RouterEigrpConfig | Out-String
            $FindingDetails += "" | Out-String    
        }
    }

    # Get IS-IS VRF configuration
    IF ($ShowRunningConfig | Select-String -Pattern "^router isis") {
        $RouterIsis = $ShowRunningConfig | Select-String -Pattern "^router isis"
        $RouterIsisConfig = Get-Section $ShowRunningConfig $RouterIsis.ToString()
        # Check if IS-IS VRF is configured
        IF ($RouterEigrpConfig | Select-String -Pattern "vrf") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Below is the IS-IS configuration on this device, make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "---------------------------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += $RouterIsis | Out-String
            $FindingDetails += $RouterIsisConfig | Out-String
            $FindingDetails += "" | Out-String    
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

Function Get-V216592 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216592
        STIG ID    : CISC-RT-000440
        Rule ID    : SV-216592r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000011
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the Network Operations Center (NOC).
        DiscussMD5 : 08122C1E2289ABFB8268F25E81B1AE11
        CheckMD5   : 9547D25A71E4DCA27350D048885B0E2C
        FixMD5     : 328BAF9A4F379211AAC9CA2BBDC4E454
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "Verify if the below is an Out of Band Management interface and make finding determination based on STIG check guidance." | Out-String
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
                    $FindingDetails += "If $Interface is Out of Band and connects to the OOBM backbone, verify that traffic destined to itself is only from the OOBM or NOC address space. Or if $Interface is Out of Band Management, verify traffic destined to itself is from the OOBM LAN address space, and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216593 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216593
        STIG ID    : CISC-RT-000450
        Rule ID    : SV-216593r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000012
        Rule Title : The Cisco router must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface.
        DiscussMD5 : E19B70837C37C18058E6A6F2087AE72E
        CheckMD5   : 531FAEF14B354C4E4113D1F8D780279B
        FixMD5     : 55E54A51F105E14E0E16A9A010DC06E6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

        if ($InterfaceConfig -like "ip access-group * in" -and $InterfaceConfig -like "ip access-group * out") {
            $OpenFinding = $True
            $FindingDetails += "This interface ($Interface) contains both an ingress and egress ACL. Review the configuration below. If this is an OOBM (non-dedicated) interface used for management access, verify that the associated ingress ACL only allows management and ICMP traffic and that the egress ACL blocks any transit traffic." | Out-String
            $FindingDetails += "This requirement is only applicable where management access to the router is via an OOBM interface which is not a true OOBM interface." | Out-String
            $FindingDetails += $Interface | Out-String
            $FindingDetails += $InterfaceConfig | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if (!$OpenFinding) {
        $Status = "Not_Reviewed"
        $FindingDetails += "No interfaces containing both an ingress and egress ACL were detected on this device. If this device has an OOBM interface used for management access, verify that it is configured with both an ingress ACL that only allows management and ICMP traffic and an egress ACL that blocks any transit traffic. This requirement is only applicable where management access to the router is via an OOBM interface which is not a true OOBM interface." | Out-String
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

Function Get-V216594 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216594
        STIG ID    : CISC-RT-000460
        Rule ID    : SV-216594r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000013
        Rule Title : The Cisco router providing connectivity to the Network Operations Center (NOC) must be configured to forward all in-band management traffic via an IPsec tunnel.
        DiscussMD5 : 70392E55F4B80776EAC729835EA873B8
        CheckMD5   : A09EC99C5D6CEF93DED326116EF6B371
        FixMD5     : 37FE307F5DE8F86B565B2A0FC885F8DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    $InterfaceCryptoConfig = @()
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -like "crypto map *")) {
            # Add interface without crypto map to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if the below is an external interface and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "Interface without 'crypto map' configured:" | Out-String
            $FindingDetails += "------------------------------------------" | Out-String
            $FindingDetails += ($Interface.ToString() | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        Else {
            # Add interface with crypto map to FindingDetails
            $InterfaceCryptoConfig += $Interface | Out-String
            $InterfaceCryptoConfig += $InterfaceConfig | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interface with 'crypto map' configured:" | Out-String
            $FindingDetails += "---------------------------------------" | Out-String
            $FindingDetails += ($Interface | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($InterfaceConfig | Select-String -Pattern "crypto map *" | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
    }
    
    # Get ISAKMP policy
    IF ($ShowRunningConfig | Select-String -Pattern "^crypto isakmp policy *") {
        $IsakmpPolicy = $ShowRunningConfig | Select-String -Pattern "^crypto isakmp policy *"
        ForEach ($Policy in $IsakmpPolicy) {
            $IsakmpPolicyConfig += $Policy | Out-String
            $IsakmpPolicyConfig += Get-Section $ShowRunningConfig $Policy.ToString() | Out-String
        }
        # Add ISAKMP Policies to FindingDetails
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below ISAKMP Policies have been configured on this device, make finding determination based on STIG check guidance:" | Out-String
        $FindingDetails += "-----------------------------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += ($IsakmpPolicyConfig.ToString() | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There isn't an ISAKMP Policy configured on this device." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    # Get ISAFMP key
    IF ($ShowRunningConfig | Select-String -Pattern "^crypto isakmp key *") {
        $IsakmpKey = $ShowRunningConfig | Select-String -Pattern "^crypto isakmp key *"
        # Add ISAKMP Keys to FindingDetails
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below ISAKMP Keys have been configured on this device, make finding determination based on STIG check guidance:" | Out-String
        $FindingDetails += "-------------------------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += ($IsakmpKey | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There isn't an ISAKMP Key configured on this device." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    # Get IPSEC Transform-Set
    IF ($ShowRunningConfig | Select-String -Pattern "^crypto ipsec transform-set *") {
        $IPSecTS = $ShowRunningConfig | Select-String -Pattern "^crypto ipsec transform-set *"
        # Add IPSEC Transform-Sets to FindingDetails
        $FindingDetails += "" | Out-String
        $FindingDetails += "The below IPSEC Transform-Sets have been configured on this device, make finding determination based on STIG check guidance:" | Out-String
        $FindingDetails += "----------------------------------------------------------------------------------------------------------------------------" | Out-String
        $FindingDetails += ($IPSecTS | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There isn't an IPSEC Transform-Set configured on this device." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    # Get Crypto Map from interface
    IF ($InterfaceCryptoConfig) {
        $InterfaceCryptoConfig = ($InterfaceCryptoConfig -split "[\r\n]+")
        $InterfaceCrypto = @()
        $CryptoMap = @()
        ForEach ($Item in $InterfaceCryptoConfig) {
            IF ($Item.ToString() | Select-String -Pattern "interface *") {
                $InterfaceCrypto += ($Item | Select-String -Pattern "interface *" | Out-String).Trim().Split([char[]]"")[-1]
            }
            IF ($Item.ToString() | Select-String -Pattern "crypto map *") {
                $CryptoMap += ($Item | Select-String -Pattern "crypto map *" | Out-String).Trim().Split([char[]]"")[-1]
            }
        }
        # Get Crypto Map configuration
        IF ($CryptoMap -AND ($ShowRunningConfig | Select-String -Pattern "^crypto map *")) {
            $CM = @()
            ForEach ($Item in $CryptoMap) {
                $CM += $ShowRunningConfig | Select-String -Pattern "^crypto map $Item"
            }
            ForEach ($Item in $CM) {
                $CryptoMapConfig += $Item | Out-String
                $CryptoMapConfig += Get-Section $ShowRunningConfig $Item.ToString() | Out-String
            }
            # Add Crypto Maps to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "The below Crypto Maps have been configured on this device, make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "-------------------------------------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += ($CryptoMapConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Crypto Maps are not properly configured on this device, make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True    
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Crypto Maps are not configured under any interface on this device, make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    
    # Get Crypto Map ACL
    IF ($CryptoMapConfig) {
        $CryptoMapConfig = ($CryptoMapConfig -split "[\r\n]+")
        $CryptoMapACL = @()
        ForEach ($Item in $CryptoMapConfig) {
            IF ($Item.ToString() | Select-String -Pattern "match address *") {
                $CryptoMapACL += ($Item | Select-String -Pattern "match address *" | Out-String).Trim().Split([char[]]"")[-1]
            }
        }
        IF ($CryptoMapACL) {
            $CryptoMapACL = $CryptoMapACL | Select-Object -Unique
            # Get Crypto Map ACL configuration
            ForEach ($Item in $CryptoMapACL) {
                IF ($ShowRunningConfig | Select-String -Pattern "ip access-list extended $Item") {
                    $ACLConfig = "ip access-list extended $Item"
                    $MapACLConfig += $ACLConfig | Out-String
                    $MapACLConfig += Get-Section $ShowRunningConfig $ACLConfig.ToString() | Out-String    
                }
                ELSE {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "ACL $Item is not configured on this device." | Out-String
                    $FindingDetails += "" | Out-String    
                }
            }
            IF ($MapACLConfig) {
            # Add Crypto Map ACLs to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the below ACLs defined in the Crypto Maps and make finding determination based on STIG check guidance:" | Out-String
            $FindingDetails += "-------------------------------------------------------------------------------------------------------------" | Out-String
            $FindingDetails += ($MapACLConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String    
            }
            ELSE {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Crypto Maps ACLs are not properly configured on this device, make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True    
            }
        }
        ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Crypto Maps ACLs are not configured on this device, make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216597 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216597
        STIG ID    : CISC-RT-000490
        Rule ID    : SV-216597r877976_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000002
        Rule Title : The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.
        DiscussMD5 : FE9D220A578DA4091F65B58176564E96
        CheckMD5   : 9D2BCD9A7DDB52F9290F0895A5AD0043
        FixMD5     : 95F129CEA6224BCCCC1ACEE9353D8331
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216598 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216598
        STIG ID    : CISC-RT-000500
        Rule ID    : SV-216598r531085_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000003
        Rule Title : The Cisco BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).
        DiscussMD5 : 15604E7A38DC562D1796E7ED9B97D40D
        CheckMD5   : A4952B5BD3AF6B7DAF571D8001B98509
        FixMD5     : 53808758934C287CF4253F52C400DA36
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216599 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216599
        STIG ID    : CISC-RT-000510
        Rule ID    : SV-216599r917412_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000004
        Rule Title : The Cisco BGP router must be configured to reject inbound route advertisements from a customer edge (CE) router for prefixes that are not allocated to that customer.
        DiscussMD5 : 1E452C1DD618D5C1A5EC12900C5D6A13
        CheckMD5   : 23B0C86BA06458632CF6B474A74354F6
        FixMD5     : E0A6DB764D80FB15920F3376DE127D1E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216600 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216600
        STIG ID    : CISC-RT-000520
        Rule ID    : SV-216600r917414_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000005
        Rule Title : The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).
        DiscussMD5 : 7241C6965424850C42BB97B5150E2364
        CheckMD5   : 1BEB07F06E4D1AE2CC97DEA874AC6F32
        FixMD5     : 4B06E5DD3E26CB99DB7282CF2851A8FC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "Verify if the below Prefix Lists are configured for each customer containing prefixes belonging to customers as well as the local AS and make finding determination based on STIG check guidance:" | Out-String
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
                            IF (!($PrefixListNames | Select-String -Pattern "$NewPrefixListName"))
                            {
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
                            IF ($MissingVrfPrefixLists) {
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

Function Get-V216601 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216601
        STIG ID    : CISC-RT-000530
        Rule ID    : SV-216601r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000006
        Rule Title : The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
        DiscussMD5 : CDC06478CEBD6B4107D41097C2DF244B
        CheckMD5   : 71BF9D88A6ABD203D19995A9D35A259F
        FixMD5     : F22AA6E7353FA7D1DF8EEB3AD914E4E1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216602 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216602
        STIG ID    : CISC-RT-000540
        Rule ID    : SV-216602r945854_rule
        CCI ID     : CCI-000032
        Rule Name  : SRG-NET-000018-RTR-000006
        Rule Title : The Cisco BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.
        DiscussMD5 : 99CE7EAD7813099EF08081FAAE051BCA
        CheckMD5   : 6936E28B467CF1AE000F4A5708BA8727
        FixMD5     : EF1C3BB3FD1680FF2ED4A807CEBD277D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216603 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216603
        STIG ID    : CISC-RT-000550
        Rule ID    : SV-216603r945855_rule
        CCI ID     : CCI-000032
        Rule Name  : SRG-NET-000018-RTR-000010
        Rule Title : The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.
        DiscussMD5 : F925954F4D552EEAF4C06F9150AD2118
        CheckMD5   : 16582DC9F85EFF5BE7F3E4A36E9E53F3
        FixMD5     : 5076200EF8B15965C089924CCA006C62
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216604 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216604
        STIG ID    : CISC-RT-000560
        Rule ID    : SV-216604r856192_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000117
        Rule Title : The Cisco BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.
        DiscussMD5 : DCD144516D9A2A6F0A3433654C5448FA
        CheckMD5   : 8E0BD70AF21C62CF78CECC917489BE84
        FixMD5     : 536C91B0A8AE5B06533C083A0C94A34B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216605 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216605
        STIG ID    : CISC-RT-000570
        Rule ID    : SV-216605r856193_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000118
        Rule Title : The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer.
        DiscussMD5 : 187F252F4E8735A2919EE37717DAF21E
        CheckMD5   : 0A84C69F04A346E681805C323BB86F32
        FixMD5     : D4F937FDB2D605850C7162DB40B86D32
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                        $BgpVrfNeighbor += "" | Out-String
                    }
                    # Get Prefix Lists from BGP VRFs
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

Function Get-V216606 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216606
        STIG ID    : CISC-RT-000580
        Rule ID    : SV-216606r991839_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000001
        Rule Title : The Cisco BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.
        DiscussMD5 : CFA31A84E8CF5C46F70DBA20922F913F
        CheckMD5   : 61D12529A918E3BB9E9844219272E10D
        FixMD5     : 3C5BA9B28D2DA740260C7C046A9A859B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                            $FindingDetails += "BGP neighbor or Peer Group on main BGP table with no update-source Loopback:" | Out-String
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
                            $FindingDetails += "BGP neighbor or Peer Group in VRF $Vrf with no update-source Loopback:" | Out-String
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

Function Get-V216607 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216607
        STIG ID    : CISC-RT-000590
        Rule ID    : SV-216607r991840_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000002
        Rule Title : The Cisco MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.
        DiscussMD5 : 07840DA21E9B8D28F87FBD673D88E6BC
        CheckMD5   : 83E0118D3AD8D791D923F353275064E6
        FixMD5     : 99957F3F55E7E6A847B63C141D363437
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        elseif ($Interfaces.count -gt 0){
            $FindingDetails += "Loopback interfaces exist but none are configured with an IP address required for LDP peering configuration. Configure the device to use a loopback address as the source address for LDP peering sessions. Loopback interfaces configured with IP addresses:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $Interfaces | Out-String
            $Status = "Open"
        }
        else {
            $FindingDetails += "The device has no loopback interfaces configured. Configure the device with a loopback interface to use as the source address for LDP peering sessions." | Out-String
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

Function Get-V216608 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216608
        STIG ID    : CISC-RT-000600
        Rule ID    : SV-216608r531085_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000003
        Rule Title : The Cisco MPLS router must be configured to synchronize IGP and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.
        DiscussMD5 : A51F8F66B369CDC74584CED06C2515B2
        CheckMD5   : 1CBA247FC076188D969CDBE6D9260A80
        FixMD5     : C31C033A0EAA4D93FE5C3E142F3BF21A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "The device's OSPF configuration is not configured such that LDP will synchronize with the link-state routing protocol. Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange." | Out-String
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
            $FindingDetails += "The device's ISIS configuration is not configured such that LDP will synchronize with the link-state routing protocol. Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange." | Out-String
            $ShowRunningConfig += "" | Out-String
        }
    }
    else {
        $Status = "Not_Reviewed"
        $FindingDetails += "No OSPF or ISIS configuration found on device. Review the configuration and configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange." | Out-String
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

Function Get-V216609 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216609
        STIG ID    : CISC-RT-000610
        Rule ID    : SV-216609r531085_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000001
        Rule Title : The MPLS router with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.
        DiscussMD5 : 077DB729EBA8D253AE18E1800844A0AC
        CheckMD5   : 2978A49751CBB4211515AD1872103E5B
        FixMD5     : 122C6D95EC63CFB86902B7EEF7D958C3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                    $FindingDetails += "RSVP-TE is enabled on this interface and it does rate limits RSVP messages based on the link speed and input queue size. Verify the rate limit is set according to the link speed and input queue size of adjacent core routers." | Out-String
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

Function Get-V216610 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216610
        STIG ID    : CISC-RT-000620
        Rule ID    : SV-216610r531085_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000004
        Rule Title : The Cisco MPLS router must be configured to have TTL Propagation disabled.
        DiscussMD5 : DE8361C65A485067FE918DB7BC708BE1
        CheckMD5   : 0A13A3BEAAEB61B8550EBB40BC262672
        FixMD5     : 9D59F0B03885FFF54A51026657CF320D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216611 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216611
        STIG ID    : CISC-RT-000630
        Rule ID    : SV-216611r991841_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000005
        Rule Title : The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.
        DiscussMD5 : DC0F4C0B031776948852D1FAAA3328A8
        CheckMD5   : 1F3502B0468C113DD46F512F8DAAA2E6
        FixMD5     : D023BE7CC188BC9DDF91F3B733A098DC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216612 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216612
        STIG ID    : CISC-RT-000640
        Rule ID    : SV-216612r991842_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000006
        Rule Title : The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).
        DiscussMD5 : 09644BAFE76C8F8C9E3877598D74478B
        CheckMD5   : F99CBDB50919D97C39510661E2DA7C51
        FixMD5     : 04227B3126204B5CE3AC34638B9607DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216613 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216613
        STIG ID    : CISC-RT-000650
        Rule ID    : SV-216613r991844_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000007
        Rule Title : The Cisco PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).
        DiscussMD5 : 691CD8FFB8F4E196E4CA5C0E909C9BBE
        CheckMD5   : 820CFA438AF10296045139BC4BB7D3B0
        FixMD5     : F71A458AD1FB624CA8A490720EE556D9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216614 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216614
        STIG ID    : CISC-RT-000660
        Rule ID    : SV-216614r864155_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-NET-000343-RTR-000001
        Rule Title : The Cisco PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.
        DiscussMD5 : 303FC40EBD15DC55D90C7E06C9924903
        CheckMD5   : 6F989BD689C9FC9DFA38A08AAC86945F
        FixMD5     : F5557B1E908C530581C679A26495208B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "The Cisco router is not compliant with this requirement but has been correctly configured to mitigate this requirement from a category 2 to a category 3 severity level." | Out-String
            $FindingDetails += "While this requirement cannot be met for this device, all available remediations have been applied and nothing further can be done." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Whilst a password has been applied for MD5 LDP sessions, 'mlps label protocol ldp' has not been enabled to successfully mitigate this category 2 severity level down to a category 3." | Out-String
            $FindingDetails += "Review the configuration and verify the router is correctly configured to authenticate targeted LDP sessions using MD5." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "Review the configuration and verify the router is correctly configured to authenticate targeted LDP sessions using MD5 to mitigate this to a category 3 from a category 2 severity level." | Out-String
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

Function Get-V216615 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216615
        STIG ID    : CISC-RT-000670
        Rule ID    : SV-216615r991845_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000008
        Rule Title : The Cisco PE router providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate virtual circuit identification (VC ID) for each attachment circuit.
        DiscussMD5 : F04395AB31B5C656ED7D0ED20DE5E04C
        CheckMD5   : 2C289BC62AD9D27133942DFE121E2ECB
        FixMD5     : B78AE649C406ED90855DD4887AEFC6EE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "Interface contains VCID. Review the interface configuration below and verify that the correct and unique VCID has been configured on both routers for the appropriate attachment circuit." | Out-String
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

Function Get-V216616 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216616
        STIG ID    : CISC-RT-000730
        Rule ID    : SV-216616r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000007
        Rule Title : The Cisco PE router must be configured to block any traffic that is destined to IP core infrastructure.
        DiscussMD5 : 0DAA9B297DEBEBE165DF969AD8F2374E
        CheckMD5   : 5B1FC6E7D092038BDB69B4CC2631C274
        FixMD5     : 73CF6AB497BEBFAA6F02736076CE7F65
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $aclPositive = @()
    $aclNegative = @()
    
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig -like "ip access-group * in") {
            $aclPositive += ($Interface.ToString() | Out-String).Trim()
        }
        else {
            $aclNegative += ($Interface | Out-String).Trim()
        }
    }

    If ($aclPositive.count -gt 0) {
        $FindingDetails += "The following interfaces have ingress ACLs applied. Verify that the ingress ACL discards and logs packets destined to the IP core address space." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($config in $aclPositive) {
            $FindingDetails += $config | Out-String
        }
        $FindingDetails += "" | Out-String
    }
    if ($aclNegative.count -gt 0) {
        $FindingDetails += "The following interfaces do not have ingress ACLs applied. Configure an ingress ACL to discard and log packets destined to the IP core address space and apply the ACL inbound to all external or CE-facing interfaces." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($config in $aclNegative) {
            $FindingDetails += $config | Out-String
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

Function Get-V216617 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216617
        STIG ID    : CISC-RT-000740
        Rule ID    : SV-216617r531085_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000008
        Rule Title : The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.
        DiscussMD5 : AFC3F12538B130296907DCA02F0CB5C3
        CheckMD5   : 8A131DAD59B49525D474AACE5A0D59BF
        FixMD5     : 5933EDB5731D98D3B744B3B6332EDD1D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216619 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216619
        STIG ID    : CISC-RT-000760
        Rule ID    : SV-216619r917417_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000113
        Rule Title : The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : 3ED253A8C7E48F6B7785F67864C65759
        CheckMD5   : 78E6078F5F62BA73E9EF102EFDE209E7
        FixMD5     : 62404BC985AE072A914DFD5A796F6828
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    elseif ($PolicyMaps.count -eq 0) {
        $FindingDetails += "No policy map has been configured on this device. Review the device configuration and remediate." | Out-String
        $FindingDetails += "The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
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
                                $FindingDetails += "Review the router configuration below and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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
            $FindingDetails += "Class maps have been found in this device configuration but lack the proper overall 'match ip *' configuration. Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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
        $FindingDetails += "No compliant QoS policies have been identified for this requirement. Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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

Function Get-V216620 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216620
        STIG ID    : CISC-RT-000770
        Rule ID    : SV-216620r917420_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000114
        Rule Title : The Cisco P router must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : 3ED253A8C7E48F6B7785F67864C65759
        CheckMD5   : 708453369C91072D741780B93A89FDCC
        FixMD5     : FABA82D588D95D8C130555E1B3B479B2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    elseif ($PolicyMaps.count -eq 0) {
        $FindingDetails += "No policy map has been configured on this device. Review the device configuration and remediate." | Out-String
        $FindingDetails += "The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
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
                                $FindingDetails += "Review the router configuration below and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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
            $FindingDetails += "Class maps have been found in this device configuration but lack the proper overall 'match ip *' configuration. Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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
        $FindingDetails += "No compliant QoS policies have been identified for this requirement. Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications and applied to all core-layer-facing interfaces." | Out-String
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

Function Get-V216621 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216621
        STIG ID    : CISC-RT-000780
        Rule ID    : SV-216621r531085_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000112
        Rule Title : The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.
        DiscussMD5 : F5E8F727DE225728A2565FF8E60E3B0A
        CheckMD5   : 71B4F77B9CFE1A8EF2E50EA22E56FDFA
        FixMD5     : C20A639D6571BFD7F3ECD66E59F9CAA1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
        $FindingDetails += "" | Out-String
        $Status = "Open"
    }
    elseif ($PolicyMaps.count -eq 0) {
        $FindingDetails += "No policy map has been configured on this device. Review the device configuration and remediate." | Out-String
        $FindingDetails += "The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks." | Out-String
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
                            $FindingDetails += "Review the configuration below and verify that the router is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
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
            $FindingDetails += "Class maps have been found in this device configuration but lack the proper 'match ip *' configuration. Review the router configuration to determine if it is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
            $FindingDetails += "" | Out-String
            $Status = "Open"
        }
    }

    if (!$VerifiedPolicies) {
        $FindingDetails += "No compliant QoS policies have been identified for this requirement. Review the router configuration to determine if it is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks." | Out-String
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

Function Get-V216622 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216622
        STIG ID    : CISC-RT-000790
        Rule ID    : SV-216622r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000003
        Rule Title : The Cisco multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.
        DiscussMD5 : 758EB7F0F92F53781D06A6915DBFA391
        CheckMD5   : 553A544CAF9628BA64D59E5C4827A0AE
        FixMD5     : 5014A4C8150E7B04E00955C8338A20CB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "Disabled interface with multicast routing configured" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += ($Interface.ToString() | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            ELSE {
                # Add enabled interface with PIM to FindingDetails
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the below interface requires multicast routing and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "Enabled interface with multicast routing configured" | Out-String
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

Function Get-V216623 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216623
        STIG ID    : CISC-RT-000800
        Rule ID    : SV-216623r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000004
        Rule Title : The Cisco multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.
        DiscussMD5 : 0C4685D5F08C52AB2BE35627C7874D11
        CheckMD5   : DFE210FEC43D29858CB2FCDDF658545D
        FixMD5     : 52C5081E085239A94ECCFCB1C7005135
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216624 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216624
        STIG ID    : CISC-RT-000810
        Rule ID    : SV-216624r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000005
        Rule Title : The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.
        DiscussMD5 : 62F442656F21941DAB2FF8599EB32308
        CheckMD5   : 2E114877CA374F77FBE95697E06F2189
        FixMD5     : 263F096C52E731EEF4840FF43242D676
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "Interface without multicast boundary configured" | Out-String
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
                    IF (!($ACLConfig -like "deny 239.0.0.0 0.255.255.255*") -or $ACLConfig -like "permit any") {
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

Function Get-V216625 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216625
        STIG ID    : CISC-RT-000820
        Rule ID    : SV-216625r864156_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000120
        Rule Title : The Cisco multicast Rendezvous Point (RP) router must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.
        DiscussMD5 : 1D8226EC842478B7C18033811A1C94E1
        CheckMD5   : 264FD3A68FE8519E72B4027DFE555F73
        FixMD5     : 442AAC7FD5DF0C95F226BA8225D47435
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                        $FindingDetails += "Inbound ACL $ACLName under $Interface is not configured." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                    ELSE {
                        # Add ACL entries to FindingDetails
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Verify that ACL $ACLName under $Interface restricts MSDP peerings to only known sources and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216626 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216626
        STIG ID    : CISC-RT-000830
        Rule ID    : SV-216626r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000013
        Rule Title : The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.
        DiscussMD5 : AFBA9F976485DD6E345D358C87F4D9A7
        CheckMD5   : 622F2F6A3DEE90E3F9BC1DE3BAB5A296
        FixMD5     : 9429F8B6E90B95F46E2B00F9F8D79BF2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "Verify if the ACL $ACLName is filtering PIM register messages received from a multicast DR for any undesirable multicast groups and sources and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216627 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216627
        STIG ID    : CISC-RT-000840
        Rule ID    : SV-216627r531085_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000014
        Rule Title : The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.
        DiscussMD5 : 886093DB12B8C178DBD7B6AB20443EE9
        CheckMD5   : 740E1BC80D4CAD040B80C49DDDB90788
        FixMD5     : E4B6AEB8F7B64D70B3ECC77B984F1F26
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                $FindingDetails += "ACL $ACLName used to filter PIM join messages for any undesirable multicast groups is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            ELSE {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLStandard.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if the ACL $ACLName is filtering PIM join messages received from a DR for any undesirable multicast groups and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216628 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216628
        STIG ID    : CISC-RT-000850
        Rule ID    : SV-216628r856196_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000121
        Rule Title : The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.
        DiscussMD5 : 3939FE094EF11D9C37F634F47CAE8EB0
        CheckMD5   : B61F38AB3B1E2CFDDB08B244AA6DADDE
        FixMD5     : 6383C018C3AAF2992276484019C46F50
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $FindingDetails += "'ip pim register-rate-limit' is not configured on this device." | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += ($PimRate[0] | Out-String).Trim()
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "PIM RP is not configured on this device." | Out-String
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

Function Get-V216629 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216629
        STIG ID    : CISC-RT-000860
        Rule ID    : SV-216629r864157_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000114
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.
        DiscussMD5 : BC62F6A539A6B3CDB8D915307F15609E
        CheckMD5   : 1015B26CFB5A13461DBE6A2490838C3F
        FixMD5     : 089BB29BC4FB5249AC30FD6642678BD9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216630 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216630
        STIG ID    : CISC-RT-000870
        Rule ID    : SV-216630r864158_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000115
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.
        DiscussMD5 : BC62F6A539A6B3CDB8D915307F15609E
        CheckMD5   : B512D97CF551391BF75E9F0A39704450
        FixMD5     : 1CE93D40EF8D2B6B8C8BB9AF0BCD23DC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216631 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216631
        STIG ID    : CISC-RT-000880
        Rule ID    : SV-216631r856199_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000122
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
        DiscussMD5 : 34D08C377A292763DA68ECD672B8219E
        CheckMD5   : 6151D0A7F4462E605886D9A7A138E810
        FixMD5     : 3AA2F5A1362E96DCD469094D21D6DF32
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
            $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
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

Function Get-V216632 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216632
        STIG ID    : CISC-RT-000890
        Rule ID    : SV-216632r945856_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000123
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to set the shortest-path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.
        DiscussMD5 : 55812D10AD50D0E624DA5A8FBDC8289E
        CheckMD5   : 284000020D1F2C53A806A0F7C701C0F5
        FixMD5     : 619DDCE109232ED6C69F2DDD1385983D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216633 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216633
        STIG ID    : CISC-RT-000900
        Rule ID    : SV-216633r856201_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000116
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.
        DiscussMD5 : EBA7B132D7963B2C3BF6422BE6A51EDC
        CheckMD5   : 7706B3E557E49526B9908D32EB47DA2F
        FixMD5     : EB015C448CCA71AB4E5C0881175AF94F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                    $FindingDetails += "Inbound ACL $ACLName under $Interface is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Verify that the ACL $ACLName under $Interface restricts MSDP peerings to only known sources and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216634 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216634
        STIG ID    : CISC-RT-000910
        Rule ID    : SV-216634r856202_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-NET-000343-RTR-000002
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.
        DiscussMD5 : 17BABA06299122724631184195E233B2
        CheckMD5   : 2C4FE82A857CBE97A216A5AD1C25D1AD
        FixMD5     : D2DDC32A17C606F4D1DF58605E4F8BD3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216635 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216635
        STIG ID    : CISC-RT-000920
        Rule ID    : SV-216635r1050881_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000007
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.
        DiscussMD5 : 0C7619950B8DEF4B21DB5EEA5726FA86
        CheckMD5   : 098E9D269E9BE46C3C4492CA5A13AD1E
        FixMD5     : 89E641A158DAF32EFF35B63A90A42A80
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                    $FindingDetails += "ACL $ACLName required to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    $ACLConfig = Get-Section $ShowRunningConfig $ACL.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "MSDP Peer with ACL $ACLName configured:" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += ($Item.ToString() | Out-String).Trim().Split([char[]]"") | Select-Object -First 4
                    $FindingDetails += "" | Out-String
                    IF ($ACLConfig | Select-String -Pattern "permit ip any any") {
                        $Exception = $True
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "permit ip any any configured on ACL $ACLName." | Out-String
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

Function Get-V216636 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216636
        STIG ID    : CISC-RT-000930
        Rule ID    : SV-216636r531085_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000008
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.
        DiscussMD5 : 4941DAD27354E7533595B49B65260840
        CheckMD5   : 85EC88C247A1B4A57EAF0EBCB80D4F4E
        FixMD5     : C68F72730A757D2DEDE65585A7A08D24
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                    $FindingDetails += "ACL $ACLName used to filter source-active multicast advertisements to external MSDP peers is not configured." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                ELSE {
                    # Add ACL entries to FindingDetails
                    $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Review ACL $ACLName and verify that MSDP source-active messages being sent to MSDP peers do not leak advertisements that are local and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216637 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216637
        STIG ID    : CISC-RT-000940
        Rule ID    : SV-216637r531085_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000009
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on a per-peer basis.
        DiscussMD5 : 3EBC6EDA406C0475A1BF74355C6C4A53
        CheckMD5   : C993E9A8FB776A3200FE8F271D3D491B
        FixMD5     : A7E06B00AF38A54BE1C1AEB5474135BC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216638 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216638
        STIG ID    : CISC-RT-000950
        Rule ID    : SV-216638r991846_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000011
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to use a loopback address as the source address when originating MSDP traffic.
        DiscussMD5 : 9DACCE773BC26EE8D2E88625C7982134
        CheckMD5   : C0C724B2CD9FBC15C98DFC441D156B99
        FixMD5     : ECA71F8967751C248391E8D0D7033F4A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216989 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216989
        STIG ID    : CISC-RT-000310
        Rule ID    : SV-216989r945858_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-NET-000205-RTR-000014
        Rule Title : The Cisco perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).
        DiscussMD5 : B9595D2DAE58AB9CE7582BBAE4615A92
        CheckMD5   : 61CC97D7EF0C7D0CB184569521FD9100
        FixMD5     : 42BA633C77AE519859C89E83A8B5033F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "The following interfaces have uRPF configured to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field." | Out-String
        $FindingDetails += "-------------------- uRPF Compliant Interfaces --------------------" | Out-String
        ForEach ($int in $urpfInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }

    if ($VerifiedACLInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces have an in ACL configured. Verify if the interface is internal and if so, that the associated ACL restricts the router from accepting outbound IP packets that contain an illegitimate address in the source address field." | Out-String
        $FindingDetails += "-------------------- Interfaces with Egress ACLs Applied --------------------" | Out-String
        ForEach ($int in $VerifiedACLInterfaces) {
            $FindingDetails += $int.ToString() | Out-String
        }
        $FindingDetails += "" | Out-String
    }

    if ($UnverifiedInterfaces.count -gt 0) {
        $FindingDetails += "The following interfaces have no 'ip access-group * in' ACLs configured. Review the device configuration and verify that an  egress ACL or uRPF is configured on any internal interfaces to restrict the router from accepting any outbound IP packet that contains an illegitimate address in the source field." | Out-String
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

Function Get-V216990 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216990
        STIG ID    : CISC-RT-000350
        Rule ID    : SV-216990r945859_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000205-RTR-000015
        Rule Title : The Cisco perimeter router must be configured to block all packets with any IP options.
        DiscussMD5 : 580BCA4BBB7649843D17285D715164E5
        CheckMD5   : 942A806BD92C0BC63B5327FC6FEDF7D4
        FixMD5     : D5A423FC41C5D834518EFC7D5C179ADF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ConfigActive = $False
    $ACLList = @()
    $UncompliantInterfaces = @()
    $OpenFinding = $False

    #Check all access lists for configuration and compile list for those with configuration present
    ForEach ($AccessList in $AccessLists) {
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        $null = $AccessList -match "ip access-list extended (?<content>.*)"    
        IF (($AccessListConfig -like "deny ip any any option any-options")) {
            IF(($ConfigActive -eq $True)) {
                $ACLList += ($matches['content'].ToString() | Out-String).Trim()
                $FindingDetails += ($matches['content'].ToString() | Out-String)
            }
            Else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "These ACLs are configured to drop all packets with IP options:" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += ($matches['content'].ToString() | Out-String)
            $ACLList += ($matches['content'].ToString() | Out-String).Trim()
            $ConfigActive = $True
            }
        }
    }
    $FindingDetails += "" | Out-String


    IF ($ConfigActive -eq $False) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No ACLs are currently configured on this device to drop all packets with IP options. Review device configuration and verify an ingress ACL is applied to all external or CE-facing interfaces" | Out-String
        $FindingDetails += "" | Out-String
        $Status = 'Open'
    }
    else {
        # Check each interface for the configuration or an ACL
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $aclPresent = $False
            ForEach ($acl in $ACLList) {
                if ($InterfaceConfig -like "ip access-group $acl in"){
                    $aclPresent = $True
                    $FindingDetails += "IP options disabled via $acl on interface: $Interface." | Out-String
                    $FindingDetails += "" | Out-String
                    break
                }
            }
            # Check whether required ACL was applied to interface
            if ($aclPresent -eq $False) {
                $OpenFinding = $True
                $UncompliantInterfaces += $Interface.ToString()
            }
        }
    }

    IF ($OpenFinding) {
        $FindingDetails += "There are currently ACLs configured on the device to block all IP options but they are not applied on the following interfaces. Ensure an ingress ACL with IP options disabled is applied to all external or CE-facing interfaces." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        foreach ($int in $UncompliantInterfaces) {
            $FindingDetails += $int | Out-String
            
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

Function Get-V216991 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216991
        STIG ID    : CISC-RT-000470
        Rule ID    : SV-216991r856208_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000124
        Rule Title : The Cisco BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).
        DiscussMD5 : 017D1AB32C3CBD0DB696871C1A2408F6
        CheckMD5   : 437E73AE03C70F3516CFC902487132C8
        FixMD5     : 30D9975034BAFE569CB9359E772F1EC3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                    IF (!($NewBgpConfig | Select-String -Pattern "neighbor $Entry ttl-security hops 1$")) {
                        # Add non-compliant BGP Neighbors to FindingDetails
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the device configuration to verify that all external BGP neighbors and Peer Groups have TTL Security configured." | Out-String
                        $FindingDetails += "BGP neighbor or Peer Group with no TTL Security:" | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
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
                    IF (!($NewBgpVrfConfig | Select-String -Pattern "neighbor $Entry ttl-security hops 1$")) {
                        # Add non-compliant BGP VRF Neighbors to FindingDetails
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Review the device configuration to verify that all external BGP neighbors and Peer Groups in VRFs have TTL Security configured." | Out-String
                        $FindingDetails += "BGP neighbor or Peer Group in VRF $Vrf with no TTL Security:" | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += ("neighbor $Entry" | Out-String).Trim()
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

Function Get-V216992 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216992
        STIG ID    : CISC-RT-000480
        Rule ID    : SV-216992r945862_rule
        CCI ID     : CCI-002205
        Rule Name  : SRG-NET-000230-RTR-000002
        Rule Title : The Cisco BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.
        DiscussMD5 : 61A61BCDF3CC1AF638D5627970244406
        CheckMD5   : 2D7FCF1C295E5343C019E4CDC8B52107
        FixMD5     : 7FB4141EFC6A42F116CAA3A7416F26DA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V216993 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216993
        STIG ID    : CISC-RT-000750
        Rule ID    : SV-216993r945860_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000205-RTR-000016
        Rule Title : The Cisco PE router must be configured to drop all packets with any IP options.
        DiscussMD5 : AF758A1A25F785C9D837E4606B47A8B6
        CheckMD5   : F06939A5D15861314A2A608573622E71
        FixMD5     : 9CCC917A4B656A30B5EDE6A6FB39819A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    
    IF ($ShowRunningConfig -contains "ip options drop") {
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify all packets with IP options are dropped." | Out-String
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

Function Get-V229030 {
    <#
    .DESCRIPTION
        Vuln ID    : V-229030
        STIG ID    : CISC-RT-000235
        Rule ID    : SV-229030r878127_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000100
        Rule Title : The Cisco router must be configured to have Cisco Express Forwarding enabled.
        DiscussMD5 : A1D0C6AD10599F8CA9AE95313508FB3C
        CheckMD5   : 52F8F5525C31AF71C6BAB7F4F837F315
        FixMD5     : 0985BF68A2EE61C3B2FFCCDFE4124BFC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    IF ($ShowRunningConfig -contains "ip cef" -and $ShowRunningConfig -contains "ipv6 cef") {
        $FindingDetails += "CEF is enabled for both IPv4 and IPv6." | Out-String
        $FindingDetails += ""
        $Status = "NotAFinding"
    }
    Elseif ($ShowRunningConfig -contains "ip cef" -and $ShowRunningConfig -notcontains "ipv6 cef") {
        $Status = "Open" | Out-String
        $FindingDetails += "CEF is enabled for IPv4 but not IPv6."
        $FindingDetails += ""
    }
    Elseif ($ShowRunningConfig -notcontains "ip cef" -and $ShowRunningConfig -contains "ipv6 cef") {
        $Status = "Open" | Out-String
        $FindingDetails += "CEF is enabled for IPv6 but not IPv4."
        $FindingDetails += ""
    }
    Else {
        $FindingDetails += "Review the switch configuration and verify Cisco Express Forwarding is enabled for both IPv4 and IPv6." | Out-String
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

Function Get-V230038 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230038
        STIG ID    : CISC-RT-000236
        Rule ID    : SV-230038r531386_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000012
        Rule Title : The Cisco router must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.
        DiscussMD5 : 58951D134DA33AFAB85953208EA404A6
        CheckMD5   : 7ADEB7B4E3D9123EC62E341328677709
        FixMD5     : 945587ACD4773B3B4ABE1A6AF37DC171
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V230041 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230041
        STIG ID    : CISC-RT-000237
        Rule ID    : SV-230041r532998_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000013
        Rule Title : The Cisco router must not be configured to use IPv6 Site Local Unicast addresses.
        DiscussMD5 : 5905FE5CC4A0A6775A24A1662EC96B2A
        CheckMD5   : B4CD914D70E318420F481682924A89CF
        FixMD5     : 09258164C3BE526391F7F061323EF3ED
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Ipv6Int = @()
    $Ipv4Int = @()
    $OpenFinding = $False

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF ($InterfaceConfig -like "ipv6 address*") {
            # Add ipv6 interface to inventory
            $Ipv6Int += ($Interface | Out-String).Trim()
            $Ipv6Int += ($InterfaceConfig | Out-String).Trim()
        }
        Else {
            # Add ipv4 interface to inventory
            $Ipv4Int += ($Interface | Out-String).Trim()
            $Ipv4Int += ($InterfaceConfig | Out-String).Trim()
        }
    }
    
    IF ($Ipv6Int) {
        $Ipv6Interfaces = $Ipv6Int | Select-String -Pattern "^interface"
        ForEach ($Interface in $Ipv6Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -like "*[fFeEcC]*0::[0-9A-Fa-f]*/10") {
                $OpenFinding = $True
                $FindingDetails += "Review the device configuration to verify that FEC0::/10 IPv6 addresses are not defined." | Out-String
                $FindingDetails += "Interfaces with FEC0::/10 IPv6 addresses:" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $Interface.ToString() | Out-String   
                $FindingDetails += "" | Out-String
            }
            Else {
                $FindingDetails += "Compliant IPv6 Interfaces:" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += $Interface.ToString() | Out-String
                $FindingDetails += "" | Out-String
               }
            }
        }
    ELSE {
            $FindingDetails += "There are no interfaces configured with IPv6 on this device." | Out-String
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

Function Get-V230044 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230044
        STIG ID    : CISC-RT-000391
        Rule ID    : SV-230044r533005_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000014
        Rule Title : The Cisco perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.
        DiscussMD5 : 38D1C8FFBC0B7B3BB01BC9B0E6A2D5A1
        CheckMD5   : AD27B90E97037E6DBEF8AC3F9749AB0F
        FixMD5     : 697936D913C8B682DBF2BF42E9570247
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

Function Get-V230047 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230047
        STIG ID    : CISC-RT-000392
        Rule ID    : SV-230047r950991_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000200
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 undetermined transport packets.
        DiscussMD5 : 6F5EC21E86DCCDD4BDAC9197F76B8722
        CheckMD5   : D5B374A09715CC2027DBAF10A8D4E74F
        FixMD5     : 23E90FE6320B4A3F911C81F1AE7201DF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Review the router interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
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

Function Get-V230050 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230050
        STIG ID    : CISC-RT-000393
        Rule ID    : SV-230050r856665_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000201
        Rule Title : The Cisco perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3–255.
        DiscussMD5 : 023F228796EF907D709583F948A41B48
        CheckMD5   : 981BAA93A7BD31D11993FC152FA6A0E5
        FixMD5     : 42996B371643B4E45534B8DE0DE7DF4A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
                        $FindingDetails += "ACL: '$AccessListName' assigned does not permit any router header types but also does not explicitly block all unauthorized router header types. Verify that the interface contains an ACL that drops IPv6 packets with a Routing Header type 0, 1, or 3-255." | Out-String
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

Function Get-V230145 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230145
        STIG ID    : CISC-RT-000394
        Rule ID    : SV-230145r856667_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000202
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values.
        DiscussMD5 : 7C33E23B97008FAECA65F0592154BD8A
        CheckMD5   : 8DC07086E2E6CEC26C85F25FBFF52822
        FixMD5     : 16B80684BAA75A2F210D95D98D624062
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Review the router configuration to determine if it is compliant with this requirement." | Out-String
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

Function Get-V230149 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230149
        STIG ID    : CISC-RT-000395
        Rule ID    : SV-230149r856669_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000203
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing a Destination Option header with invalid option type values.
        DiscussMD5 : 78F792CD8713130D6E190E2BAD4D9105
        CheckMD5   : A2E44D58994BB00F1B8F88C04A39EF6B
        FixMD5     : 78A55DFF93EEF9C9091D7A793209CB90
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "There are IPv6 interfaces but no ACLs found on the device that drop IPv6 packets containing a Destination Option header with option type values of 0x05 (Router Alert) or 0xC2 (Jumbo Payload)." | Out-String
        $FindingDetails += "Review the router interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
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
            $FindingDetails += "The following IPv6 interfaces are not configured with a compliant ACL for this requirement. Verify that an inbound IPv6 ACL that drops IPv6 packets containing a Destination Option header with option type values of 0x05 (Router Alert) or 0xC2 (Jumbo Payload) has been configured for all external IPv6 interfaces." | Out-String
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

Function Get-V230152 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230152
        STIG ID    : CISC-RT-000396
        Rule ID    : SV-230152r856671_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000204
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing an extension header with the Endpoint Identification option.
        DiscussMD5 : E5C7A9AE4D14F4BD2F188D81435C985F
        CheckMD5   : 4795C2B9EDCE4CD1EA54057B782FF83E
        FixMD5     : B2C377E12AB16BCA8EE83554AE7DBADA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Review the router interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
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

Function Get-V230155 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230155
        STIG ID    : CISC-RT-000397
        Rule ID    : SV-230155r856673_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000205
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing the NSAP address option within Destination Option header.
        DiscussMD5 : D9C7467C245639452E2AB647D504F034
        CheckMD5   : 358FD008BE7665A22041297BF6FF501C
        FixMD5     : ACDDD966A1552318087EBD1110ED560E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Review the router interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
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

Function Get-V230158 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230158
        STIG ID    : CISC-RT-000398
        Rule ID    : SV-230158r856675_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000206
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.
        DiscussMD5 : 2C86126E62F212E0E1D0BBED19FD8C89
        CheckMD5   : ABE0D9FB43DE34C69717E8EA2549FE41
        FixMD5     : 76EDE7502F828EB3E20948D55ED8EC2E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Review the router interface and ACL configurations to determine if it is compliant with this requirement." | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBpaO6CrQJUH8In
# gn0jYwhcO42zwntABPNrPBv1YwNAQKCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCC140ajSbTY8KGTM348HBOKAgRQ6hwWH0eytzXcUKm2ezANBgkqhkiG9w0BAQEF
# AASCAQALpIVP3Zmjf1ZLoKjVmpdLJ3adQPVrN9npzp9iTFk9k41lydRPp7etkY3c
# jUny5l50fehVIDKRnESjb+jrNuVH3JozxIthz+VtZ3fed8vrqqH/YkTm9O3f8aZV
# B/Cz/22UIPNjFFRXuZWrmeoPdQHh3nd4fFjaSbCKIKxTBt46dzpPzihz7xc9SmbU
# qyFm2934JPjaVDYCQezcicmWrdnxdyEipPg5Frfy+IdByjWwhgyf02ijZ8k2g3vm
# fdv7O1h+eRFPr/NrjUhtqWsxjqVWsyFJe8riuUvZpDTbrn2lM1jtwrqUnpfTWvAY
# j8FxhNfE19i1TDJ1BSYLM/b6EyinoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTYzMVowLwYJKoZIhvcNAQkEMSIEINAXsKjevf8ECixYG7Du3cPCLuR/
# XuBlJPtwbnsfE/cuMA0GCSqGSIb3DQEBAQUABIICAB/+kp+gCugpYBx9FzR5OKeO
# eCA3yMc5sQzsHP4dya1mpbMxgyZyloAu02LENjuVgh7MEDNvVggDIDzjmvoD+Q92
# SVJhHVMAwgrESsbMCPDF6JuPCsnc4kgo8L4EaB3qna0pWzDDAC8krkoMIMyNJjlU
# rbb7p4+b93App7zU3Eyx99wabuqgL//rfioOQq1Wknsupc1nOqT9ZUHI/ZtR1tvr
# b5yzHD+6kgtsRy7u/4vN138B/lltilOg6UUlgP7TUPjBOCFmG6gckLeroTt6jsWt
# 1fZeIwnBN/rkiDWR0B8Fb3svsJm0RAQGKvsJ43Pp1kMV0mSvLScmKVvCWJ+TkW27
# Ta+VsssLD2DgMzlQ6zFltK8+8GcYcrfsB/DasU+kSoTLivjoAsPxHUsTSHi7p2gg
# q3kpQyVc4gFJKzfRew23m7nceCTzORLkIWiq2h27bult1y4ImtLp2a2qtemnudea
# s50vIpxJrpfdV2vp38Gd8QQevrSr4sEaPKs3BLSjE9BUJpXbUsPRu2+AiWXDHbjW
# S4R0WSXwwGy6jNPquPbVZQe6WxcHeZgnFKE9CFi1kGt2lbo4Yigye8pH3b6C/5We
# Z+SlAWw1ZhhqxFcAEZKztJEN1/jUHSLmUPRSBHHLa/62uthT+wcHVC8E8p7oQDzH
# 2r1jd4ta6md/O9Vkh9aZ
# SIG # End signature block
