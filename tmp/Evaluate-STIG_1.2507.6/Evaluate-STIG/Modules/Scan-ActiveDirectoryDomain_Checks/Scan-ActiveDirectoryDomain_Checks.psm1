##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Active Directory Domain
# Version:  V3R5
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Format-TrustObject {
    param($TrustObj)

    $AttsToDoc = @("Target", "Type", "Direction", "DisallowTransivity", "ForestTransitive", "SelectiveAuthentication", "SIDFilteringQuarantined", "SIDFilteringForestAware", "TrustAttributes")
    $FormattedObj = [ordered]@{}
    ForEach ($Att in $AttsToDoc) {
        Switch ($Att) {
            "Type" {
                If ($TrustObj.TrustType -eq "Uplevel") {
                    If ($TrustObj.TrustAttributes -band 4) {
                        $FormattedObj.Add($_, "External")
                    }
                    ElseIf ($TrustObj.TrustAttributes -band 8) {
                        $FormattedObj.Add($_, "Forest")
                    }
                    Else {
                        $FormattedObj.Add($_, "Unknown")
                    }
                }
                ElseIf ($TrustObj.TrustType -eq "MIT") {
                    $FormattedObj.Add($_, "Realm")
                }
                Else {
                    $FormattedObj.Add($_, $TrustObj.TrustType)
                }
            }
            {$_ -in @("SIDFilteringQuarantined", "SIDFilteringForestAware")} {
                If ($FormattedObj.Type -eq "External") {
                    If ($_ -eq "SIDFilteringQuarantined") {
                        $FormattedObj.Add($_, $TrustObj.$_)
                    }
                }
                ElseIf ($FormattedObj.Type -eq "Forest") {
                    If ($_ -eq "SIDFilteringForestAware") {
                        $FormattedObj.Add($_, $TrustObj.$_)
                    }
                }
                Else {
                    $FormattedObj.Add($_, $TrustObj.$_)
                }
            }
            "TrustAttributes" {
                $FormattedObj.Add($_, $(((Get-TrustAttributes).Keys | Where-Object {$_ -band $TrustObj.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}) -join ","))
            }
            DEFAULT {
                $FormattedObj.Add($_, $TrustObj.$_)
            }
        }
    }

    Return $FormattedObj
}

Function Get-TrustAttributes {
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
    $TrustAttributes = @{
        1    = "TANT" # (TRUST_ATTRIBUTE_NON_TRANSITIVE)
        2    = "TAUO" # (TRUST_ATTRIBUTE_UPLEVEL_ONLY)
        4    = "TAQD" # (TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)
        8    = "TAFT" # (TRUST_ATTRIBUTE_FOREST_TRANSITIVE)
        16   = "TACO" # (TRUST_ATTRIBUTE_CROSS_ORGANIZATION)
        32   = "TAWF" # (TRUST_ATTRIBUTE_WITHIN_FOREST)
        64   = "TATE" # (TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL)
        128  = "TARC" # (TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION)
        512  = "TANC" # (TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION)
        1024 = "TAPT" # (TRUST_ATTRIBUTE_PIM_TRUST)
        2048 = "TAEC" # (TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION)
        4096 = "TDAV" # (TRUST_ATTRIBUTE_DISABLE_AUTH_TARGET_VALIDATION)
    }
    Return $TrustAttributes
}

Function Get-V243466 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243466
        STIG ID    : AD.0001
        Rule ID    : SV-243466r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership to the Enterprise Admins group must be restricted to accounts used only to manage the Active Directory Forest.
        DiscussMD5 : C1602A3A446F4347D9CAB5E7F68F0119
        CheckMD5   : D139919DA9CEE53C02D93BFEB5303BAF
        FixMD5     : E05BCC2A7340F3423872EB89DCF1A1D8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GroupsToCheck = @("Enterprise Admins")
    $OtherAdminGroups = @("Domain Admins", "Schema Admins", "Administrators")
    $Compliant = $true
    $NeedsReview = $false

    ForEach ($Group in $GroupsToCheck) {
        Try {
            If (Get-ADGroup -Identity $Group) {
                $Exists = $true
            }
        }
        Catch {
            $Exists = $false
        }
        If ($Exists) {
            $ReturnedUsers = Get-MembersOfADGroup -Identity $Group -Recursive | Sort-Object Name -Unique
            If (($ReturnedUsers | Measure-Object).Count -eq 0) {
                $Status = "NotAFinding"
                $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
            }
            Else {
                $FindingDetails += "Members of '$($Group)'" | Out-String
                $FindingDetails += "=========================" | Out-String
                ForEach ($User in $ReturnedUsers) {
                    $UserFinding = $false
                    $OtherGroups = @()
                    ForEach ($DN in (Get-ADObject -Identity $User.objectGUID -Properties MemberOf).MemberOf) {
                        $MemberOfName = (Get-ADObject -Identity $DN).Name
                        If ($MemberOfName -in $OtherAdminGroups) {
                            $Compliant = $false
                            $userFinding = $true
                            $OtherGroups += "$MemberOfName [FINDING]"
                        }
                        ElseIf ($MemberOfName -ne $Group) {
                            $NeedsReview = $true
                            $OtherGroups += "$MemberOfName"
                        }
                    }
                    If ($UserFinding) {
                        $FindingDetails += "Name:`t`t`t`t$($User.name) [FINDING]" | Out-String
                    }
                    Else {
                        $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                    }
                    $FindingDetails += "objectClass:`t`t`t$($User.objectClass)" | Out-String
                    $FindingDetails += "objectSID:`t`t`t$($User.objectSID.Value)" | Out-String
                    $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                    $FindingDetails += "OtherMemberOf:" | Out-String
                    ForEach ($Item in $OtherGroups) {
                        $FindingDetails += $Item | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true -and -Not($NeedsReview)) {
                    $Status = "NotAFinding"
                }
                ElseIf ($Compliant -eq $false) {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "The group '$($Group)' does not exist within this domain." | Out-String
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

Function Get-V243467 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243467
        STIG ID    : AD.0002
        Rule ID    : SV-243467r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership to the Domain Admins group must be restricted to accounts used only to manage the Active Directory domain and domain controllers.
        DiscussMD5 : A4A34538E8735E3BB2ADB13396CC56C5
        CheckMD5   : E31EEFE9FA76CE0E4DD00658BD0F8555
        FixMD5     : 0D935DFACEA89D932BEA45D2DEC8D08E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GroupsToCheck = @("Domain Admins")
    $OtherAdminGroups = @("Enterprise Admins", "Schema Admins", "Administrators")
    $Compliant = $true
    $NeedsReview = $false

    ForEach ($Group in $GroupsToCheck) {
        Try {
            If (Get-ADGroup -Identity $Group) {
                $Exists = $true
            }
        }
        Catch {
            $Exists = $false
        }
        If ($Exists) {
            $ReturnedUsers = Get-MembersOfADGroup -Identity $Group -Recursive | Sort-Object Name -Unique
            If (($ReturnedUsers | Measure-Object).Count -eq 0) {
                $Status = "NotAFinding"
                $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
            }
            Else {
                $FindingDetails += "Members of '$($Group)'" | Out-String
                $FindingDetails += "=========================" | Out-String
                ForEach ($User in $ReturnedUsers) {
                    $UserFinding = $false
                    $OtherGroups = @()
                    ForEach ($DN in (Get-ADObject -Identity $User.objectGUID -Properties MemberOf).MemberOf) {
                        $MemberOfName = (Get-ADObject -Identity $DN).Name
                        If ($MemberOfName -in $OtherAdminGroups) {
                            $Compliant = $false
                            $userFinding = $true
                            $OtherGroups += "$MemberOfName [FINDING]"
                        }
                        ElseIf ($MemberOfName -ne $Group) {
                            $NeedsReview = $true
                            $OtherGroups += "$MemberOfName"
                        }
                    }
                    If ($UserFinding) {
                        $FindingDetails += "Name:`t`t`t`t$($User.name) [FINDING]" | Out-String
                    }
                    Else {
                        $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                    }
                    $FindingDetails += "objectClass:`t`t`t$($User.objectClass)" | Out-String
                    $FindingDetails += "objectSID:`t`t`t$($User.objectSID.Value)" | Out-String
                    $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                    $FindingDetails += "OtherMemberOf:" | Out-String
                    ForEach ($Item in $OtherGroups) {
                        $FindingDetails += $Item | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true -and -Not($NeedsReview)) {
                    $Status = "NotAFinding"
                }
                ElseIf ($Compliant -eq $false) {
                    $Status = "Open"
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "The group '$($Group)' does not exist within this domain." | Out-String
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

Function Get-V243473 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243473
        STIG ID    : AD.0013
        Rule ID    : SV-243473r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Separate domain accounts must be used to manage public facing servers from any domain accounts used to manage internal servers.
        DiscussMD5 : AB1BEBD355D05A18AC49C41A1E7612B5
        CheckMD5   : 12FBCBF043E8A184C9FC7306506C3250
        FixMD5     : 83FE7BDC862FD9A6C4784C517C912A36
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Groups = @("Administrators")

    ForEach ($Group in $Groups) {
        $ReturnedObjects = Get-GroupMembership -Group $Group
        If (($ReturnedObjects | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
        }
        Else {
            $FindingDetails += "Members of '$($Group)'" | Out-String
            $FindingDetails += "=========================" | Out-String
            ForEach ($Object in $ReturnedObjects) {
                $FindingDetails += "Name:`t`t$($Object.Name)" | Out-String
                $FindingDetails += "objectClass:`t$($Object.objectClass)" | Out-String
                $FindingDetails += "objectSID:`t$($Object.objectSID.Value)" | Out-String
                $FindingDetails += "" | Out-String
            }
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

Function Get-V243476 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243476
        STIG ID    : AD.0016
        Rule ID    : SV-243476r1026173_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000076
        Rule Title : All accounts, privileged and unprivileged, that require smart cards must have the underlying NT hash rotated at least every 60 days.
        DiscussMD5 : 99FFF6EC74B1BD3FCAAB2786CF903752
        CheckMD5   : 4649F9C55B3640B78D1BCD211C6D83FC
        FixMD5     : 8F44587DB6D777AC97B94B15B1D09EFB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Domain = Get-ADDomain
    $RollingNTLMSecrets = $Domain.PublicKeyRequiredPasswordRolling

    $FindingDetails += "Domain Level:`t$($Domain.DomainMode)" | Out-String
    $FindingDetails += "" | Out-String
    If ($Domain.DomainMode -in @("Windows2016Domain")) {
        $FindingDetails += "Rolling of expiring NTLM Secrets:`t$($RollingNTLMSecrets)" | Out-String
        If ($RollingNTLMSecrets -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "Domain functional level does not support rolling of expiring NTLM secrets.  Verify the organization rotates the NT hash for smart card-enforced accounts every 60 days." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V243477 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243477
        STIG ID    : AD.0017
        Rule ID    : SV-243477r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : User accounts with domain level administrative privileges must be members of the Protected Users group in domains with a domain functional level of Windows 2012 R2 or higher.
        DiscussMD5 : 1B7D39C4EA26A2DBBEBF9F0E5356F9BD
        CheckMD5   : 60D39FC7E59B7E29250B837A836B1DBB
        FixMD5     : 1F3E56D2148D90A349381D9F8CDDFBC8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Domain = Get-ADDomain
    $AcceptedDomainLevels = @("Windows2012R2Domain", "Windows2016Domain")
    $Groups = @("Enterprise Admins", "Domain Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators")

    If ($Domain.DomainMode -in $AcceptedDomainLevels) {
        $GroupMembers = @()
        $UserMembership = New-Object System.Collections.Generic.List[System.Object]
        $MissingUsers = New-Object System.Collections.Generic.List[System.Object]

        ForEach ($Group in $Groups) {
            $GroupUsers = Get-MembersOfADGroup -Identity $Group -Recursive | Where-Object {($_.objectSID.Value -match $Domain.DomainSID) -and ($_.objectClass -eq "user") -and ($_.Name -notmatch '\$$')}
            $GroupMembers += $GroupUsers
            ForEach ($User in $GroupUsers) {
                $Obj = [PSCustomObject]@{
                    objectSID = $User.objectSID.Value
                    MemberOf  = $Group
                }
                $UserMembership.Add($Obj)
            }
        }
        $GroupMembers = $GroupMembers | Sort-Object Name -Unique

        $ProtectedUsers = Get-MembersOfADGroup -Identity "Protected Users" -Recursive | Where-Object objectClass -EQ "user" | Sort-Object Name -Unique
        ForEach ($Member in $GroupMembers) {
            If ($Member.objectSID.Value -notin $ProtectedUsers.objectSID.Value) {
                $Obj = [PSCustomObject]@{
                    Name              = $Member.name
                    objectClass       = $Member.objectClass
                    objectSID         = $Member.objectSID.Value
                    DistinguishedName = $Member.distinguishedName
                    MemberOf          = (($UserMembership | Where-Object objectSID -EQ $Member.objectSID.Value).MemberOf | Select-Object -Unique | Sort-Object) -join ", "
                }
                $MissingUsers.Add($Obj)
            }
        }

        If (($MissingUsers | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No accounts were missing from the 'Protected Users' group" | Out-String
        }
        Else {
            $FindingDetails += "Accounts are missing from 'Protected Users'.  Only service accounts and one (1) user account with domain level administrative privileges may be excluded.  Please confirm for compliance." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Users Missing From 'Protected Users' Group" | Out-String
            $FindingDetails += "============================================" | Out-String
            ForEach ($User in $MissingUsers) {
                $FindingDetails += "Name:`t`t`t`t$($User.Name)" | Out-String
                $FindingDetails += "objectClass:`t`t`t$($User.ObjectClass)" | Out-String
                $FindingDetails += "objectSID:`t`t`t$($User.objectSID)" | Out-String
                $FindingDetails += "DistinguishedName:`t$($User.DistinguishedName)" | Out-String
                $FindingDetails += "MemberOf:`t`t`t$($User.MemberOf)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "Domain Level: $($Domain.DomainMode)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "The domain functional level is not Windows 2012 R2 or higher, so this check is Not Applicable" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V243478 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243478
        STIG ID    : AD.0018
        Rule ID    : SV-243478r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Domain-joined systems (excluding domain controllers) must not be configured for unconstrained delegation.
        DiscussMD5 : 988D2F280B241C5B8DB4DC6AA79D276F
        CheckMD5   : 41F002D6CE182ACAFDCABC4F66708FCD
        FixMD5     : 2A53D1A8C44E2844C5B9C7BB96598796
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Computers = Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupID -eq 515)} -Properties Name, DistinguishedName, Enabled, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, Description, PrimaryGroupID

    If (($Computers | Measure-Object).Count -gt 0) {
        $Status = "Open"
        ForEach ($Computer in $Computers) {
            $FindingDetails += "Name:`t`t`t`t`t`t$($Computer.Name)" | Out-String
            $FindingDetails += "Enabled:`t`t`t`t`t`t$($Computer.Enabled)" | Out-String
            $FindingDetails += "Trusted For Delegation:`t`t`t$($Computer.TrustedForDelegation)" | Out-String
            $FindingDetails += "Trusted To Auth For Delegation:`t$($Computer.TrustedToAuthForDelegation)" | Out-String
            ForEach ($SPN in $Computer.ServicePrincipalName) {
                $FindingDetails += "Service Principal Name:`t`t`t$($SPN)" | Out-String
            }
            $FindingDetails += "Description:`t`t`t`t`t$($Computer.Description)" | Out-String
            $FindingDetails += "PrimaryGroupID:`t`t`t`t$($Computer.PrimaryGroupID)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No computers are Trusted for Delegation and have a Primary Group ID of '515'" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V243480 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243480
        STIG ID    : AD.0160
        Rule ID    : SV-243480r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : The domain functional level must be at a Windows Server version still supported by Microsoft.
        DiscussMD5 : BF511DDBD2355F8EC131C70699B187E8
        CheckMD5   : 3E24686B1D055B297357FD1AA8F51A95
        FixMD5     : 01C27C506EF5E14C07F0CE262EA69BD4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Regex = "(?:Windows)(\d{4})"
    $DomainFunctionalLevel = (Get-ADDomain).DomainMode
    If ($DomainFunctionalLevel -match $Regex) {
        If ($Matches[1] -lt 2016) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }

    }
    $FindingDetails += "Domain Level: $($DomainFunctionalLevel)" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V243481 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243481
        STIG ID    : AD.0170
        Rule ID    : SV-243481r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Access to need-to-know information must be restricted to an authorized community of interest.
        DiscussMD5 : 771D0AFF10E522E29C586603F758B0F9
        CheckMD5   : A6C356692B97E095BF578DE68A223603
        FixMD5     : B038BACB79F04B8B9AD0C537B662EF0D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter *

    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += "No trusts are configured."
    }
    Else {
        $FindingDetails += "Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $Trusts) {
            $FormattedTrust = Format-TrustObject $Trust
            ForEach ($Key in $FormattedTrust.Keys) {
                $FindingDetails += "$($Key) : $($FormattedTrust.$Key)" | Out-String
            }
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

Function Get-V243482 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243482
        STIG ID    : AD.0180
        Rule ID    : SV-243482r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Interconnections between DoD directory services of different classification levels must use a cross-domain solution that is approved for use with inter-classification trusts.
        DiscussMD5 : 19459BC72C2C41C7DA245B052AC55C70
        CheckMD5   : 93817D9E5660762D72947C75B2AAC23B
        FixMD5     : 716556A05447C9E746D7FB80578A5894
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter *

    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $Trusts) {
            $FormattedTrust = Format-TrustObject $Trust
            ForEach ($Key in $FormattedTrust.Keys) {
                $FindingDetails += "$($Key) : $($FormattedTrust.$Key)" | Out-String
            }
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

Function Get-V243483 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243483
        STIG ID    : AD.0181
        Rule ID    : SV-243483r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : A controlled interface must have interconnections among DoD information systems operating between DoD and non-DoD systems or networks.
        DiscussMD5 : 1A800498D6B3A26DE74CE7BAFD0E7C60
        CheckMD5   : 50B71771212D1DD1C847D4A6CC412A9F
        FixMD5     : BE2DCA0BB0B2B74C9E277DEB6DF27D5F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter *

    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $Trusts) {
            $FormattedTrust = Format-TrustObject $Trust
            ForEach ($Key in $FormattedTrust.Keys) {
                $FindingDetails += "$($Key) : $($FormattedTrust.$Key)" | Out-String
            }
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

Function Get-V243484 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243484
        STIG ID    : AD.0190
        Rule ID    : SV-243484r958482_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-OS-000104
        Rule Title : Security identifiers (SIDs) must be configured to use only authentication data of directly trusted external or forest trust.
        DiscussMD5 : 5E0B4DF203317D6A5CE9CEC76EA8E178
        CheckMD5   : A8442DD04E978956B41BFBE81DD69D66
        FixMD5     : 2F1F12CBA5D0AD4B59AC6537C9111630
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter * | Where-Object TrustType -EQ "Uplevel"

    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No 'External' or 'Forest' trusts are configured so this requirement is NA."
    }
    Else {
        $Compliant = $true
        $BadTrust = [System.Collections.Generic.List[System.Object]]::new()
        $GoodTrust = [System.Collections.Generic.List[System.Object]]::new()
        ForEach ($Trust in $Trusts) {
            $TrustCompliant = $true
            $FormattedTrust = Format-TrustObject $Trust
            Switch ($FormattedTrust.Type) {
                "External" {
                    If ($FormattedTrust.SIDFilteringQuarantined -ne $true) {
                        $TrustCompliant = $false
                        $FormattedTrust.SIDFilteringQuarantined = "$($FormattedTrust.SIDFilteringQuarantined) [expected True]"
                    }
                }
                "Forest" {
                    If ($FormattedTrust.SIDFilteringForestAware -ne $false) {
                        $TrustCompliant = $false
                        $FormattedTrust.SIDFilteringForestAware = "$($FormattedTrust.SIDFilteringForestAware) [expected False]"
                    }
                }
                DEFAULT {
                    $TrustCompliant = $false
                    $FormattedTrust.SIDFilteringQuarantined = "$($FormattedTrust.SIDFilteringQuarantined) [unabled to determine trust Type]"
                    $FormattedTrust.SIDFilteringForestAware = "$($FormattedTrust.SIDFilteringForestAware) [unabled to determine trust Type]"
                }
            }

            If ($TrustCompliant -eq $true) {
                $GoodTrust.Add($FormattedTrust)
            }
            Else {
                $BadTrust.Add($FormattedTrust)
            }
        }

        If (($BadTrust | Measure-Object).Count -gt 0) {
            $Compliant = $false
            $FindingDetails += "Non-Compliant Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Key in $BadTrust.Keys) {
                $FindingDetails += "$($Key) : $($BadTrust.$Key)"
                $FindingDetails += "" | Out-String
            }
        }
        If (($GoodTrust | Measure-Object).Count -gt 0) {
            $FindingDetails += "Compliant Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Key in $GoodTrust.Keys) {
                $FindingDetails += "$($Key) : $($GoodTrust.$Key)"
                $FindingDetails += "" | Out-String
            }
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

Function Get-V243485 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243485
        STIG ID    : AD.0200
        Rule ID    : SV-243485r958472_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080
        Rule Title : Selective Authentication must be enabled on outgoing forest trusts.
        DiscussMD5 : AF713C14A7F3B185362B1D5C846E789C
        CheckMD5   : 52686D946E71B3F46E6435A848CA5E66
        FixMD5     : 2A885A5460F15C3C4C4CA4D55E9ACEED
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter *

    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    ElseIf (($Trusts | Where-Object {$_.TrustType -EQ "Uplevel" -and $_.TrustAttributes -band 8 -and $_.Direction -in @("Outbound","BiDirectional")} | Measure-Object).Count -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += "No outgoing forest trusts are configured."
    }
    Else {
        $Compliant = $true
        $BadTrust = [System.Collections.Generic.List[System.Object]]::new()
        $GoodTrust = [System.Collections.Generic.List[System.Object]]::new()
        ForEach ($Trust in $Trusts) {
            $TrustCompliant = $true
            $FormattedTrust = Format-TrustObject $Trust
            If ($FormattedTrust.Type -eq "Forest" -and $FormattedTrust.Direction -in @("Outbound", "BiDirectional")) {
                If ($FormattedTrust.SelectiveAuthentication -ne $true) {
                    $TrustCompliant = $false
                    $FormattedTrust.SelectiveAuthentication = "$($FormattedTrust.SelectiveAuthentication) [expected True]"
                }

                If ($TrustCompliant -eq $true) {
                    $GoodTrust.Add($FormattedTrust)
                }
                Else {
                    $BadTrust.Add($FormattedTrust)
                }
            }
        }

        If (($BadTrust | Measure-Object).Count -gt 0) {
            $Compliant = $false
            $FindingDetails += "Non-Compliant Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Key in $BadTrust.Keys) {
                $FindingDetails += "$($Key) : $($BadTrust.$Key)"
                $FindingDetails += "" | Out-String
            }
        }
        If (($GoodTrust | Measure-Object).Count -gt 0) {
            $FindingDetails += "Compliant Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Key in $GoodTrust.Keys) {
                $FindingDetails += "$($Key) : $($GoodTrust.$Key)"
                $FindingDetails += "" | Out-String
            }
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

Function Get-V243486 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243486
        STIG ID    : AD.0220
        Rule ID    : SV-243486r958504_rule
        CCI ID     : CCI-000804
        Rule Name  : SRG-OS-000121
        Rule Title : The Anonymous Logon and Everyone groups must not be members of the Pre-Windows 2000 Compatible Access group.
        DiscussMD5 : 6F728C07E5CE5EC947F0796A5F74871D
        CheckMD5   : C1441D38C9F4995AF33BC9D123283287
        FixMD5     : 17B28E75235D3E16F7F96EB521DDF6CF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MemberGroup = "Pre-Windows 2000 Compatible Access"
    $Users = Get-MembersOfADGroup -identity $MemberGroup -Recursive | Where-Object {$_.Name -eq "Everyone" -or $_.Name -eq "Anonymous Logon"}

    If (($Users | Measure-Object).Count -gt 0) {
        $Status = "Open"
        If ($Users -contains "Anonymous Logon") {
            $FindingDetails += "'Anonymous Logon' is a member of '$($MemberGroup)'" | Out-String
        }
        Else {
            $FindingDetails += "'Everyone' is a member of '$($MemberGroup)'" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Both 'Anonymous Logon' and 'Everyone' are not members of '$MemberGroup'."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V243487 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243487
        STIG ID    : AD.0240
        Rule ID    : SV-243487r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership in the Group Policy Creator Owners and Incoming Forest Trust Builders groups must be limited.
        DiscussMD5 : 5A0874037B414AAB211026AA91ACD525
        CheckMD5   : 963386734590F059367C25EE370751D2
        FixMD5     : 27C8047EF20DBD5CFDAE8E12F3C513C2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Groups = @("Incoming Forest Trust Builders", "Group Policy Creator Owners")

    ForEach ($Group in $Groups) {
        $ReturnedUsers = Get-MembersOfADGroup -Identity $Group -Recursive
        If (($ReturnedUsers | Measure-Object).Count -eq 0) {
            $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "Members of '$($Group)'" | Out-String
            $FindingDetails += "=========================" | Out-String
            ForEach ($User in $ReturnedUsers) {
                $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                $FindingDetails += "objectClass:`t`t`t$($User.objectClass)" | Out-String
                $FindingDetails += "objectSID:`t`t`t$($User.objectSID.Value)" | Out-String
                $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += "" | Out-String
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

Function Get-V243489 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243489
        STIG ID    : AD.0270
        Rule ID    : SV-243489r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Read-only Domain Controller (RODC) architecture and configuration must comply with directory services requirements.
        DiscussMD5 : 69C3ECF4EF53B06E300FFD658F105CD5
        CheckMD5   : 8E9B923F9910DF8B46B22B8ABE92B36C
        FixMD5     : 624B6AE58F4926ADCBF07D2D51B4FE3A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    If ($AllDCs.IsReadOnly -eq $true) {
        $FindingDetails += "Read-only domain controllers (RODC):"
        $FindingDetails += "====================================" | Out-String
        ForEach ($DC in ($AllDCs | Where-Object IsReadOnly -EQ $true)) {
            $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
            $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
            $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
            $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
            $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
            $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
            $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
            $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No read-only domain controllers (RODC) exist in the domain." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V243490 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243490
        STIG ID    : AD.AU.0001
        Rule ID    : SV-243490r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Usage of administrative accounts must be monitored for suspicious and anomalous activity.
        DiscussMD5 : 476B92E61BE863347694192E92340292
        CheckMD5   : 322E707B90FA3FB1432565150AAFCD73
        FixMD5     : 69F5AAFB6E7E8BC3EF6613D5E0432DF6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $AuditCategorys = @("Logon", "User Account Management", "Account Lockout", "Security Group Management") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4740", "4728", "4732", "4756", "4624", "4625", "4648")

    ForEach ($EventID in $EventIDs) {
        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue @{logname = 'system', 'application', 'security'; ID = $EventID} -MaxEvents 1 | Select-Object ContainerLog, ID, LevelDisplayName, Message, TimeCreated
        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvent.Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "Level:`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t$($ReturnedEvent.TimeCreated)" | Out-String
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

Function Get-V243491 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243491
        STIG ID    : AD.AU.0002
        Rule ID    : SV-243491r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Systems must be monitored for attempts to use local accounts to log on remotely from other systems.
        DiscussMD5 : 310D95035BAA0906406FD88DE4FA5CD3
        CheckMD5   : DB5C112F7ABE2426550E9DA55145EBBE
        FixMD5     : 41D2E9309CC9580703E1B2EDF1872115
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $AuditCategorys = @("Logon", "Account Lockout") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = 4624, 4625
    $DomainNames = (Get-CimInstance Win32_NTDomain).DomainName

    foreach ($EventID in $EventIDs) {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $EventID } -ErrorAction SilentlyContinue |
        ForEach-Object {
            # Parse XML to get named EventData
            $xml = [xml]$_.ToXml()
            $dataH = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $dataH[$d.Name] = $d.'#text'
            }

            # Normalize fields that differ across 4624/4625
            $acct = if ($_.Id -eq 4624) {
                $dataH['SubjectUserName']
            }
            else {
                $dataH['TargetUserName']
            }
            $domain = if ($_.Id -eq 4624) {
                $dataH['SubjectDomainName']
            }
            else {
                $dataH['TargetDomainName']
            }

            [pscustomobject]@{
                Event     = $_
                LogonType = $dataH['LogonType']
                AuthPkg   = $dataH['AuthenticationPackageName']
                Account   = $acct
                Domain    = $domain
            }
        } |
        Where-Object {
            $_.LogonType -eq '3' -and
            $_.AuthPkg -eq 'NTLM' -and
            $_.Account -ne 'ANONYMOUS LOGON' -and
            $_.Domain -notin $DomainNames
        } |
        Select-Object -First 1

        if (-not $events) {
            $FindingDetails += "No event was found for EventID: $EventID" | Out-String
            $FindingDetails += "" | Out-String
            continue
        }

        $ReturnedEvent = $events.Event

        # Safe first-sentence extract (handles no-period case; dot matches newlines)
        $m = [regex]::Match($ReturnedEvent.Message, '(?s)^[^.]*\.')
        $Message = if ($m.Success) {
            $m.Value
        }
        else {
            ($ReturnedEvent.Message -split "`r?`n")[0]
        }

        $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.Id)" | Out-String
        $FindingDetails += "Message:`t`t`t$Message" | Out-String
        $FindingDetails += "User:`t`t`t$($events.Account)" | Out-String
        $FindingDetails += "Domain:`t`t`t$($events.Domain)" | Out-String
        $FindingDetails += "Level:`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
        $FindingDetails += "Container Log:`t`t$($ReturnedEvent.ContainerLog)" | Out-String
        $FindingDetails += "Time Created:`t`t$($ReturnedEvent.TimeCreated)" | Out-String
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

Function Get-V243492 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243492
        STIG ID    : AD.AU.0003
        Rule ID    : SV-243492r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Systems must be monitored for remote desktop logons.
        DiscussMD5 : 2FC955A6E511747A8FECB54F64797FD0
        CheckMD5   : 3D50DF20FA909877553CD645A93769D6
        FixMD5     : B2E6489427F5971AFE21C231B58F755A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $AuditCategorys = @("Logon") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4624")

    ForEach ($EventID in $EventIDs) {

        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue @{logname = 'system', 'application', 'security'; ID = $EventID; LogonType = '10'; AuthenticationPackageName = 'Negotiate'} | Select-Object -First 1 ContainerLog, ID, LevelDisplayName, Message, TimeCreated, Properties
        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvent.Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "Logon Type:`t`t`t$($ReturnedEvent.Properties[8].Value)" | Out-String
            $FindingDetails += "Authentication Package Name:`t$($ReturnedEvent.Properties[10].Value)" | Out-String
            $FindingDetails += "Level:`t`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t`t$($ReturnedEvent.TimeCreated)" | Out-String
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

Function Get-V243494 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243494
        STIG ID    : DS00.1120_AD
        Rule ID    : SV-243494r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Each cross-directory authentication configuration must be documented.
        DiscussMD5 : BC8D64FB5D0C40E6968964EBC3DA0DE7
        CheckMD5   : 5EF88BD796A7C721267309B2C046ED9C
        FixMD5     : 9EB5E9AC069020E6AB0756C93136825D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter *

    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $Trusts) {
            $FormattedTrust = Format-TrustObject $Trust
            ForEach ($Key in $FormattedTrust.Keys) {
                $FindingDetails += "$($Key) : $($FormattedTrust.$Key)" | Out-String
            }
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

Function Get-V243495 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243495
        STIG ID    : DS00.1140_AD
        Rule ID    : SV-243495r958908_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-OS-000423
        Rule Title : A VPN must be used to protect directory network traffic for directory service implementation spanning enclave boundaries.
        DiscussMD5 : FEF5CBB69394DD59CEC391EABD467690
        CheckMD5   : 7FA4BD45B637C969B7565A359E6A41A5
        FixMD5     : 5FD79A513A50944D749E141ABE74EE19
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
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

Function Get-V243496 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243496
        STIG ID    : DS00.3200_AD
        Rule ID    : SV-243496r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Accounts from outside directories that are not part of the same organization or are not subject to the same security policies must be removed from all highly privileged groups.
        DiscussMD5 : 85EF8B1FE370205505C284040A6FE73E
        CheckMD5   : D04E419E94AEB91A736C74730AB80DC2
        FixMD5     : 57CF2A84767882079FB22EEFD0116D49
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Groups = @("Incoming Forest Trust Builders", "Domain Admins", "Enterprise Admins", "Schema Admins", "Group Policy Creator Owners")
    $Forest = Get-ADForest
    $ForestDN = ""
    ForEach ($Item in (($Forest).Name).Split(".")) {
        $ForestDN += "DC=$($Item),"
    }
    $Pattern = [regex]::Escape($($ForestDN -replace ",$", "")) + "$"
    ForEach ($Group in $Groups) {
        $ReturnedMembers = Get-MembersOfADGroup -Identity $Group -Recursive
        If (($ReturnedMembers | Measure-Object).Count -eq 0) {
            $FindingDetails += "'$($Group)' - Contains no members" | Out-String
        }
        Else {
            $ExternalMembers = @()
            ForEach ($Member in $ReturnedMembers) {
                If (($Member.DistinguishedName -notmatch $Pattern) -or ($Member.objectClass -eq 'foreignSecurityPrincipal')) {
                    $ExternalMembers += $Member
                }
            }
            If (($ExternalMembers | Measure-Object).Count -gt 0) {
                $Compliant = $false
                $FindingDetails += "'$($Group)' - Contains external members:" | Out-String
                $FindingDetails += "=========================" | Out-String
                ForEach ($Member in $ExternalMembers) {
                    $FindingDetails += "Name:`t`t`t`t$($Member.name)" | Out-String
                    $FindingDetails += "objectClass:`t`t`t$($Member.objectClass)" | Out-String
                    $FindingDetails += "objectSID:`t`t`t$($Member.objectSID.Value)" | Out-String
                    $FindingDetails += "DistinguishedName:`t$($Member.distinguishedName)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $FindingDetails += "'$($Group)' - All members from '$($Forest.Name)' forest" | Out-String
            }
        }
        $FindingDetails += "" | Out-String
    }

    If ($compliant -eq $true) {
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

Function Get-V243497 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243497
        STIG ID    : DS00.3230_AD
        Rule ID    : SV-243497r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Inter-site replication must be enabled and configured to occur at least daily.
        DiscussMD5 : FC5B5F2A8CDC20DC3E23B142BC2A267E
        CheckMD5   : A359B8785BC4CAA8EFEAC198462FECE6
        FixMD5     : 5F64A13768971B8ECF064F614CB86020
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ADSites = Get-ADReplicationSite -Filter * -Properties *
    If (($ADSites | Measure-Object).Count -eq 1) {
        $Status = "Not_Applicable"
        $FindingDetails += "Only one site exists so this requirement is NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Site: $($ADSites.Name)" | Out-String
    }
    Else {
        $Compliant = $true
        $SiteLinks = Get-ADReplicationSiteLink -Filter * -Properties *
        $FindingDetails += "Site Link Replication Frequency" | Out-String
        $FindingDetails += "===============================" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($SiteLink in $SiteLinks) {
            $FindingDetails += "Name:`t`t$($SiteLink.Name)" | Out-String
            If ($SiteLink.ReplicationFrequencyInMinutes -gt 1440) {
                $Compliant = $false
                $FindingDetails += "Frequency:`t$($SiteLink.ReplicationFrequencyInMinutes) [Expected: 1440 or less]" | Out-String
            }
            Else {
                $FindingDetails += "Frequency:`t$($SiteLink.ReplicationFrequencyInMinutes)" | Out-String
            }

            $TimeSlotsWithoutReplication = 0
            For ($i = 20; $i -lt (($SiteLink.Schedule) | Measure-Object).Count; $i++) {
                #Run through the replication schedule. There are 288 bytes in total, with the first 20 being a header.
                If ($SiteLink.Schedule[$i] -eq 240) {
                    #If the value equals 255, replication is set to happen; if 240, replication will not happen.
                    $TimeSlotsWithoutReplication += 1
                    If ($TimeSlotsWithoutReplication -eq 24) {
                        $Compliant = $false
                        $FindingDetails += "There are 24 hour period(s) with no available replication schedule.  [Finding]" | Out-String
                    }
                }
                Else {
                    $TimeSlotsWithoutReplication = 0
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
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V243498 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243498
        STIG ID    : DS00.4140_AD
        Rule ID    : SV-243498r958406_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000032
        Rule Title : If a VPN is used in the AD implementation, the traffic must be inspected by the network Intrusion detection system (IDS).
        DiscussMD5 : 13596707828FFF28E11B82225D90CF6B
        CheckMD5   : 2638A2EAD85C4A512087DE8650D9F648
        FixMD5     : FC5A22230981FD5607AE352E115AE4FD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
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

Function Get-V243500 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243500
        STIG ID    : DS00.6140_AD
        Rule ID    : SV-243500r959010_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Active Directory must be supported by multiple domain controllers where the Risk Management Framework categorization for Availability is moderate or high.
        DiscussMD5 : FFEA62BE1ECD26422B15F6E14AD97557
        CheckMD5   : CCB80FC26B24D7FE9276B046C797E783
        FixMD5     : CB5C2A2BC5CEE67C9994E6E31DAC82D9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    If (($AllDCs | Measure-Object).Count -eq 1) {
        $FindingDetails += "Only one domain controller exists in the domain.  If Availability categorization is low, mark as NA.  Otherwise, mark as Open." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Multiple domain controllers exist in the domain." | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
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

Function Get-V243501 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243501
        STIG ID    : DS00.7100_AD
        Rule ID    : SV-243501r1016334_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : The impact of CPCON changes on the cross-directory authentication configuration must be considered and procedures documented.
        DiscussMD5 : 3D8348F71E9E4DEEAFFEEA9749D64A6C
        CheckMD5   : FB2F46AC5AAE3E049A2127B9382C3558
        FixMD5     : 9B08AF355D64C06F5FFB1BB6870B40B3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter *

    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $Trusts) {
            $FormattedTrust = Format-TrustObject $Trust
            ForEach ($Key in $FormattedTrust.Keys) {
                $FindingDetails += "$($Key) : $($FormattedTrust.$Key)" | Out-String
            }
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

Function Get-V269097 {
    <#
    .DESCRIPTION
        Vuln ID    : V-269097
        STIG ID    : AD.0205
        Rule ID    : SV-269097r1026170_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Windows Server domain controllers must have Kerberos logging enabled with servers hosting Active Directory Certificate Services (AD CS).
        DiscussMD5 : DC427F21F5610C5AFC4A3A4CB83F51E5
        CheckMD5   : E4E6219AB4F6DF82490D532844BC1383
        FixMD5     : 05A737A9E94EB67C544F67BC77F3B3C9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $AuditSubcat = @("Kerberos Authentication Service", "Kerberos Service Ticket Operations")
    $AuditIncSet = @("Success", "Failure")

    ForEach ($Cat in $AuditSubcat) {
        $AuditPol = AuditPol /Get /Category:* /r | ConvertFrom-Csv | Where-Object {$_.Subcategory -eq $Cat}
        If ($AuditPol) {
            ForEach ($Set in $AuditIncSet) {
                If (-Not($AuditPol.'Inclusion Setting' -match $Set)) {
                    $Compliant = $false
                }
            }

            $FindingDetails += "$($Cat):`t$($AuditPol.'Inclusion Setting')" | Out-String
        }
        Else {
            $FindingDetails += "'$($Cat)' not found as an audit subcategory.  Please manually review." | Out-String
        }

        $FindingDetails += "" | Out-String
    }

    If ($Compliant) {
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCqx4XFcaBx9BMJ
# 8l6yJl+Y81sPglvgkvLZxpoyVOxDp6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDA+fpcjoHGrgRdvyoNzGP4cA+g7dzrGrJ6DXUEDtWbtTANBgkqhkiG9w0BAQEF
# AASCAQBqkMKYm5LDIjMnEtq3NcqDZu68gnIJb44PdxMFoY5ggNkjOwjPg2FWetxx
# 2UT3nvgT+jhDtUVquud3u1MrNwvBxu/6kCstIJHj09pix+D6B+MFpAKxj/WAJ/6L
# rAYUjUWG/vEZt6VW/BbfdtXEhXwTU6QSh+gfO6+olr6cISRJ9RRuVpC+kmSDrBeo
# kYVU2wAVUgtE10mViwBKIAbQtjsG4Z92c350oQz0fGFVEkGn9TNjaPNg0n3HyEDL
# /ggCsJhoyQ2sz0C4zICJVwFbnZO9xtzgjFwqWR+nFODxZ13aj6RMFDLUJ5/amGe5
# 3GK4nxuePrvasqiMDnZGZ1BVNtKUoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAwMTE2NTcwOVowLwYJKoZIhvcNAQkEMSIEIEIfrvhKF4hxCB2njGcc1YJXztwD
# UguCvQJkkJ51UP9MMA0GCSqGSIb3DQEBAQUABIICAJvhiXkJ5cyjElnXTmHlHVv4
# LicJCbIsYlbZZJWQwfkjWjE3vdxtYoYFqrYpN0DggJphRHiQYnSmvkoQj/Mg6ZNv
# Uzz9QkSbZy6twECKwPh7LDqSIIvnCpyBzpO6Qcsog9+eaewA0h91R5vR7O9TXme7
# /l8tTV0ke3bQMxx1ugMQ/swC0qM7X5Z+f7QVAggPAehMy2UvqVpPOu4Zbw9uqjIq
# LxDof9/tYiKrIBy7QPoz93v4ylW2nXBjmNPvAp/RU4q0YVVrcWDG/jx2T5cS2VCK
# HaAqpQyYLGZ5pvQWT6kcSaBgfD9qrm6v1WXV66o2OBvJjZWnJBfmsyFCdXGq1A0B
# OaUkm6S+8IudtXkUfWTEMWUULfByTVnX1zC+kJkZ50z8Dw+YWzM14NiLyA65cdz1
# 4GhlB8eVAEatQVgKYiKIBwxf16bg14QXC4S3Hyt5wJMPgJHhFMuvtH6RP/c/UQKs
# WAViPkRVLqZygoJ2c5QqBArONf2XRbMJ7sgy2k/Dc0s+dBk3LlK7aAzDdm/XkljC
# +BoFKDx8xOxw13LQaLa9p/sEECuh5+Vx8v6cp0Ul9erB+UGeSl1KTMm/ACxX8/nQ
# Vh9UzSmSFfL9qGHuwZQWe1wJc0/AzsaCb13ZWkzbNPvP6WfzzoLzSlyj6wvd85C4
# FjwrC6g5muthtWy6iAW+
# SIG # End signature block
