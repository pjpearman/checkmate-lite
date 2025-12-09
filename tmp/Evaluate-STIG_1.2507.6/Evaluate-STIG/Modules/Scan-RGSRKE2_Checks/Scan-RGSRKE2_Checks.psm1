##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Rancher Government Solutions RKE2
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Air Systems Command (NAVAIR)
##########################################################################
$ErrorActionPreference = "Stop"

Function FormatFinding {
    # Return string which is added at end of $FindingDetails by each V-XXXXX method.
    # Requires finding argument.
    Param(
        [parameter (Mandatory = $true, position = 0, ParameterSetName = 'finding')]
        [AllowNull()]
        $line
    )

    # insert separator line between $FindingMessage and $finding
    $BarLine = "------------------------------------------------------------------------"
    $FormattedFinding += $BarLine | Out-String

    # insert findings
    $FormattedFinding += $finding | Out-String

    Return $FormattedFinding
}

Function Get-V254553 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254553
        STIG ID    : CNTR-R2-000010
        Rule ID    : SV-254553r1016525_rule
        CCI ID     : CCI-000068, CCI-000185, CCI-000382, CCI-000803, CCI-001184, CCI-001453, CCI-002420, CCI-002422, CCI-002450
        Rule Name  : SRG-APP-000014-CTR-000035
        Rule Title : Rancher RKE2 must protect authenticity of communications sessions with the use of FIPS-validated 140-2 or 140-3 security requirements for cryptographic modules.
        DiscussMD5 : 120FD4742249839918BF1FA416E697C9
        CheckMD5   : 78070265A751222325CFEABD440090E7
        FixMD5     : 97BDC377E0DCA21CEDE3C2DDD67301A6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $found = 0
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String
        #If the setting "tls-min-version" is not configured or it is set to "VersionTLS10" or "VersionTLS11", this is a finding.
        If ((($finding.split(" ") | Select-String "tls-min-version") -split ("="))[1] -ge "VersionTLS12") {
            $found++
            $FindingMessage = "kube-apiserver --tls-min-version is set to VersionTLS12 or greater."
        }
        Else {
            $FindingMessage = "kube-apiserver --tls-min-version is not set to VersionTLS12 or greater."
        }
        $FindingDetails += $FindingMessage | Out-String
        #If "tls-cipher-suites" is not set for all servers, or does not contain the following, this is a finding:
        If ((($finding.split(" ") | Select-String "tls-cipher-suites") -split ("="))[1] -eq "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            $found++
            $FindingMessage = "kube-apiserver --tls-cipher-suites is set to required string."
        }
        Else {
            $FindingMessage = "kube-apiserver --tls-cipher-suites is not set to required string."
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingMessage += $(FormatFinding "kube-apiserver process was not found found on system") | Out-String
    }

    $finding = (Get-Process | Where-Object { $_.name -eq "kube-controller-manager"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If ((($finding.split(" ") | Select-String "tls-min-version") -split ("="))[1] -ge "VersionTLS12") {
            $found++
            $FindingMessage = "kube-controller-manager --tls-min-version is set to VersionTLS12 or greater."
        }
        Else {
            $FindingMessage = "kube-controller-manager --tls-min-version is not set to VersionTLS12 or greater."
        }
        $FindingDetails += $FindingMessage | Out-String
        If ((($finding.split(" ") | Select-String "tls-cipher-suites") -split ("="))[1] -eq "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            $found++
            $FindingMessage = "kube-controller-manager --tls-cipher-suites is set to required string."
        }
        Else {
            $FindingMessage = "kube-controller-manager --tls-cipher-suites is not set to required string."
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingMessage += "kube-controller-manager process was not found found on system"
    }

    $finding = (Get-Process | Where-Object { $_.name -eq "kube-scheduler"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If ((($finding.split(" ") | Select-String "tls-min-version") -split ("="))[1] -ge "VersionTLS12") {
            $found++
            $FindingMessage = "kube-scheduler --tls-min-version is set to VersionTLS12 or greater."
        }
        Else {
            $FindingMessage = "kube-scheduler --tls-min-version is not set to VersionTLS12 or greater."
        }
        $FindingDetails += $FindingMessage | Out-String
        If ((($finding.split(" ") | Select-String "tls-cipher-suites") -split ("="))[1] -eq "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            $found++
            $FindingMessage = "kube-scheduler --tls-cipher-suites is set to required string."
        }
        Else {
            $FindingMessage = "kube-scheduler --tls-cipher-suites is not set to required string."
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingMessage += "kube-scheduler process was not found on system"
    }
    If (Get-Process | Where-Object { $_.name -in "kube-controller-manager", "kube-apiserver", "kube-scheduler"}) {
        If ($found -eq 6) {
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

Function Get-V254554 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254554
        STIG ID    : CNTR-R2-000030
        Rule ID    : SV-254554r1043176_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-CTR-000055
        Rule Title : RKE2 must use a centralized user management solution to support account management functions.
        DiscussMD5 : CAC05079CC5E2A7C0F995C25ED99DDF7
        CheckMD5   : A979612B91F4E05F4ADBA145C1798802
        FixMD5     : 4662BDB61010D4DC951E7AF3D21B625E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-controller-manager"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If --use-service-account-credentials argument is not set to "true" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "use-service-account-credentials") -split ("="))[1] -eq $true) {
            $FindingMessage = "kube-scheduler --use-service-account-credentials is set to true."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-scheduler --use-service-account-credentials is not set to true or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails = "kube-controller-manager not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254555
        STIG ID    : CNTR-R2-000060
        Rule ID    : SV-254555r1056186_rule
        CCI ID     : CCI-000018, CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000172, CCI-000366, CCI-001403, CCI-001404, CCI-001464, CCI-001487, CCI-001851, CCI-001889, CCI-001890, CCI-002130, CCI-002234, CCI-002884, CCI-003938
        Rule Name  : SRG-APP-000026-CTR-000070
        Rule Title : Rancher RKE2 components must be configured in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : 293EBF76299A9A31A93C228856AD3517
        CheckMD5   : F759A6453246BA7D20A9B322727FBBA9
        FixMD5     : 1E28C9717AD7318A5446B1135952BAD2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "audit-policy-file") -split ("="))[1] -match "\S") {
            $FindingMessage = "kube-apiserver --audit-policy-file is set."
        }
        Else {
            $FindingMessage = "kube-apiserver --audit-policy-file is not configured."
            $Compliant = $false
        }
        $FindingDetails += $FindingMessage | Out-String

        If ((($finding.split(" ") | Select-String "audit-log-mode") -split ("="))[1] -eq "blocking-strict") {
            $FindingMessage = "kube-apiserver --audit-log-mode is set to blocking-strict."
        }
        Else {
            $FindingMessage = "kube-apiserver --audit-log-mode is not set to blocking-strict or is not configured."
            $Compliant = $false
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kube-apiserver not found on system"
    }
    If (Test-Path "/etc/rancher/rke2/config.yaml") {
        $finding = ((Get-Content /etc/rancher/rke2/config.yaml) -match 'profile: (.+)')
        If ($finding) {
            $FindingDetails += $(FormatFinding $finding) | Out-String
            If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
                $finding3 = (/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version -o json | ConvertFrom-Json).serverVersion.gitVersion
                $FindingDetails += $finding3 | Out-String
                If ($finding3 -le 1.24) {
                    If (($finding -split (" "))[1].trim('"') -eq "cis-1.6") {
                        $FindingMessage = "CIS Profile set to 1.6"
                    }
                    Else {
                        $FindingMessage = "CIS Profile not set to 1.6 or is not configured"
                        $Compliant = $false
                    }
                }
                ElseIf ($finding3 -lt 1.25.15 -and $finding3 -gt 1.24) {
                    If (($finding -split (" "))[1].trim('"') -eq "cis-1.23") {
                        $FindingMessage = "CIS Profile set to 1.23"
                    }
                    Else {
                        $FindingMessage = "CIS Profile not set to 1.23 or is not configured"
                        $Compliant = $false
                    }
                }
                Else {
                    If (($finding -split (" "))[1].trim('"') -eq "cis") {
                        $FindingMessage = "CIS Profile set to cis"
                    }
                    Else {
                        $FindingMessage = "CIS Profile not set to cis or is not configured"
                        $Compliant = $false
                    }
                }
                $FindingDetails += $FindingMessage | Out-String
            }
            Else {
                $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
                $Compliant = $false
            }
        }
        Else {
            $FindingDetails += "No profile string found in config.yaml"
            $Compliant = $false
        }
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/config.yaml"
        $Compliant = $false
    }
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $finding = Get-Content (($finding.split(" ") | Select-String "audit-policy-file") -split ("="))[1]
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding -join ('')).Replace(' ', '') -eq 'apiVersion:audit.k8s.io/v1kind:Policymetadata:name:rke2-audit-policyrules:-level:Metadataresources:-group:""resources:["secrets"]-level:RequestResponseresources:-group:""resources:["*"]') {
            $FindingMessage = "Audit Policy File matches requirements"
        }
        Else {
            $FindingMessage = "Audit Policy File does not match requirements"
            $Compliant = $false
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kube-apiserver not found on system"
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

Function Get-V254556 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254556
        STIG ID    : CNTR-R2-000100
        Rule ID    : SV-254556r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000090
        Rule Title : The Kubernetes Controller Manager must have secure binding.
        DiscussMD5 : 66AB62873A113C9719D906C305D58D73
        CheckMD5   : ACBD27CAFB661AD57FE5F4BA54DAD4F2
        FixMD5     : 8A0D8898E3DD20D53E3E63961C9F91B0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-controller-manager"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "bind-address") -split ("="))[1] -eq "127.0.0.1") {
            $FindingMessage = "kube-controller-manager --bind-address is set to 127.0.0.1."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-controller-manager --bind-address is not set to 127.0.0.1 or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kube-controller-manager process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254557
        STIG ID    : CNTR-R2-000110
        Rule ID    : SV-254557r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000090
        Rule Title : The Kubernetes Kubelet must have anonymous authentication disabled.
        DiscussMD5 : 64B90A4ABBB693546D11D19C134E807A
        CheckMD5   : 3B6CF9ACDDD90A5A02ECDC17D38D00B7
        FixMD5     : A17DEF77B23FCCA3640986FB7D5FBB01
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "anonymous-auth") -split ("="))[1] -eq $false) {
            $FindingMessage = "kubelet --anonymous-auth is set to false."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --anonymous-auth is not set to false or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kubelet process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254558 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254558
        STIG ID    : CNTR-R2-000120
        Rule ID    : SV-254558r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes API server must have the insecure port flag disabled.
        DiscussMD5 : 5FEEC9515F9EFC80DD46D2204520FE20
        CheckMD5   : 278E7460747CF64144D7996DE2F25565
        FixMD5     : 1ED0EA5836ECD0F34637CC6056208861
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version | Select-String Server
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding -split ("[+:]"))[1].trim(" v") -le 1.23 -and ($finding -split ("[+:]"))[1].trim(" v") -ge 1.20) {
            $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
            If ($finding) {
                $FindingDetails += $(FormatFinding $finding) | Out-String
                $finding = $finding.split("=") | Select-String "insecure-port"
                If (($NULL -eq $finding) -or (($finding)[1] -eq "0")) {
                    $FindingMessage = "kube-apiserver --insecure-port is set to 0 or is not configured."
                    $Status = "NotAFinding"
                }
                Else {
                    $FindingMessage = "kube-apiserver --insecure-port is not set to 0."
                    $Status = "Open"
                }
                $FindingDetails += $FindingMessage | Out-String
            }
            Else {
                $FindingDetails += "kube-apiserver process not found on system"
            }
        }
        ElseIf (($finding -split ("[+:]"))[1].trim(" v") -eq 1.24) {
            $Status = "Not_Applicable"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254559
        STIG ID    : CNTR-R2-000130
        Rule ID    : SV-254559r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes Kubelet must have the read-only port flag disabled.
        DiscussMD5 : B7182AAF88661892F5C911BCE3BFC260
        CheckMD5   : 6AB372C13B3AB1CDE9407E3AFD8D2D2B
        FixMD5     : 50DED6F6A5CB1F26175B39D18232513C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "read-only-port") -split ("="))[1] -eq 0) {
            $FindingMessage = "kubelet --read-only-port is set to 0."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --read-only-port is not set to 0 or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kubelet process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254560 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254560
        STIG ID    : CNTR-R2-000140
        Rule ID    : SV-254560r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes API server must have the insecure bind address not set.
        DiscussMD5 : 1C681A5890D454AC06FD27CBF3098F5B
        CheckMD5   : A22E80C6B0B02222DD5FEDFE5693C6EA
        FixMD5     : 3BECB9B14878A911D2DB304020F843B6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version | Select-String Server
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding -split ("[+:]"))[1].trim(" v") -gt 1.20) {
            $Status = "Not_Applicable"
        }
        Else {
            $finding = "Upgrade to a supported version of RKE2 Kubernetes."
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254561 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254561
        STIG ID    : CNTR-R2-000150
        Rule ID    : SV-254561r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes kubelet must enable explicit authorization.
        DiscussMD5 : 3C23D558EAF12604B16D4C20508C2CAC
        CheckMD5   : AA1181E49F412C83C76083D8E839CB83
        FixMD5     : 981B25E6D7DD1EFB1218FEA7695C30B8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "authorization-mod") -split ("="))[1] -eq "Webhook") {
            $FindingMessage = "kubelet --authorization-mod is set to Webhook."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --authorization-mod is not set to Webhook or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kublet process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254562 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254562
        STIG ID    : CNTR-R2-000160
        Rule ID    : SV-254562r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000100
        Rule Title : The Kubernetes API server must have anonymous authentication disabled.
        DiscussMD5 : EC45C0668655A032A4DB52A74024EF06
        CheckMD5   : 1BE5E19F81CA5635E1FA19E687D12B0A
        FixMD5     : 5EB90ABE8A8CB6C17543475AD49A9BCE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "anonymous-auth") -split ("="))[1] -eq $false) {
            $FindingMessage = "kube-apiserver --anonymous-auth is set to false."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-apiserver --anonymous-auth is not set to false or is not configured."
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "kube-apiserver process not found on system"
    }
    $FindingDetails += $FindingMessage | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254563 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254563
        STIG ID    : CNTR-R2-000320
        Rule ID    : SV-254563r960906_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-CTR-000200
        Rule Title : All audit records must identify any containers associated with the event within Rancher RKE2.
        DiscussMD5 : 4EBD2150B8AC7353654D718FCA8F43C2
        CheckMD5   : AFC537501D329740DE3D57BEC50EBDFF
        FixMD5     : 42E7D26402FE16AC2634962334923229
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If --protect-kernel-defaults argument is not set to "true" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "audit-log-maxage") -split ("="))[1] -ge 30) {
            $FindingMessage = "kube-apiserver --audit-log-maxage is set to 30 or more days."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-apiserver --audit-log-maxage is not set to 30 or more days, or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kube-apiserver process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254564 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254564
        STIG ID    : CNTR-R2-000520
        Rule ID    : SV-254564r1016531_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-CTR-000300
        Rule Title : Configuration and authentication files for Rancher RKE2 must be protected.
        DiscussMD5 : 6CD36A99E7B1D0BE4DCCF1A66B93D1DE
        CheckMD5   : 14B2DFC2619096F972ACFAA93B1F5E95
        FixMD5     : 0CD1E6EDAA82BC3E69915D052377D314
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $found = 0
    $finding = (stat -c "%a %U %G %n" /etc/rancher/rke2/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "600 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /etc/rancher/rke2/"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /etc/rancher/rke2/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/agent/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/*.kubeconfig)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "640" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on kubeconfig files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Permissions are correct on kubeconfig files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/*.crt)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "600" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on crt files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Permissions are correct on crt files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/*.key)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "600" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on key files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Permissions are correct on key files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/pod-manifests/)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "700" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct for /var/lib/rancher/rke2/agent/pod-manifests/"
    }
    Else {
        $FindingMessage = "Permissions are correct for /var/lib/rancher/rke2/agent/pod-manifests/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/etc/)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "700" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct for /var/lib/rancher/rke2/agent/etc/"
    }
    Else {
        $FindingMessage = "Permissions are correct for /var/lib/rancher/rke2/agent/etc/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %U %G %n" /var/lib/rancher/rke2/bin/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "750 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /var/lib/rancher/rke2/bin"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /var/lib/rancher/rke2/bin"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %U %G %n" /var/lib/rancher/rke2/data)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "750 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /var/lib/rancher/rke2/data"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /var/lib/rancher/rke2/data"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/data/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/data"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/data"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %U %G %n" /var/lib/rancher/rke2/data/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "640 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /var/lib/rancher/rke2/data"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /var/lib/rancher/rke2/data"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/server/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/server"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/server/cred /var/lib/rancher/rke2/server/db /var/lib/rancher/rke2/server/tls)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "700" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on cred, db, and tls in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Permissions are correct on cred, db, and tls in /var/lib/rancher/rke2/server"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/server/manifests /var/lib/rancher/rke2/server/logs)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "750" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on manifests and logs in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Permissions are correct on manifests and logs in /var/lib/rancher/rke2/server"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/server/token)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "600" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on token in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Permissions are correct on token in /var/lib/rancher/rke2/server"
    }
    $FindingDetails += $FindingMessage | Out-String

    If (Test-Path '/etc/rancher/rke2/config.yaml') {
        $finding = Get-Content /etc/rancher/rke2/config.yaml
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding | Select-String 'write-kubeconfig-mode') -match '0600') {
            $FindingMessage = '/etc/rancher/rke2/config.yaml contains write-kubeconfig-mode: "0600"'
        }
        Else {
            $found++
            $FindingMessage = '/etc/rancher/rke2/config.yaml does not contain write-kubeconfig-mode: "0600"'
        }
        $FindingDetails += $FindingMessage | Out-String
    }

    If ($found -gt 0) {
        $Status = "Open"
    }
    Else {
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

Function Get-V254565 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254565
        STIG ID    : CNTR-R2-000550
        Rule ID    : SV-254565r960963_rule
        CCI ID     : CCI-000381, CCI-001764
        Rule Name  : SRG-APP-000141-CTR-000315
        Rule Title : Rancher RKE2 must be configured with only essential configurations.
        DiscussMD5 : 111D62C55697089EF7CB91E7C6D8906E
        CheckMD5   : B1B5903D55FA245026E71BF1F3CF188A
        FixMD5     : 15882A526B657F27F6041CE6D2FA15F8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/etc/rancher/rke2/config.yaml') {
        $finding = Get-Content /etc/rancher/rke2/config.yaml
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/config.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254566 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254566
        STIG ID    : CNTR-R2-000580
        Rule ID    : SV-254566r1050657_rule
        CCI ID     : CCI-000382, CCI-001762
        Rule Name  : SRG-APP-000142-CTR-000325
        Rule Title : Rancher RKE2 runtime must enforce ports, protocols, and services that adhere to the PPSM CAL.
        DiscussMD5 : 757FC70698A3F1629DE153FD2FCA0066
        CheckMD5   : 5EA70DACAFBFCEA68043DF439B096A22
        FixMD5     : C773BF117AC2ED4EAF1954740BB14E9A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml') {
        $finding = Select-String "--insecure-port" -Path /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml
        $FindingDetails += "grep kube-apiserver.yaml -I -insecure-port" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = Select-String "--secure-port" -Path /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml
        $FindingDetails += "grep kube-apiserver.yaml -I -secure-port" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = Select-String "--etcd-servers" -Path /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml
        $FindingDetails += "grep kube-apiserver.yaml -I -etcd-servers *" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml"
    }
    If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
        $finding = (/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get po -n kube-system -l component=kube-controller-manager -o=jsonpath="{.items[*].spec.containers[*].args}").split(",") | Select-String "--secure-port", "--etcd-servers", "--insecure-port"
        $FindingDetails += '/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-controller-manager -o=jsonpath="{.items[*].spec.containers[*].args}"' | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = (/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get po -n kube-system -l component=kube-scheduler -o=jsonpath="{.items[*].spec.containers[*].args}").split(",") | Select-String "--secure-port", "--etcd-servers", "--insecure-port"
        $FindingDetails += '/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-scheduler -o=jsonpath="{.items[*].spec.containers[*].args}"' | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = (/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get po -n kube-system -l component=kube-apiserver -o=jsonpath="{.items[*].spec.containers[*].args}").split(",") | Select-String "--secure-port", "--etcd-servers", "--insecure-port"
        $FindingDetails += '/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-apiserver -o=jsonpath="{.items[*].spec.containers[*].args}"' | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254567 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254567
        STIG ID    : CNTR-R2-000800
        Rule ID    : SV-254567r1016559_rule
        CCI ID     : CCI-000196, CCI-004062
        Rule Name  : SRG-APP-000171-CTR-000435
        Rule Title : Rancher RKE2 must store only cryptographic representations of passwords.
        DiscussMD5 : B4574D9C97E80AF015C00153E09EA136
        CheckMD5   : 17B826DD0EB61DAB069C8107A57BAE5C
        FixMD5     : 71F1BAF58EADDB098AA503E6911F8E43
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods -A
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get pods -A" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get jobs -A
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get jobs -A" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get cronjobs -A
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get cronjobs -A" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254568 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254568
        STIG ID    : CNTR-R2-000890
        Rule ID    : SV-254568r1016534_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-APP-000190-CTR-000500
        Rule Title : Rancher RKE2 must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after five minutes of inactivity.
        DiscussMD5 : BA39C5BB6D3444F2FC3598B9D9F0BA34
        CheckMD5   : 432AF40F2F8E2B02DC66D1CB68D8FED6
        FixMD5     : A8AEE499179E94F2F7F2E4E274B2973F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If --treaming-connection-idle-timeout argument is not set to "true" or is not configured, this is a finding.
        If ((($finding.split(" ") -match "streaming-connection-idle-timeout") -split ("="))[1] -le "5m") {
            $FindingMessage = "kubelet --treaming-connection-idle-timeout is set to 5 minutes or less."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --treaming-connection-idle-timeout is not set to 5 minutes or less, or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kublet process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254569 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254569
        STIG ID    : CNTR-R2-000940
        Rule ID    : SV-254569r1016537_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-CTR-000585
        Rule Title : Rancher RKE2 runtime must isolate security functions from nonsecurity functions.
        DiscussMD5 : AE77B63CBCEBB4084D5CA85E934B5E55
        CheckMD5   : 19043A769546ACAB07FD7ABD749FADF2
        FixMD5     : 0D89A373E8F560A61DAF74C80D505558
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") -match "protect-kernel-defaults") -split ("="))[1] -eq $true) {
            $FindingMessage = "kubelet --protect-kernel-defaults is set to true."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --protect-kernel-defaults is not set to true or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kublet process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254570 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254570
        STIG ID    : CNTR-R2-000970
        Rule ID    : SV-254570r1016539_rule
        CCI ID     : CCI-001082, CCI-001090, CCI-002530
        Rule Name  : SRG-APP-000243-CTR-000600
        Rule Title : Rancher RKE2 runtime must maintain separate execution domains for each container by assigning each container a separate address space to prevent unauthorized and unintended information transfer via shared system resources.
        DiscussMD5 : 92721D033F360E1A438D12850166F246
        CheckMD5   : 9F850FE4B41649F2134BD83216309905
        FixMD5     : FF8AB163E09B64022B017D45CA4EC24F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get namespaces
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get namespaces" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n default -o name
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get all -n default" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n kube-public -o name
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get all -n kube-public" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n kube-node-lease -o name
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get all -n kube-node-lease" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n kube-system -o name
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get all -n kube-system" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254571 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254571
        STIG ID    : CNTR-R2-001130
        Rule ID    : SV-254571r961353_rule
        CCI ID     : CCI-002233, CCI-002235
        Rule Name  : SRG-APP-000340-CTR-000770
        Rule Title : Rancher RKE2 must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
        DiscussMD5 : 1CE0BBEF15311450459C8F6650673A23
        CheckMD5   : 5F1EFB09BE266BA9EC6BBAC7420741BD
        FixMD5     : A5AAE0EB3695C744DE83CBF5CC0A15C7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version | Select-String Server
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding -split ("[+:]"))[1].trim(" v") -le 1.24) {
            $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get podsecuritypolicy
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $Status = "Not_Reviewed"
        }
        Else {
            If (Test-Path '/etc/rancher/rke2/rke2-pss.yaml') {
                $finding = Get-Content /etc/rancher/rke2/rke2-pss.yaml
                $FindingDetails += $(FormatFinding $finding) | Out-String
                If (($finding | grep defaults: -A 6).replace(" ", "") -join '' -eq 'defaults:enforce:"restricted"enforce-version:"latest"audit:"restricted"audit-version:"latest"warn:"restricted"warn-version:"latest"') {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
            Else {
                $FindingDetails += "system does not have a /etc/rancher/rke2/rke2-pss.yaml"
            }
        }
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254572
        STIG ID    : CNTR-R2-001270
        Rule ID    : SV-254572r1016560_rule
        CCI ID     : CCI-001812, CCI-003980
        Rule Name  : SRG-APP-000378-CTR-000880
        Rule Title : Rancher RKE2 must prohibit the installation of patches, updates, and instantiation of container images without explicit privileged status.
        DiscussMD5 : A618710D7C1F4AE0B637343C785C2FE9
        CheckMD5   : BB95E3CCC3BB442F027EE80FB28CD010
        FixMD5     : FFF81CEE1F95D49A466C40E401203622
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If  --authorization-mode is not set to "RBAC,Node" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "authorization-mode") -split ("="))[1] -eq "RBAC,Node") {
            $FindingMessage = "kube-scheduler --authorization-mode is set to RBAC,Node."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-scheduler --authorization-mode is not set to RBAC,Node or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kube-apiserver process not found on system"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254573 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254573
        STIG ID    : CNTR-R2-001500
        Rule ID    : SV-254573r1050650_rule
        CCI ID     : CCI-002476
        Rule Name  : SRG-APP-000429-CTR-001060
        Rule Title : Rancher RKE2 keystore must implement encryption to prevent unauthorized disclosure of information at rest within Rancher RKE2.
        DiscussMD5 : 6CAC83AFA7436D654D8ADC95A3F2FDDD
        CheckMD5   : 6B894823E0360C47979C41DCC875CE92
        FixMD5     : 6E32D7DBFD5F33F46F8B26006508E1C9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ((/var/lib/rancher/rke2/bin/kubectl version -o json | ConvertFrom-Json).serverVersion.gitVersion -lt 1.20) {
        If (Test-Path "/var/lib/rancher/rke2/server/cred/encryption-config.json") {
            $finding = Get-Content /var/lib/rancher/rke2/server/cred/encryption-config.json
            $FindingDetails += $(FormatFinding $finding)
        }
        Else {
            $FindingDetails += "system does not have a /var/lib/rancher/rke2/server/cred/encryption-config.json"
        }
        #Ensure the RKE2 configuration file on all RKE2 servers, located at /etc/rancher/rke2/config.yaml, does NOT contain: secrets-encryption: false
        If (Test-Path '/etc/rancher/rke2/config.yaml') {
            $finding = Select-String -Path /etc/rancher/rke2/config.yaml -Pattern "secrets-encryption: false"
            If ($finding) {
                $Status = "Open"
                $FindingDetails += $finding | Out-String
            }
            Else {
                $Status = "NotAFinding"
                $FindingDetails += "/etc/rancher/rke2/config.yaml, does NOT contain secrets-encryption: false"
            }
        }
        Else {
            $FindingDetails += "system does not have a /etc/rancher/rke2/config.yaml"
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "This is Not Applicable for RKE2 versions 1.20 and greater."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254574 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254574
        STIG ID    : CNTR-R2-001580
        Rule ID    : SV-254574r961677_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-APP-000454-CTR-001110
        Rule Title : Rancher RKE2 must remove old components after updated versions have been installed.
        DiscussMD5 : 12D3E83936A3FF5AC511113EEABF02EF
        CheckMD5   : C84840A81D68C4B3AF3EE3ECEB89CE7D
        FixMD5     : E31CE520DBA1C86D6FC50049C4F015B2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path '/etc/rancher/rke2/rke2.yaml') {
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods --all-namespaces -o jsonpath="{..image}" | tr -s '[[:space:]]' '\n' | Sort-Object | uniq -c
        $FindingDetails += $finding | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V254575 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254575
        STIG ID    : CNTR-R2-001620
        Rule ID    : SV-254575r961683_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-CTR-001125
        Rule Title : Rancher RKE2 registry must contain the latest images with most recent updates and execute within Rancher RKE2 runtime as authorized by IAVM, CTOs, DTMs, and STIGs.
        DiscussMD5 : 690B2699C1501789FF62C86E2354D88A
        CheckMD5   : C5DBDDF1BDC00C3666798AE3983BFD16
        FixMD5     : F9EE341C102013B756A52F558A77FE80
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path "/etc/rancher/rke2/rke2.yaml") {
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes
        $FindingDetails += "/var/lib/rancher/rke2/bin/kubectl get nodes" | Out-String
        $FindingDetails += $finding | Out-String
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].image}" | tr -s '[[:space:]]' '\n' | Sort-Object | uniq -c
        $FindingDetails += $finding | Out-String
    }
    Else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAl/dBKANpkupNt
# CV00aPUt5Bv+SzZPEevNU+h4ThgDXqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCBF279iKdHNS3GmoX+ajfclSZGM2nZ9Wf1GhLi5/QyLnTANBgkqhkiG9w0BAQEF
# AASCAQCMNNGSRMc3oD7oCNKmpM6a3cAOqkM89B98TPNlWJ2zYejWM8ZCUBEqqExR
# sKWnryLWaSODXOtulMhgfk12M8pHapvZK8TRsu7uEDlwwhkFQefvRi7qUooIo80d
# 5Q8hV62VJSPEo7KU5aIDvtuwPsI/sToKwg83/6Sn2ddoWs4Ycxs+u2zS+fv3gG/R
# ANw7uBuW0DEQmaSZSuJQMwxqFBxuNhm1+xEI2c2wOJqIQLrJQCHgc8EZnU32V+ZC
# o0l604WVErZl8UN4HLCzGWBX0hREM3i8QAFBTeryhmoxbnehZE8BbU5OXXPtZf63
# oLPIrM0rD2E9AvaaMxBEK1T2FLCvoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAwMTE2NTc0M1owLwYJKoZIhvcNAQkEMSIEIOxtA8saT3rGtI9F1QjdOtvkXeK6
# vrlAnBPj22Bi6ibjMA0GCSqGSIb3DQEBAQUABIICAGQxyYu5yIp0J+ppZSCyWjtC
# 1CCtI4l2uPmRGZfgeu3VNQAt3IWnf0w3tk4Oeb9+i/hX+oOPRXJIqM5hHYGl3O/v
# OCtqH1vzbV34EBFWe2Wy6KOkxznQv3sUmWR8smNLJGPsIngPPyciwPWXxCDUVol4
# z3OzLGSjRt0R+mIp1DrHepi+36Ja+Vh4OaeC5x4txZH1A3MSGZUZa5COvmf3EfTr
# IOrYhRnLIvNjGAX4c4t2rg8A2k0U5NJAq41ZT7QX70J+6T/rUf7JnR5wl8Blxjq+
# 5vsGo37qcSD2TYvS69gFs8HySW7MF4PyZVIVZ03G9Ejlk898YqvMLYxSvxCIPFU8
# GiICI5CrrrCFVVwkuIjejpct9Y+Sk9SMJ90brkWU2rsK+bOP2VQC4aHhF8MTWnr/
# vcSJSImO+toJXv7vk9x/7vcKNZBN/0+dMilcoWAfSAv3CWVXhyw3cqpYG0z+W40P
# 0UPHgTHQ5lEE/CSZnE+UtQBfk8KnNrKIFobuRss3jchqvFQrLqk3VlaoN40y0DC1
# tOy5UBrl46hTSSu6bU6gpfUN6kwaeT9IYxKYC2K7MRo6GcZn/P9mjZgt6aLUUPmy
# yicqerusBpSg131kHOa8J4QhT4IanQ+xoJldFixw9ZFERzayqlKUEOFrwhcQs3q7
# g3dwoU64aVWwYfGWE3vK
# SIG # End signature block
