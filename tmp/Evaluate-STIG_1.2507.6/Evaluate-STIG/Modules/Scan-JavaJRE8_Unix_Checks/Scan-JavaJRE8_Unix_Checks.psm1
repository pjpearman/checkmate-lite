##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Java Runtime Environment (JRE) version 8
# Version:  V1R3
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Format-JavaPath {
    # https://en.wikipedia.org/wiki/File_URI_scheme
    # https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("deployment.properties", "exception.sites")]
        [String]$JavaFile
    )

    $Result = New-Object System.Collections.Generic.List[System.Object]
    $Pass = $true

    $WorkingPath = $Path -replace "\\{5,}", "///" -replace "\\{4}", "//" -replace "\\{3}", "/" -replace "\\{2}", "/" -replace "\\{1}", ""

    Switch ($JavaFile) {
        "deployment.properties" {
            # Java variables don't appear to work for deployment.properties path
            If ($WorkingPath -like '*$SYSTEM_HOME*' -or $WorkingPath -like '*$USER_HOME*' -or $WorkingPath -like '*$JAVA_HOME*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites cannot include a variable.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            ElseIf ($WorkingPath -notlike 'file:*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites must start with proper 'file:' format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            Else {
                Switch -Regex ($WorkingPath) {
                    # Local path patterns
                    "^file:/{1}[A-Za-z0-9]" {
                        # 'file:/<local path>'
                        $Formatted = $WorkingPath -replace "file:", ""
                    }
                    "^file:/{3}[A-Za-z0-9]" {
                        # 'file:///<local path>'
                        $Formatted = $WorkingPath -replace "file:/{3}", "/"
                    }
                    # UNC path pattern
                    "^file:/{2}[A-Za-z0-9]" {
                        # 'file://<server>'
                        $Formatted = $WorkingPath -replace "file:", ""
                        If ($Formatted -match ":") {
                            $Pass = $false
                        }
                    }
                    # Dynamic pattern
                    "^file:/{4,}[A-Za-z0-9]" {
                        # 'file:////<server or drive letter>' (4 or more slashes)
                        $Formatted = $WorkingPath -replace "file:/{5,}", "////"
                    }
                    Default {
                        $Pass = $false
                        $Formatted = "Path to deployment.properites is invalid format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
                    }
                }
            }
        }
        "exception.sites" {
            If ($WorkingPath -like '*$SYSTEM_HOME*') {
                $WorkingPath = $WorkingPath.Replace('$SYSTEM_HOME', '/etc/.java/deployment')
            }
            Switch -Regex ($WorkingPath) {
                # Local path patterns
                "^/{1}[A-Za-z0-9]" {
                    # '/<local path>'
                    $Formatted = $WorkingPath
                }
                # Dynamic pattern
                "^/{2,}[A-Za-z0-9]" {
                    # '//<server or drive letter>' (2 or more slashes)
                    $Formatted = $WorkingPath -replace "/{2,}", "//"
                }
                Default {
                    $Pass = $false
                    $Formatted = "Path to exception.sites is an invalid format."
                }
            }
        }
    }

    $NewObj = [PSCustomObject]@{
        Pass       = $Pass
        Configured = $Path
        Working    = $WorkingPath
        Formatted  = $Formatted
    }
    $Result.Add($NewObj)

    Return $Result
}

Function Get-V66721 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66721
        STIG ID    : JRE8-UX-000010
        Rule ID    : SV-81211r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.config file present.
        DiscussMD5 : 91D4281474ED54A1748E785FA85518E9
        CheckMD5   : C4E54062304601F2AEF1E046046CEE72
        FixMD5     : E9F14D23BA1A89A8AD861D2D8E931DAB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If (Test-Path $ConfigFile) {
        $Status = "NotAFinding"
        $FindingDetails += "The following config file was found:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $ConfigFile | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V66909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66909
        STIG ID    : JRE8-UX-000020
        Rule ID    : SV-81399r2_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 deployment.config file must contain proper keys and values.
        DiscussMD5 : 8FB93155C9BB13C1B3634DD0F84DDDE2
        CheckMD5   : A55825EB652B461B5D8E6FF5FB3E0962
        FixMD5     : CC78F18EAAA8CBB5565F9626D08B0610
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.system.config=", `
        "deployment.system.config.mandatory=true"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $Option1Set = $false
        $Option2Set = $false
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        $FindingDetails += "" | Out-String
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "$($KeysToEval[0])*") {
                $Option1Set = $true
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    ElseIf ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        $FindingDetails += "$Line is present" | Out-String
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
            }
            ElseIf (($Line -Replace "\s", "") -eq $KeysToEval[1]) {
                $Option2Set = $true
                $FindingDetails += "$Line is present" | Out-String
            }
        }

        If ($Option1Set -eq $false) {
            $Compliant = $false
            $FindingDetails += "Path to 'deployment.properties' is NOT present" | Out-String
        }
        ElseIf ($Option2Set -eq $false) {
            $Compliant = $false
            $FindingDetails += "deployment.system.config.mandatory=true is NOT present" | Out-String
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

Function Get-V66911 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66911
        STIG ID    : JRE8-UX-000030
        Rule ID    : SV-81401r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.properties file present.
        DiscussMD5 : 588666C94B5F3D39746B984449C6E6D5
        CheckMD5   : EF858FBA3D142B1779B49366FE514C55
        FixMD5     : EDDD2479375CEB9BB512D1D98FE2AB8B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $FindingDetails += "Properties file exists in the path defined." | Out-String
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
        }
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

Function Get-V66913 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66913
        STIG ID    : JRE8-UX-000060
        Rule ID    : SV-81403r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must default to the most secure built-in setting.
        DiscussMD5 : 61476BE2840E85A7AA739C3F90814373
        CheckMD5   : D6334D52C7D46EF33A9AF0500535A654
        FixMD5     : 81DEE608C012C410673FBF4AEA881EBC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.security.level=VERY_HIGH", `
        "deployment.security.level.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
        }
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

Function Get-V66915 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66915
        STIG ID    : JRE8-UX-000070
        Rule ID    : SV-81405r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must be set to allow Java Web Start (JWS) applications.
        DiscussMD5 : 5DEE22E2DE37260B37F6F641CDFAE90C
        CheckMD5   : 681BC1FD9BDA1230E8A61C7C21C88892
        FixMD5     : 11C9D913495619013FAE2442026F7C96
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.webjava.enabled=true", `
        "deployment.webjava.enabled.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
        }
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

Function Get-V66917 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66917
        STIG ID    : JRE8-UX-000080
        Rule ID    : SV-81407r1_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must disable the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
        DiscussMD5 : 884B69274C3B7E49843DC681FC28341A
        CheckMD5   : 0440BF8BB57507D02C51FA7923DECC7D
        FixMD5     : 325309F86E188AF4F54199F77AAF31FF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.askgrantdialog.notinca=false", `
            "deployment.security.askgrantdialog.notinca.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66919 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66919
        STIG ID    : JRE8-UX-000090
        Rule ID    : SV-81409r1_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must lock the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
        DiscussMD5 : CF669DA14A24210AF51C2FEB68300BBC
        CheckMD5   : 8C14F6145C7192D65BEB9E8C1D450F7D
        FixMD5     : 7B5BB65067CB648832EC4C0FD3B84BB2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.askgrantdialog.show=false", `
            "deployment.security.askgrantdialog.show.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66921 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66921
        STIG ID    : JRE8-UX-000100
        Rule ID    : SV-81411r1_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Oracle JRE 8 must set the option to enable online certificate validation.
        DiscussMD5 : A49775A6E44134FD46FF4732407BF5FB
        CheckMD5   : EC84F58A66EA4580C5FC4A38D4A2DCAF
        FixMD5     : 9F8170004F58D4AEEA94FBA1FD9A22F1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.validation.ocsp=true", `
            "deployment.security.validation.ocsp.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66923 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66923
        STIG ID    : JRE8-UX-000110
        Rule ID    : SV-81413r1_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : Oracle JRE 8 must prevent the download of prohibited mobile code.
        DiscussMD5 : CEC79E03E4228BD7547CB3EBAB995CA3
        CheckMD5   : 78C60C93923FABA5BFD79739E2A18CDD
        FixMD5     : 3999EBFF2A891ADAEDED7A9C7190DE07
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.security.blacklist.check=true", `
        "deployment.security.blacklist.check.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
        }
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

Function Get-V66925 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66925
        STIG ID    : JRE8-UX-000120
        Rule ID    : SV-81415r2_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must enable the option to use an accepted sites list.
        DiscussMD5 : F07373721D4DC99C769562427B1C6F3B
        CheckMD5   : 55BC64EBF4CFDAE753B1D0F8FF7500E4
        FixMD5     : ECC649E6493D45B1ABF568289B294A63
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.user.security.exception.sites"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($DeployFileContent -match $Key) {
                                ForEach ($Line in $DeployFileContent) {
                                    If ($Line -like "$($KeysToEval)*") {
                                        $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                        Break
                                    }
                                }
                                If ($ExceptionPath) {
                                    $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                    If ($ExceptionFile.Pass -ne $true) {
                                        $Compliant = $false
                                        $FindingDetails += "$Line" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += $ExceptionFile.Formatted | Out-String
                                    }
                                    ElseIf ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                        $Compliant = $false
                                        $FindingDetails += "$Line" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "$Key does not point to an 'exception.sites' file." | Out-String
                                    }
                                    Else {
                                        $FindingDetails += "$Line is present" | Out-String
                                    }
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Line" | Out-String
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Path to 'exception.sites' file is not defined in properties file." | Out-String
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
        }
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

Function Get-V66927 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66927
        STIG ID    : JRE8-UX-000130
        Rule ID    : SV-81417r1_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must have an exception.sites file present.
        DiscussMD5 : F07373721D4DC99C769562427B1C6F3B
        CheckMD5   : F071BC4DA9172CC248A012337EF8A102
        FixMD5     : D24B0D67013B5A3E18908526549F8D27
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.user.security.exception.sites"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($DeployFileContent -match $Key) {
                                    ForEach ($Line in $DeployFileContent) {
                                        If ($Line -like "$($KeysToEval)*") {
                                            $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                            Break
                                        }
                                    }
                                    If ($ExceptionPath) {
                                        $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                        If ($ExceptionFile.Pass -ne $true) {
                                            $Compliant = $false
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "$Line" | Out-String
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += $ExceptionFile.Formatted | Out-String
                                        }
                                        Else {
                                            $FindingDetails += "Exception File:`t`t$($ExceptionFile.Configured)" | Out-String
                                            $FindingDetails += "" | Out-String
                                            If ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                                $Compliant = $false
                                                $FindingDetails += "$Key does not point to an 'exception.sites' file." | Out-String
                                            }
                                            Else {
                                                If (Test-Path $ExceptionFile.Formatted) {
                                                    $FindingDetails += "Exception file exists in the path defined." | Out-String
                                                }
                                                Else {
                                                    $Compliant = $false
                                                    $FindingDetails += "Exception file not found in the path defined." | Out-String
                                                }
                                            }
                                        }
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "Path to 'exception.sites' file is not defined in properties file." | Out-String
                                    }
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66929 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66929
        STIG ID    : JRE8-UX-000150
        Rule ID    : SV-81419r1_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000401
        Rule Title : Oracle JRE 8 must enable the dialog to enable users to check publisher certificates for revocation.
        DiscussMD5 : C3D8C5511483BF09893323791B8DFE96
        CheckMD5   : 71F37CA63D6799FEC5EDB410DFF45FDB
        FixMD5     : A78D21DCB7FF170922F19D4C1C03609E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.validation.crl=true", `
            "deployment.security.validation.crl.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66931 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66931
        STIG ID    : JRE8-UX-000160
        Rule ID    : SV-81421r1_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000401
        Rule Title : Oracle JRE 8 must lock the option to enable users to check publisher certificates for revocation.
        DiscussMD5 : 641C7784614699CE2C93D8CA2E495B55
        CheckMD5   : 1176EB32C94023E5D1CDFD508D83A2EB
        FixMD5     : 6104CC5D40C2B234D2D0AA6589008344
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.revocation.check=ALL_CERTIFICATES", `
            "deployment.security.revocation.check.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66933 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66933
        STIG ID    : JRE8-UX-000170
        Rule ID    : SV-81423r1_rule
        CCI ID     : CCI-002460
        Rule Name  : SRG-APP-000488
        Rule Title : Oracle JRE 8 must prompt the user for action prior to executing mobile code.
        DiscussMD5 : EB406C03E21F7D1CBE591AA7FDC219DE
        CheckMD5   : F551C7A3701972DBCFDAA2C0CDBFF1FC
        FixMD5     : 201AB606A1B0DED343C7258E70D23E93
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.insecure.jres=PROMPT", `
        "deployment.insecure.jres.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
        }
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

Function Get-V66937 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66937
        STIG ID    : JRE8-UX-000180
        Rule ID    : SV-81427r1_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The version of Oracle JRE 8 running on the system must be the most current available.
        DiscussMD5 : 1A65A3F13B756E1A1094EFEA1913C357
        CheckMD5   : 7072FDA515397EA01DD65078489A9562
        FixMD5     : C276CB234E7261A6644215C1898FC872
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Result = Start-ProcessWithOutput -FileName "java" -Arguments "-version"
    $JavaVer = $Result.StdErr
    $FindingDetails += $JavaVer | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAbRgXYdffpNzMr
# NmLrSatmWbrfp43IWkwCGMWR2dJ7tKCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDvuxOcL4jeaTkd2QQLP1UJL2bSxJ4fdqNuZIHqyD4LpTANBgkqhkiG9w0BAQEF
# AASCAQAQPnlFZG/p91RuDqk55+aRqNVqmg3/KRTaWGMBrr6QZJW0LCwshord+nPD
# 8DH4QRUBflZwyCVrW1ljHQWDkP1r5HZ+lxojKcqn+xiuMlXimFW+S4dgaZI02ihj
# zemY9DspuVFWyLQsmScsGwOXsY3Hl3/cvJDRXLmtmuLAU5fLYmHOuVlbw+wbuhUZ
# 4/LZBZXxmIxWOQ7AgflHoeA8gjSNj2PxhujivY5+2+RVI9xneMRqYVC+P9OAOJEX
# d6tbPXRQhlg5TubWw0qqjhGuVpDzEhbXqJ8I0ocWl7QQXlsiYwhk2cMIZXkmn4yo
# H80rtuGCjIi1SdSzfeLfSBZqcW6eoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTUzNVowLwYJKoZIhvcNAQkEMSIEIGyG3foz1HeuSmfN6omV1aW2Elml
# SvAp/qgw1OW+3C7bMA0GCSqGSIb3DQEBAQUABIICAHGokDzOPpA8xuy8yGBukObV
# TRBBW9Pkm37l49WT/QLjU2N8mB4VP6Jp5M6zLRXoXv6k1r6Ns34veiVkjYCJ3siT
# WqMW0SLDga9//20Y72lpBhPZtXgUr1cerKF39swVUl39AwqLM3nzstbHqUs12lBB
# nagbLqXGK0UP0NaQP0aHCNiHWA++yXWedDCoOwGf7pFpS07MMZY5pxxovH0ts+ve
# EG/gmKo+DQjgMQNsb5dudvzU+aBQSGwmRMBWBO+BbP4n6XIcAxtgl/Vn/EhJCPzk
# tSmPUb7ZzLhP1613OkQ6Qr8Mi27R+3tFvv2Wz/dQK6GW51jpS4KMchnT8ljT0Z/F
# 5JMWobroM0zQGczBAJcGrnDjXDJxG8qecXOl9VcjvC6w77hVmUaSUwc3Umu5+nmP
# PeB+c2fpmNfpvLFv4W4H0Pwe+MEvcKiixyF2fpfMd/ixd2Frl2sH+qvWxhQ33jA9
# M+V7oBD+RiSaWwI+cijfKeh91cl5zeCDNkuFWcHhpg7VU9tOkGCsIU8/ku+67XJ4
# yV8EMwIbAmBiAriGpKg1Y+Z5JCy8SW7I6FV40YZaf3gZG29BuYnXEPQqMhcOFHa4
# FvKDmu7ezyjYsv4E4Srh3JMR9i3hAlLbJdeaLvSaUL2Z9m5EmQwqQ5SuHbSUF3In
# vmaD26lBbal63RCQdBVO
# SIG # End signature block
