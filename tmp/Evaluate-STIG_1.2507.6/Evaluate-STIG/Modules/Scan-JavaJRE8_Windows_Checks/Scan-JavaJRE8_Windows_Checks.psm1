##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Oracle Java Runtime Environment (JRE) Version 8 for Windows
# Version:  V2R1
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

function Format-JavaPath {
    # https://en.wikipedia.org/wiki/File_URI_scheme
    # https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html
    param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("deployment.properties", "exception.sites")]
        [String]$JavaFile
    )

    $Result = New-Object System.Collections.Generic.List[System.Object]
    $Pass = $true

    $WorkingPath = $Path -replace "\\{5,}", "///" -replace "\\{4}", "//" -replace "\\{3}", "/" -replace "\\{2}", "/" -replace "\\{1}", ""

    switch ($JavaFile) {
        "deployment.properties" {
            # Java variables don't appear to work for deployment.properties path
            if ($WorkingPath -like '*$SYSTEM_HOME*' -or $WorkingPath -like '*$USER_HOME*' -or $WorkingPath -like '*$JAVA_HOME*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites cannot include a variable.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            elseif ($WorkingPath -notlike 'file:*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites must start with proper 'file:' format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            else {
                switch -Regex ($WorkingPath) {
                    # Local path patterns
                    "^file:[A-Za-z]:{1}" {
                        # 'file:C:'
                        $Formatted = $WorkingPath -replace "file:", ""
                    }
                    "^file:/{1}[A-Za-z]:{1}" {
                        # 'file:/C:'
                        $Formatted = $WorkingPath -replace "file:/{1}", ""
                    }
                    "^file:/{3}[A-Za-z]:{1}" {
                        # 'file:///C:'
                        $Formatted = $WorkingPath -replace "file:/{3}", ""
                    }
                    # UNC path pattern
                    "^file:/{2}[A-Za-z0-9]" {
                        # 'file://<server>'
                        $Formatted = $WorkingPath -replace "file:", ""
                        if ($Formatted -match ":") {
                            $Pass = $false
                        }
                    }
                    # Dynamic pattern
                    "^file:/{4,}[A-Za-z0-9]" {
                        # 'file:////<server or drive letter>' (4 or more slashes)
                        if ($WorkingPath -match "file:/{4,}[A-Za-z]:") {
                            # Drive letter detected
                            $Formatted = $WorkingPath -replace "file:/{4,}", ""
                        }
                        else {
                            # No drive letter detected so UNC
                            $Formatted = $WorkingPath -replace "file:/{4,}", "//"
                        }
                    }
                    default {
                        $Pass = $false
                        $Formatted = "Path to deployment.properites is invalid format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
                    }
                }
            }
        }
        "exception.sites" {
            if ($WorkingPath -like '*$SYSTEM_HOME*') {
                $WorkingPath = $WorkingPath.Replace('$SYSTEM_HOME', $("$($env:SystemRoot.Replace("\","/"))/Sun/Java/Deployment"))
            }
            switch -Regex ($WorkingPath) {
                # Local path patterns
                "^[A-Za-z]:{1}" {
                    # 'C:'
                    $Formatted = $WorkingPath
                }
                "^/{1}[A-Za-z]:{1}" {
                    # '/C:'
                    $Formatted = $WorkingPath -replace "/{1}", ""
                }
                # Dynamic pattern
                "^/{2,}[A-Za-z0-9]" {
                    # '//<server or drive letter>' (2 or more slashes)
                    if ($WorkingPath -match "/{2,}[A-Za-z]:") {
                        # Drive letter detected
                        $Formatted = $WorkingPath -replace "/{2,}", ""
                    }
                    else {
                        # No drive letter detected so UNC
                        $Formatted = $WorkingPath -replace "/{2,}", "//"
                    }
                }
                default {
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

    return $Result
}

function Get-JreInstallPath {
    $JrePath = @()
    $ExpandedPaths = @()
    if (Test-Path 'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment\1.8') {
        $JrePath += Get-ChildItem "HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment\" -Recurse | Where-Object { ($_.Name -match "1\.8") -and ($_.Property -match "INSTALLDIR") } | ForEach-Object { Get-ItemPropertyValue -Path $_.PsPath -Name "INSTALLDIR" }
    }
    if (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment\1.8') {
        $JrePath += Get-ChildItem "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment\" -Recurse | Where-Object { ($_.Name -match "1\.8") -and ($_.Property -match "INSTALLDIR") } | ForEach-Object { Get-ItemPropertyValue -Path $_.PsPath -Name "INSTALLDIR" }
    }

    Get-InstalledSoftware | Where-Object DisplayName -Like "Java 8*" | ForEach-Object {
        if ($_.InstallLocation) {
            $JrePath += $_.InstallLocation
        }
    }

    foreach ($Path in ($JrePath)) {
        $ExpandedPaths += (Get-Item $Path).FullName
    }

    return $ExpandedPaths | Select-Object -Unique
}

function Test-ConfigFile {
    $Result = New-Object System.Collections.Generic.List[System.Object]
    $ResultText = @()
    $Compliant = $true
    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $JREPaths = Get-JreInstallPath
    $PathsToEval += $JREPaths | ForEach-Object {return $_ + "Lib\"}
    $ConfigFiles = @()
    foreach ($Path in ($PathsToEval | Sort-Object -Descending)) {
        if (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $ResultText += "Java JRE 8 Install Paths:"
    foreach ($JREPath in $JREPaths) {
        $ResultText += " - $($JREPath)"
    }
    $ResultText += ""

    if (-not($ConfigFiles)) {
        $Compliant = $false
        $ResultText += "No deployment.config file found - FINDING"
    }
    else {
        $ResultText += "Config file status:"
        # Check for Windows deployment.config
        if ("$env:windir\Sun\Java\Deployment\deployment.config" -in $ConfigFiles.FullName) {
            $WindowsJREConfig = $true
            $ResultText += " - $env:windir\Sun\Java\Deployment\deployment.config - Found"
        }
        else {
            $WindowsJREConfig = $false
            $ResultText += " - $env:windir\Sun\Java\Deployment\deployment.config - Not Found"
        }

        # Check for JRE install deployment.config
        foreach ($JREPath in $JREPaths) {
            if ($ConfigFiles.FullName -like "$($JREPath)*") {
                $ResultText += " - $JREPath\lib\deployment.config - Found"
            }
            else {
                if ($WindowsJREConfig -ne $true) {
                    $Compliant = $false
                    $ResultText += " - $JREPath\lib\deployment.config - Not Found - FINDING"
                }
                else {
                    $ResultText += " - $JREPath\lib\deployment.config - Not Found - Using $env:WINDIR config file"
                }
            }
        }
    }
    $NewObj = [PSCustomObject]@{
        Compliant   = $Compliant
        ConfigFiles = $ConfigFiles
        ResultText  = $ResultText
    }
    $Result.Add($NewObj)

    return $Result
}

function Get-V234683 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234683
        STIG ID    : JRE8-WN-000010
        Rule ID    : SV-234683r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.config file present.
        DiscussMD5 : 9818E1EA7EECA4B3BD524ED5B2EEEC58
        CheckMD5   : FF4729117E5666B70713BE75F7FEC6F6
        FixMD5     : 616E11652FD1B9DA6AA094820F1EE7B1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234684 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234684
        STIG ID    : JRE8-WN-000020
        Rule ID    : SV-234684r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 deployment.config file must contain proper keys and values.
        DiscussMD5 : 8FB93155C9BB13C1B3634DD0F84DDDE2
        CheckMD5   : D0E2F44955928C45651341C1B0A4307F
        FixMD5     : 24AAF789E785C2C58A3DC0E11C7EFAE3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "------------------------------------------" | Out-String

    $KeysToEval = "deployment.system.config=", `
        "deployment.system.config.mandatory=true"

    if (-not($ConfigResult.ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found - FINDING" | Out-String
    }
    else {
        foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
            $Option1Set = $false
            $Option2Set = $false
            $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
            $FindingDetails += "" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
            if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            else {
                $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                foreach ($Line in $ConfigFileContent) {
                    if (($Line -replace "\s", "") -like "$($KeysToEval[0])*") {
                        $Option1Set = $true
                        if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                            $PropsPath = ($Line.Split("=")[1]).Trim()
                        }
                        if ($PropsPath) {
                            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                            if ($PropsFile.Pass -ne $true) {
                                $Compliant = $false
                                $FindingDetails += "$Line" | Out-String
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "$($PropsFile.Configured) - FINDING" | Out-String
                            }
                            elseif ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                                $Compliant = $false
                                $FindingDetails += "$Line" | Out-String
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                            }
                            else {
                                $FindingDetails += "$Line is present" | Out-String
                            }
                        }
                        else {
                            $Compliant = $false
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                        }
                    }
                    elseif (($Line -replace "\s", "") -eq $KeysToEval[1]) {
                        $Option2Set = $true
                        $FindingDetails += "$Line is present" | Out-String
                    }
                }

                if ($Option1Set -eq $false) {
                    $Compliant = $false
                    $FindingDetails += "Path to 'deployment.properties' is NOT present - FINDING" | Out-String
                }
                elseif ($Option2Set -eq $false) {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config.mandatory=true is NOT present - FINDING" | Out-String
                }
            }
            $FindingDetails += "------------------------------------------" | Out-String
        }
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234685 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234685
        STIG ID    : JRE8-WN-000030
        Rule ID    : SV-234685r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.properties file present.
        DiscussMD5 : 588666C94B5F3D39746B984449C6E6D5
        CheckMD5   : 9E5CA877CB4BF5114A763616C17A6EC3
        FixMD5     : 5285A3A0AD25A1377B2C103E30555390
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "------------------------------------------" | Out-String

    if (-not($ConfigResult.ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found - FINDING" | Out-String
    }
    else {
        foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
            $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
            if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                foreach ($Line in $ConfigFileContent) {
                    if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        break
                    }
                }
                if ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    if ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$($PropsFile.Configured) - FINDING" | Out-String
                    }
                    else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                        }
                        else {
                            if (Test-Path $PropsFile.Formatted) {
                                $FindingDetails += "Properties file exists in the path defined." | Out-String
                            }
                            else {
                                $Compliant = $false
                                $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                            }
                        }
                    }
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                }
            }
            $FindingDetails += "------------------------------------------" | Out-String
        }
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234686 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234686
        STIG ID    : JRE8-WN-000060
        Rule ID    : SV-234686r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must default to the most secure built-in setting.
        DiscussMD5 : 61476BE2840E85A7AA739C3F90814373
        CheckMD5   : 4E1BE6FB8538E4CD45764ACED10D661E
        FixMD5     : 4FAE488F6C2251EC3DB60D01D0D3E46E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.security.level=VERY_HIGH", `
        "deployment.security.level.locked"

    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "------------------------------------------" | Out-String

    if (-not($ConfigResult.ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found - FINDING" | Out-String
    }
    else {
        foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
            $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
            if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                foreach ($Line in $ConfigFileContent) {
                    if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        break
                    }
                }
                if ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    if ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                    }
                    else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                        }
                        else {
                            if (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    foreach ($Key in $KeysToEval) {
                                        if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                        }
                                    }
                                }
                            }
                            else {
                                $Compliant = $false
                                $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                            }
                        }
                    }
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                }
            }
            $FindingDetails += "------------------------------------------" | Out-String
        }
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234687 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234687
        STIG ID    : JRE8-WN-000070
        Rule ID    : SV-234687r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must be set to allow Java Web Start (JWS) applications.
        DiscussMD5 : 5DEE22E2DE37260B37F6F641CDFAE90C
        CheckMD5   : E7961FD2EE56FB5CA335A6698971F3E6
        FixMD5     : E1BDBFD6E8B5B20A33BAA0C7A49ED5EF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.webjava.enabled=true", `
        "deployment.webjava.enabled.locked"

    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "------------------------------------------" | Out-String

    if (-not($ConfigResult.ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found - FINDING" | Out-String
    }
    else {
        foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
            $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
            if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                foreach ($Line in $ConfigFileContent) {
                    if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        break
                    }
                }
                if ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    if ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                    }
                    else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                        }
                        else {
                            if (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    foreach ($Key in $KeysToEval) {
                                        if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                        }
                                    }
                                }
                            }
                            else {
                                $Compliant = $false
                                $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                            }
                        }
                    }
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                }
            }
            $FindingDetails += "------------------------------------------" | Out-String
        }
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234688 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234688
        STIG ID    : JRE8-WN-000080
        Rule ID    : SV-234688r617446_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must disable the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
        DiscussMD5 : 884B69274C3B7E49843DC681FC28341A
        CheckMD5   : 168E005119660EA412563B0774F80DCF
        FixMD5     : 79422036C6641DB371AABE21829E3348
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    else {
        $KeysToEval = "deployment.security.askgrantdialog.notinca=false", `
            "deployment.security.askgrantdialog.notinca.locked"

        $ConfigResult = Test-ConfigFile
        $Compliant = $ConfigResult.Compliant
        foreach ($Line in $ConfigResult.ResultText) {
            $FindingDetails += $Line | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------------------------------------" | Out-String

        if (-not($ConfigResult.ConfigFiles)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found - FINDING" | Out-String
        }
        else {
            foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
                $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
                $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                }
                else {
                    # Get path to deployment.properties from .config file
                    $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                    foreach ($Line in $ConfigFileContent) {
                        if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                            $PropsPath = ($Line.Split("=")[1]).Trim()
                            break
                        }
                    }
                    if ($PropsPath) {
                        $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                        if ($PropsFile.Pass -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                        }
                        else {
                            $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                            $FindingDetails += "" | Out-String
                            if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                                $Compliant = $false
                                $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                            }
                            else {
                                if (Test-Path $PropsFile.Formatted) {
                                    $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                    if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                        $Compliant = $false
                                        $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                        $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                    }
                                    else {
                                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                        foreach ($Key in $KeysToEval) {
                                            if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                                $FindingDetails += "$Key is present" | Out-String
                                            }
                                            else {
                                                $Compliant = $false
                                                $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                            }
                                        }
                                    }
                                }
                                else {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                                }
                            }
                        }
                    }
                    else {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                    }
                }
                $FindingDetails += "------------------------------------------" | Out-String
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

function Get-V234689 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234689
        STIG ID    : JRE8-WN-000090
        Rule ID    : SV-234689r617446_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must lock the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
        DiscussMD5 : CF669DA14A24210AF51C2FEB68300BBC
        CheckMD5   : 0CB927326259CC3E224BDE774FBA1ED8
        FixMD5     : 177A88046D5AD5B5870DACC0E0A44623
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    else {
        $KeysToEval = "deployment.security.askgrantdialog.show=false", `
            "deployment.security.askgrantdialog.show.locked"

        $ConfigResult = Test-ConfigFile
        $Compliant = $ConfigResult.Compliant
        foreach ($Line in $ConfigResult.ResultText) {
            $FindingDetails += $Line | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------------------------------------" | Out-String

        if (-not($ConfigResult.ConfigFiles)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found - FINDING" | Out-String
        }
        else {
            foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
                $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
                $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                }
                else {
                    # Get path to deployment.properties from .config file
                    $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                    foreach ($Line in $ConfigFileContent) {
                        if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                            $PropsPath = ($Line.Split("=")[1]).Trim()
                            break
                        }
                    }
                    if ($PropsPath) {
                        $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                        if ($PropsFile.Pass -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                        }
                        else {
                            $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                            $FindingDetails += "" | Out-String
                            if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                                $Compliant = $false
                                $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                            }
                            else {
                                if (Test-Path $PropsFile.Formatted) {
                                    $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                    if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                        $Compliant = $false
                                        $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                        $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                    }
                                    else {
                                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                        foreach ($Key in $KeysToEval) {
                                            if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                                $FindingDetails += "$Key is present" | Out-String
                                            }
                                            else {
                                                $Compliant = $false
                                                $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                            }
                                        }
                                    }
                                }
                                else {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                                }
                            }
                        }
                    }
                    else {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                    }
                }
                $FindingDetails += "------------------------------------------" | Out-String
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

function Get-V234690 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234690
        STIG ID    : JRE8-WN-000100
        Rule ID    : SV-234690r617446_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Oracle JRE 8 must set the option to enable online certificate validation.
        DiscussMD5 : A49775A6E44134FD46FF4732407BF5FB
        CheckMD5   : CC8ADDB08E2971213CD95E02DA5D331E
        FixMD5     : E48D9A9FD9F1FA1AB4B430C56DD5B426
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    else {
        $KeysToEval = "deployment.security.validation.ocsp=true", `
            "deployment.security.validation.ocsp.locked"

        $ConfigResult = Test-ConfigFile
        $Compliant = $ConfigResult.Compliant
        foreach ($Line in $ConfigResult.ResultText) {
            $FindingDetails += $Line | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------------------------------------" | Out-String

        if (-not($ConfigResult.ConfigFiles)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found - FINDING" | Out-String
        }
        else {
            foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
                $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
                $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                }
                else {
                    # Get path to deployment.properties from .config file
                    $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                    foreach ($Line in $ConfigFileContent) {
                        if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                            $PropsPath = ($Line.Split("=")[1]).Trim()
                            break
                        }
                    }
                    if ($PropsPath) {
                        $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                        if ($PropsFile.Pass -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                        }
                        else {
                            $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                            $FindingDetails += "" | Out-String
                            if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                                $Compliant = $false
                                $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                            }
                            else {
                                if (Test-Path $PropsFile.Formatted) {
                                    $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                    if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                        $Compliant = $false
                                        $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                        $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                    }
                                    else {
                                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                        foreach ($Key in $KeysToEval) {
                                            if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                                $FindingDetails += "$Key is present" | Out-String
                                            }
                                            else {
                                                $Compliant = $false
                                                $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                            }
                                        }
                                    }
                                }
                                else {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                                }
                            }
                        }
                    }
                    else {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                    }
                }
                $FindingDetails += "------------------------------------------" | Out-String
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

function Get-V234691 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234691
        STIG ID    : JRE8-WN-000110
        Rule ID    : SV-234691r617446_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : Oracle JRE 8 must prevent the download of prohibited mobile code.
        DiscussMD5 : CEC79E03E4228BD7547CB3EBAB995CA3
        CheckMD5   : B5A925EEBB4F85963F29B7BEE5DEF7D1
        FixMD5     : C65541F32BE040260340C60BD50313A1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.security.blacklist.check=true", `
        "deployment.security.blacklist.check.locked"

    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "------------------------------------------" | Out-String

    if (-not($ConfigResult.ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found - FINDING" | Out-String
    }
    else {
        foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
            $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
            if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                foreach ($Line in $ConfigFileContent) {
                    if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        break
                    }
                }
                if ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    if ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                    }
                    else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                        }
                        else {
                            if (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    foreach ($Key in $KeysToEval) {
                                        if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                        }
                                    }
                                }
                            }
                            else {
                                $Compliant = $false
                                $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                            }
                        }
                    }
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                }
            }
            $FindingDetails += "------------------------------------------" | Out-String
        }
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234692 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234692
        STIG ID    : JRE8-WN-000120
        Rule ID    : SV-234692r617446_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must enable the option to use an accepted sites list.
        DiscussMD5 : F07373721D4DC99C769562427B1C6F3B
        CheckMD5   : 5393E295AA4782DB5B1EA14A54130D52
        FixMD5     : A05A7DFCBDAF91D48996E1CE3387991B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.user.security.exception.sites"

    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "------------------------------------------" | Out-String

    if (-not($ConfigResult.ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found - FINDING" | Out-String
    }
    else {
        foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
            $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
            if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                foreach ($Line in $ConfigFileContent) {
                    if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        break
                    }
                }
                if ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    if ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                    }
                    else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                        }
                        else {
                            if (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    foreach ($Key in $KeysToEval) {
                                        if ($DeployFileContent -match $Key) {
                                            foreach ($Line in $DeployFileContent) {
                                                if ($Line -like "$($KeysToEval)*") {
                                                    $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                                    break
                                                }
                                            }
                                            if ($ExceptionPath) {
                                                $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                                if ($ExceptionFile.Pass -ne $true) {
                                                    $Compliant = $false
                                                    $FindingDetails += "$Line" | Out-String
                                                    $FindingDetails += "" | Out-String
                                                    $FindingDetails += "$($ExceptionFile.Formatted) - FINDING" | Out-String
                                                }
                                                elseif ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                                    $Compliant = $false
                                                    $FindingDetails += "$Line" | Out-String
                                                    $FindingDetails += "" | Out-String
                                                    $FindingDetails += "$Key does NOT point to an 'exception.sites' file - FINDING" | Out-String
                                                }
                                                else {
                                                    $FindingDetails += "$Line is present" | Out-String
                                                }
                                            }
                                            else {
                                                $Compliant = $false
                                                $FindingDetails += "$Line" | Out-String
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "Path to 'exception.sites' file is NOT defined in properties file - FINDING" | Out-String
                                            }
                                        }
                                        else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                        }
                                    }
                                }
                            }
                            else {
                                $Compliant = $false
                                $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                            }
                        }
                    }
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                }
            }
            $FindingDetails += "------------------------------------------" | Out-String
        }
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234693 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234693
        STIG ID    : JRE8-WN-000130
        Rule ID    : SV-234693r617446_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must have an exception.sites file present.
        DiscussMD5 : F07373721D4DC99C769562427B1C6F3B
        CheckMD5   : FF7236A21E04C91934EAE2F409EAD6C7
        FixMD5     : B1E34DCC935F0488D74FFD96F8460B8D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    else {
        $KeysToEval = "deployment.user.security.exception.sites"

        $ConfigResult = Test-ConfigFile
        $Compliant = $ConfigResult.Compliant
        foreach ($Line in $ConfigResult.ResultText) {
            $FindingDetails += $Line | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------------------------------------" | Out-String

        if (-not($ConfigResult.ConfigFiles)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found - FINDING" | Out-String
        }
        else {
            foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
                $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
                $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                }
                else {
                    # Get path to deployment.properties from .config file
                    $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                    foreach ($Line in $ConfigFileContent) {
                        if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                            $PropsPath = ($Line.Split("=")[1]).Trim()
                            break
                        }
                    }
                    if ($PropsPath) {
                        $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                        if ($PropsFile.Pass -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                        }
                        else {
                            $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                            if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                                $Compliant = $false
                                $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                            }
                            else {
                                if (Test-Path $PropsFile.Formatted) {
                                    $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                    if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                        $Compliant = $false
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                        $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                    }
                                    else {
                                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                        foreach ($Key in $KeysToEval) {
                                            if ($DeployFileContent -match $Key) {
                                                foreach ($Line in $DeployFileContent) {
                                                    if ($Line -like "$($KeysToEval)*") {
                                                        $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                                        break
                                                    }
                                                }
                                                if ($ExceptionPath) {
                                                    $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                                    if ($ExceptionFile.Pass -ne $true) {
                                                        $Compliant = $false
                                                        $FindingDetails += "" | Out-String
                                                        $FindingDetails += "$Line" | Out-String
                                                        $FindingDetails += "" | Out-String
                                                        $FindingDetails += "$($ExceptionFile.Formatted) - FINDING" | Out-String
                                                    }
                                                    else {
                                                        $FindingDetails += "Exception File:`t`t$($ExceptionFile.Configured)" | Out-String
                                                        $FindingDetails += "" | Out-String
                                                        if ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                                            $Compliant = $false
                                                            $FindingDetails += "$Key does NOT point to an 'exception.sites' file - FINDING" | Out-String
                                                        }
                                                        else {
                                                            if (Test-Path $ExceptionFile.Formatted) {
                                                                $FindingDetails += "Exception file exists in the path defined." | Out-String
                                                            }
                                                            else {
                                                                $Compliant = $false
                                                                $FindingDetails += "Exception file NOT found in the path defined - FINDING" | Out-String
                                                            }
                                                        }
                                                    }
                                                }
                                                else {
                                                    $Compliant = $false
                                                    $FindingDetails += "" | Out-String
                                                    $FindingDetails += "Path to 'exception.sites' file is NOT defined in properties file - FINDING" | Out-String
                                                }
                                            }
                                            else {
                                                $Compliant = $false
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                            }
                                        }
                                    }
                                }
                                else {
                                    $Compliant = $false
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                                }
                            }
                        }
                    }
                    else {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                    }
                }
                $FindingDetails += "------------------------------------------" | Out-String
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

function Get-V234694 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234694
        STIG ID    : JRE8-WN-000150
        Rule ID    : SV-234694r617446_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000401
        Rule Title : Oracle JRE 8 must enable the dialog to enable users to check publisher certificates for revocation.
        DiscussMD5 : C3D8C5511483BF09893323791B8DFE96
        CheckMD5   : B3C20A52D5863216EE499BB854FE40B7
        FixMD5     : 9D0734F8F6C3FCA24CD845A37B0F0F7B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    else {
        $KeysToEval = "deployment.security.validation.crl=true", `
            "deployment.security.validation.crl.locked"

        $ConfigResult = Test-ConfigFile
        $Compliant = $ConfigResult.Compliant
        foreach ($Line in $ConfigResult.ResultText) {
            $FindingDetails += $Line | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------------------------------------" | Out-String

        if (-not($ConfigResult.ConfigFiles)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found - FINDING" | Out-String
        }
        else {
            foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
                $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
                $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                }
                else {
                    # Get path to deployment.properties from .config file
                    $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                    foreach ($Line in $ConfigFileContent) {
                        if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                            $PropsPath = ($Line.Split("=")[1]).Trim()
                            break
                        }
                    }
                    if ($PropsPath) {
                        $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                        if ($PropsFile.Pass -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                        }
                        else {
                            $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                            $FindingDetails += "" | Out-String
                            if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                                $Compliant = $false
                                $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                            }
                            else {
                                if (Test-Path $PropsFile.Formatted) {
                                    $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                    if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                        $Compliant = $false
                                        $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                        $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                    }
                                    else {
                                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                        foreach ($Key in $KeysToEval) {
                                            if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                                $FindingDetails += "$Key is present" | Out-String
                                            }
                                            else {
                                                $Compliant = $false
                                                $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                            }
                                        }
                                    }
                                }
                                else {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                                }
                            }
                        }
                    }
                    else {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                    }
                }
                $FindingDetails += "------------------------------------------" | Out-String
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

function Get-V234695 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234695
        STIG ID    : JRE8-WN-000160
        Rule ID    : SV-234695r617446_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must lock the option to enable users to check publisher certificates for revocation.
        DiscussMD5 : 641C7784614699CE2C93D8CA2E495B55
        CheckMD5   : 69FD6048228D19D71C796DAC9E09DBEA
        FixMD5     : 95295612F60E641D17F03A3554121290
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    else {
        $KeysToEval = "deployment.security.revocation.check=ALL_CERTIFICATES", `
            "deployment.security.revocation.check.locked"

        $ConfigResult = Test-ConfigFile
        $Compliant = $ConfigResult.Compliant
        foreach ($Line in $ConfigResult.ResultText) {
            $FindingDetails += $Line | Out-String
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "------------------------------------------" | Out-String

        if (-not($ConfigResult.ConfigFiles)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found - FINDING" | Out-String
        }
        else {
            foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
                $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
                $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                }
                else {
                    # Get path to deployment.properties from .config file
                    $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                    foreach ($Line in $ConfigFileContent) {
                        if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                            $PropsPath = ($Line.Split("=")[1]).Trim()
                            break
                        }
                    }
                    if ($PropsPath) {
                        $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                        if ($PropsFile.Pass -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                        }
                        else {
                            $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                            $FindingDetails += "" | Out-String
                            if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                                $Compliant = $false
                                $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                            }
                            else {
                                if (Test-Path $PropsFile.Formatted) {
                                    $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                    if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                        $Compliant = $false
                                        $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                        $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                    }
                                    else {
                                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                        foreach ($Key in $KeysToEval) {
                                            if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                                $FindingDetails += "$Key is present" | Out-String
                                            }
                                            else {
                                                $Compliant = $false
                                                $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                            }
                                        }
                                    }
                                }
                                else {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                                }
                            }
                        }
                    }
                    else {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                    }
                }
                $FindingDetails += "------------------------------------------" | Out-String
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

function Get-V234696 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234696
        STIG ID    : JRE8-WN-000170
        Rule ID    : SV-234696r617446_rule
        CCI ID     : CCI-002460
        Rule Name  : SRG-APP-000488
        Rule Title : Oracle JRE 8 must prompt the user for action prior to executing mobile code.
        DiscussMD5 : EB406C03E21F7D1CBE591AA7FDC219DE
        CheckMD5   : 99698508AC947007FC327449F5723040
        FixMD5     : D0F38D5725FC822140C02C022ECD214C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.insecure.jres=PROMPT", `
        "deployment.insecure.jres.locked"

    $ConfigResult = Test-ConfigFile
    $Compliant = $ConfigResult.Compliant
    foreach ($Line in $ConfigResult.ResultText) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "------------------------------------------" | Out-String

    if (-not($ConfigResult.ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found - FINDING" | Out-String
    }
    else {
        foreach ($ConfigFile in $ConfigResult.ConfigFiles) {
            $FindingDetails += "Config File:`t`t$($ConfigFile.FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFile.FullName
            if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFile.FullName
                foreach ($Line in $ConfigFileContent) {
                    if (($Line -replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        break
                    }
                }
                if ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    if ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$($PropsFile.Formatted) - FINDING" | Out-String
                    }
                    else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        if ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does NOT point to a 'deployment.properties' file - FINDING" | Out-String
                        }
                        else {
                            if (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                if ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows - FINDING." | Out-String
                                    $FindingDetails += "Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    foreach ($Key in $KeysToEval) {
                                        if ($Key -in ($DeployFileContent -replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present - FINDING" | Out-String
                                        }
                                    }
                                }
                            }
                            else {
                                $Compliant = $false
                                $FindingDetails += "Properties file NOT found in the path defined - FINDING" | Out-String
                            }
                        }
                    }
                }
                else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is NOT defined in deployment.config - FINDING" | Out-String
                }
            }
            $FindingDetails += "------------------------------------------" | Out-String
        }
    }

    if ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    else {
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

function Get-V234697 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234697
        STIG ID    : JRE8-WN-000180
        Rule ID    : SV-234697r617446_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The version of Oracle JRE 8 running on the system must be the most current available.
        DiscussMD5 : 1A65A3F13B756E1A1094EFEA1913C357
        CheckMD5   : 73D1DCFC26D761464C4511F16DEC18A8
        FixMD5     : 342FFDCC86D141555A2D54F97E83C461
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Java version information:`r`n" | Out-String
    $JrePaths = Get-JreInstallPath
    foreach ($Path in $JrePaths) {
        if (Test-Path $(Join-Path $Path -ChildPath bin | Join-Path -ChildPath java.exe)) {
            $File = Get-ChildItem $(Join-Path $Path -ChildPath bin | Join-Path -ChildPath java.exe)
            $FindingDetails += "Path:`t`t$($File.FullName)" | Out-String
            $FindingDetails += "Version:`t$($File.VersionInfo.ProductVersion)" | Out-String
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

function Get-V234698 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234698
        STIG ID    : JRE8-WN-000190
        Rule ID    : SV-234698r617446_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-APP-000454
        Rule Title : Oracle JRE 8 must remove previous versions when the latest version is installed.
        DiscussMD5 : 1664F2CB47698D309E1F3C0682B43A4C
        CheckMD5   : D9DACA84A573EDCFE6560D4873ED4CA5
        FixMD5     : E9C4DC2493D4E29DD6CFA6A4A22D77F1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $InstalledSoftwareVersions = Get-InstalledSoftware | Where-Object DisplayName -Match "Java 8" | Select-Object DisplayName, DisplayVersion

    if (($InstalledSoftwareVersions.DisplayVersion | Select-Object -Unique).Count -gt 1) {
        $Status = "Open"
        $FindingDetails += "Multiple versions of Java JRE are installed:" | Out-String
        foreach ($Version in $InstalledSoftwareVersions) {
            $FindingDetails += $Version.Displayname + " ($($Version.DisplayVersion))" | Out-String
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "Java JRE version information:`r`n" | Out-String
        foreach ($Version in $InstalledSoftwareVersions) {
            $FindingDetails += $Version.Displayname + " ($($Version.DisplayVersion))" | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDhN7AeORUaBXL+
# KiES5i4QzakutC1KxEN9S/d9CYke2aCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDC5ucKwL1K8NauNeBckEMpF6Ep9OQ1pij4m6BkqmUVBjANBgkqhkiG9w0BAQEF
# AASCAQBIP/r4KMg666Bg5jEFdRnTJ6t3kwXwXZ+MF66QOmGU1a5vhX2A6zpbHYbM
# luZ1aY+6DUg8dXXVv+VeHqY+A24JqknSox1FkKOC94dFV0eoHg82fkjRdRlzusuu
# G81n6pGTpQuddEJGuYYA1AL/irQzQbPnpQSVWM44/VTCMJ1y2UHFoW/Y/B84Lv/0
# KKk1EOPjwAvo+veccGdqNNwQHJJEiNw2jxiu7l0hcvP6knxPn6lABtpJ03pp04Ka
# LggHR7Em3v8b25oqpaAqFe//zkCC+t5f8HPQZGSufy9Rbasb5sbZIxp9VGuYOwAs
# TcZ9C43KVkERjlpn9tCmpF5J4jikoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTUzOFowLwYJKoZIhvcNAQkEMSIEIKR5aIeyj6csSMgLLs2m6t0AQKjU
# iLADbl6qrJx+NRIgMA0GCSqGSIb3DQEBAQUABIICABCvjgDn2E6H0pnLKw1ANK01
# blG85R/0OgrwRzmkbf+xaDfqlfjAodwPISZlP9SyhlIcz2RW2yeZLDR95wfPIOz6
# Ln12Rx//sfPANzu29sHUePMt9r5/BBMm8P7aJH2aUEZ7AeUniTIqYvAqE9BuR7Ef
# X8Vat+IiiTy5pYOyVxt8NKxMdEpnA7sgJCnCc5wlaBuB+czAyB0lM8k6OelAvbot
# ReznOL4NhwzlK5P2EdgCZ4LS35g2N/QTO3zGdiivEabBTn4SHcr2IF5N6/JZT5t0
# KdjApJuHfnZp97/g8AL9GEkF3po575CuuqPEu17+GlW+WtdXGSeyo8fvj0T85gnq
# 4+Bp3uL7jiFWkVp6La9sz9q7o82eOkNLPOmB2PCRVGL51VuiU6xs0h8eGblsnxVc
# ta9+9v/gpGVvTqkpx77J4cUVyFSFFYdP728FjhwGOF0TPxPoA4BqNkS9kcq0izVx
# khpa5dyavjZ9nQmS/0CQtV458Jbj5otq27sLaY8SlzmKdjQZ+S39rrVh6n/BeItb
# Mc9Lx0UwHTDhZkvmvrEo/A39JDMHouIhc50P7McLYU+n+yGWhEHq7X9xJK49qY9b
# pOLkB9eK0+yTw9TBAn2sbZ03dDgA0KbYwMFB5S7+K5sE1DqrvZ4JMPfhqGz6iB/D
# u8Yr1shdBA4wB7jcjLX0
# SIG # End signature block
