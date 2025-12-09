##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Apache Tomcat Application Server 9
# Version:  V3R2
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function ConvertModeStringtoDigits {
    Param(
        [parameter (Mandatory = $true, position = 0, ParameterSetName = 'modestring')]
        [AllowNull()]
        $line
    )

    $Digits = ($line.substring(1)) -replace ".$" | sed -re 's/rwx/7/g' -e 's/rw-/6/g' -e 's/r-x/5/g' -e 's/r--/4/g' -e 's/-wx/3/g' -e 's/-w-/2/g' -e 's/--x/1/g' -e 's/---/0/g'

    return $Digits
}

Function Get-CatalinaBase {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessString
    )

    $paramIndex = $ProcessString.IndexOf("catalina.base")

    if ($paramIndex -ne -1) {
        $valueIndex = $ProcessString.IndexOf("=", $paramIndex) + 1
        $nextIndex = $ProcessString.IndexOf("-D", $valueIndex) - 1
        $catalinaBase = ($ProcessString.Substring($valueIndex, $nextIndex - $valueIndex)).Replace("`"","")
    }
    else {
        $sepChar = [IO.Path]::DirectorySeparatorChar
        $catalinaBase = ($ProcessString -replace "\$($sepChar)bin\$($sepChar).*", "$($sepChar)").Replace("`"","")
    }

    if ($null -eq $catalinaBase -or $catalinaBase -eq "" -or $catalinaBase -eq ".") {
        $catalinaBase = $env:CATALINA_BASE
    }

    return $catalinaBase
}

Function Get-CatalinaHome {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessString
    )

    $paramIndex = $ProcessString.IndexOf("catalina.home")

    if ($paramIndex -ne -1) {
        $valueIndex = $ProcessString.IndexOf("=", $paramIndex) + 1
        $nextIndex = $ProcessString.IndexOf("-D", $valueIndex) - 1
        $catalinaHome = ($ProcessString.Substring($valueIndex, $nextIndex - $valueIndex)).Replace("`"","")
    }
    else {
        $sepChar = [IO.Path]::DirectorySeparatorChar
        $catalinaHome = ($ProcessString -replace "\$($sepChar)bin\$($sepChar).*", "$($sepChar)").Replace("`"", "")
    }

    if ($null -eq $catalinaHome -or $catalinaHome -eq "" -or $catalinaHome -eq ".") {
        $catalinaHome = $env:CATALINA_HOME
    }

    return $catalinaHome
}

Function Get-Executable {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessId
    )

    $executableString = ((Get-Process -Id $ProcessId).Path)

    return $executableString
}

Function Get-JoinPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [psobject]$ChildPath,
        [Parameter(Mandatory = $true)]
        [psobject]$AdditionalChildPath
    )

    if ($ChildPath -eq $TomcatInstance.ConfDir) {
        $DirPath = $ChildPath
    }
    else {
        $DirPath = Join-Path -Path $Path -ChildPath $ChildPath
    }

    $FilePath = Join-Path -Path $DirPath -ChildPath $AdditionalChildPath

    return $FilePath
}

Function Get-ProcessBinding {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessId
    )

    if ($IsLinux) {
        $netstatString = netstat -pant | grep $ProcessId
        if ($null -eq $netstatString -or $netstatString -eq "") {
            $processIP = "Unknown"
        }
        else {
            $processIP = (($netstatString -replace '\s+', ' ') -split " ")[3]
        }
    }
    else {
        $netstatString = netstat -ano -p TCP | findstr $ProcessId | findstr "LISTENING"
        if ($null -eq $netstatString -or $netstatString -eq "") {
            $processIP = "Unknown"
        }
        else {
            $processIP = $netstatString | ForEach-Object {(($_ -replace '\s+', ' ') -split " ")[2]}
        }
    }

    return $processIP
}

Function Get-TomcatInstance {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessID,
        [Parameter(Mandatory = $True)]
        [int]$Index
    )

    $ProcessString = Get-ProcessString -ProcessId $ProcessID
    $ProcessUser = Get-ProcessUser -ProcessId $ProcessID
    $HomeDir = Get-CatalinaHome -ProcessString $ProcessString
    $Base = Get-CatalinaBase -ProcessString $ProcessString
    if ( $null -eq $Base) {
        $Base = $HomeDir
    }
    if ( $null -ne $Base) {
        $Conf = Join-Path -Path $Base -ChildPath "conf"
        $sepChar = [IO.Path]::DirectorySeparatorChar
        $Bindings = $Conf.replace("$sepChar","-")
        if ($Bindings.Length -gt 20) {
            $Bindings = $Bindings.substring(0,20)
        }
    }
    $Executable = Get-Executable -ProcessId $ProcessID
#    $Bindings = Get-ProcessBinding -ProcessId $ProcessID

    $Instance = [PSCustomObject]@{
        Index         = $Index
        ProcessID     = $ProcessID
        ProcessUser   = $ProcessUser
        ProcessString = $ProcessString
        Bindings      = $Bindings
        HomeDir       = $HomeDir
        BaseDir       = $Base
        ConfDir       = $Conf
        Executable    = $Executable
    }

    return $Instance
}

Function Get-TomcatInstances {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param ()

    $TomcatProcesses = Get-TomcatProcessId

    $Index = 0
    [System.Collections.ArrayList]$Instances = @()
    foreach ($processId in $TomcatProcesses) {
        $Instance = Get-TomcatInstance -ProcessID $processId -Index $Index
        if ($null -ne $Instance.HomeDir) {
            [void] $Instances.add($Instance)
            $Index++
        }
    }

    return $Instances
}

Function Get-TomcatProcessId {
    param ()

    $ProcessId1 = Get-Process | Where-Object { $_.Name -match "^tomcat\d{0,}\b" } | ForEach-Object {
        Write-Output "$($_.Id)"
    }

    $ProcessId2 = Get-Process | ForEach-Object {
        if (($_.Name -match "^java\d{0,}\b") -and ((Get-ProcessCommandLine -ProcessId $_.Id) -match "catalina.base|catalina.home")) {
            Write-Output "$($_.Id)"
        }
    }

    [System.Collections.ArrayList]$ProcessIDs = @()

    if (($ProcessId1 | Measure-Object).Count -gt 0){
        [void] $ProcessIDs.add($ProcessId1)
    }

    if (($ProcessId2 | Measure-Object).Count -gt 0){
        [void] $ProcessIDs.add($ProcessId2)
    }

    return $ProcessIDs
}

Function Get-XMLObject {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [psobject]$TomcatInstance,
        [Parameter(Mandatory = $false)]
        [psobject]$FilePath = $TomcatInstance.ConfDir
    )

    $XmlFile = Join-Path -Path $FilePath -ChildPath $Filename
    if (-not (Test-Path $XmlFile)) {
        if ($FilePath -ne $TomcatInstance.ConfDir) {
            $XmlFile = Get-JoinPath -Path $TomcatInstance.BaseDir -ChildPath $FilePath -AdditionalChildPath $FileName
            if (-not (Test-Path $XmlFile)) {
                return $null
            }
        }
        else {
            $XmlFile = Join-Path -Path $TomcatInstance.ConfDir -ChildPath "$Filename"
            if (-not (Test-Path $XmlFile)) {
                return $null
            }
        }
    }

    try {
        $_xml = New-Object System.Xml.XmlDocument
        $XmlError = $($_xml.Load("$XmlFile")) 2>&1

        if ($null -ne $XmlError) {
            return $null
        }
    }
    catch {
        return $null
    }

    return ($_xml)
}

Function Get-V222926 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222926
        STIG ID    : TCAT-AS-000010
        Rule ID    : SV-222926r960735_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-AS-000001
        Rule Title : The number of allowed simultaneous sessions to the manager application must be limited.
        DiscussMD5 : 62E39294091CE3123C258DBAA743F47F
        CheckMD5   : 0FC3EEC29B5D3020B75561EE49C8A30F
        FixMD5     : FB3B59DA3DD0C3995208E45846EA5150
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ManagerInUse = 0
    $ErrorCount = 0
    $UserFile = "tomcat-users.xml"
    $XmlObject = Get-XMLObject -FileName $UserFile -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $ElementName = "user"
        $ManagerRoles = $XmlObject.GetElementsByTagName($ElementName)
        foreach ($user in $ManagerRoles) {
            If ($user."roles" -match "Manager*") {
                $ManagerInUse++
                break
            }
        }

        $ManagerXML = @((Get-ChildItem $TomcatInstance.ConfDir -Recurse | Where-Object { $_.Name -like "manager.xml" }).FullName)

        if ($ManagerXML) {
            $ManagerInUse++
        }

        if ($ManagerInUse -ge 2) {

            $FileName = "context.xml"
            $FilePath = "webapps/manager/META-INF"
            $ContextConfig = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath $FilePath
            $ElementName = "Manager"
            $AttributeName = "maxActiveSessions"
            $Element = $ContextConfig.GetElementsByTagName($ElementName)
            $ExpectedValue = "Configured according to SSP"
            $ConfigFile = Get-JoinPath -Path $TomcatInstance.BaseDir -ChildPath $FilePath -AdditionalChildPath $FileName
            $FindingDetails += "Config File:`n`t$ConfigFile" | Out-String
            $FindingDetails += "Setting:`n`t$AttributeName" | Out-String
            $FindingDetails += "Expected State:`n`t$ExpectedValue" | Out-String
            if ($null -eq $($Element.$AttributeName) -or $($Element.$AttributeName) -eq "") {
                $DetectedState = "Not Configured"
                $ErrorCount++
            }
            elseif ($($Element.$AttributeName) -eq "-1" ) {
                $DetectedState = "$AttributeValue (no limit)"
                $ErrorCount++
            }
            else {
                $DetectedState = $($Element.$AttributeName)
            }

            $FindingDetails += "Detected State:`n`t$DetectedState" | Out-String

            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += "The manager application is not present or not in use" | Out-String
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

Function Get-V222927 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222927
        STIG ID    : TCAT-AS-000020
        Rule ID    : SV-222927r960759_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-AS-000009
        Rule Title : Secured connectors must be configured to use strong encryption ciphers.
        DiscussMD5 : 6131E1B56A7BEAEC5CC24B42D52C7CCC
        CheckMD5   : 01DEC284D36506224E22B758B2BC1321
        FixMD5     : A2177BB323D066B5CCB96BDE1215B1F5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $CheckCount = 0
    $FileName = "server.xml"
    $ElementName = "Connector"
    $AttributeName = "ciphers"
    $MinBit = 128
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $Elements = $XmlObject.GetElementsByTagName($ElementName)

        $FindingDetails += "Config File:`n`t$(Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName)" | Out-String
        $FindingDetails += "" | Out-String

        Foreach ($element in $Elements) {
            if ( $element.redirectPort -ne "8443" -and $element.redirectPort -ne "443" ) {
                $CheckCount++
                $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
                $attributeValue = $element.$AttributeName
                if ($null -eq $attributeValue -or $attributeValue -eq "" ) {
                    $attributeValue = "No Value Found"
                }
                else {
                    foreach ($attr in ($attributeValue -split ",")) {
                        $cipherBit = $attr -replace '\D+AES_([\d+]*)_.*', '$1'
                        if ( $null -eq $attr -or $attr -eq "" -or $cipherBit -lt $MinBit) {
                            $ErrorCount++
                        }
                    }
                }
                $FindingDetails += "Attribute Value:`n`t$($attributeValue)`n" | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        if ($CheckCount -eq 0) {
            $FindingDetails += "`nNo Secured $($ElementName) Found" | Out-String
            $Status = "NotAFinding"
        }
        else {
            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
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

Function Get-V222928 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222928
        STIG ID    : TCAT-AS-000030
        Rule ID    : SV-222928r960762_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : HTTP Strict Transport Security (HSTS) must be enabled.
        DiscussMD5 : B37AE015CA757C9F2CA87DCFD7BDC67C
        CheckMD5   : 11A3D83A846E48802802134D7FFCB02C
        FixMD5     : 763D96E70919CEC156A05A2125B66194
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "web.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $FilterName = "httpHeaderSecurity"
        $FilterStatus = "Not Found"
        $ManadatoryParam = "hstsEnabled"
        $ParamNames = & {"hstsEnabled", "hstsMaxAgeSeconds", "hstsIncludeSubDomains"}
        $Elements = $XmlObject.GetElementsByTagName("filter")
        foreach ($element in $Elements) {
            if ($element."filter-name" -eq $FilterName) {
                $FilterStatus = "Enabled"
                $FindingDetails += "Filter $FilterName Status:`n`t$FilterStatus" | Out-String
                $FindingDetails += "" | Out-String

                foreach ($item in $element."init-param") {
                    if ($ParamNames -contains $item."param-name") {
                        if ($item."param-name" -eq $ManadatoryParam) {
                            if ($item."param-value" -ne $true) {
                                $ErrorCount++
                            }
                        }

                        $FindingDetails += "$($item."param-name") Setting:`n`t$($item."param-value")" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }

                foreach ($param in $ParamNames) {
                    if ($element.'init-param'.'param-name' -notcontains $param ) {
                        if ($param -eq $ManadatoryParam) {
                            $ErrorCount++
                        }

                        $FindingDetails += "$param Setting:`n`tNot Found" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
            }
        }

        if ($FilterStatus -eq "Not Found") {
            $FindingDetails += "Filter $($FilterName) Status:`n`t$FilterStatus" | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $FilterStatus = "Not Found"
        $Elements = $XmlObject.GetElementsByTagName("filter-mapping")
        foreach ($element in $Elements) {
            if ($element."filter-name" -eq $FilterName) {
                $FilterStatus = "Enabled"
                $FindingDetails += "Filter Mapping $FilterName Status:`n`t$FilterStatus" | Out-String
                $FindingDetails += "" | Out-String
                $settingValue = $element."url-pattern"
                if ( $null -eq $settingValue) {
                    $settingValue = "Not Found"
                }
                $FindingDetails += "url-pattern Setting:`n`t$($settingValue)" | Out-String
                $FindingDetails += "" | Out-String
                $settingValue = $element."dispatcher"
                if ( $null -eq $settingValue) {
                    $settingValue = "Not Found"
                }
                $FindingDetails += "dispatcher Setting:`n`t$($settingValue)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        if ($FilterStatus -eq "Not Found") {
            $FindingDetails += "Filter Mapping $($FilterName) Status:`n`t$FilterStatus" | Out-String
            $FindingDetails += "" | Out-String
        }

        if ($ErrorCount -gt 0) {
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

Function Get-V222929 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222929
        STIG ID    : TCAT-AS-000040
        Rule ID    : SV-222929r960762_rule
        CCI ID     : CCI-000197, CCI-001453, CCI-002418
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : TLS 1.2 must be used on secured HTTP connectors.
        DiscussMD5 : AB71959CE45F59D180AA470499A64B7F
        CheckMD5   : 30BA00E9D094354AE1DAD9816056C16E
        FixMD5     : 000284D8839C765389019586EE75CE7C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $CheckCount = 0
    $FileName = "server.xml"
    $ElementName = "Connector"
    $AttributeName = "SSLEnabledProtocols"
    $TLSVersion = 1.2
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $Elements = $XmlObject.GetElementsByTagName($ElementName)

        $FindingDetails += "Config File:`n`t$(Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName)" | Out-String
        $FindingDetails += "" | Out-String

        Foreach ($element in $Elements) {
            if ( $element.protocol -match "http" ) {
                $CheckCount++
                $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
                $attributeValue = $element.$AttributeName
                if ($null -eq $attributeValue -or $attributeValue -eq "" ) {
                    $attributeValue = "No Value Found"
                    $ErrorCount++
                }
                else {
                    foreach ($attr in $attributeValue) {
                        $TLS = $attr -replace 'TLSv([\d+]*)', '$1'
                        if ( $null -eq $attr -or $attr -eq "" -or $TLS -lt $TLSVersion) {
                            $ErrorCount++
                        }
                    }
                }
                $FindingDetails += "Attribute Value:`n`t$($attributeValue)`n" | Out-String
            }
        }

        if ($CheckCount -eq 0) {
            $FindingDetails += "`nNo HTTP $($ElementName) Found" | Out-String
            $Status = "NotAFinding"
        }
        else {
            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
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

Function Get-V222930 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222930
        STIG ID    : TCAT-AS-000050
        Rule ID    : SV-222930r960765_rule
        CCI ID     : CCI-000067, CCI-000130, CCI-000133, CCI-000134, CCI-000166, CCI-000169, CCI-000172
        Rule Name  : SRG-APP-000016-AS-000013
        Rule Title : AccessLogValve must be configured for each application context.
        DiscussMD5 : 341A8B4CDB881276F0D347FBE4DD0A99
        CheckMD5   : E0E4E46EF48EB01C6D2FCCA1344C7A73
        FixMD5     : 54176B54D9EEEDE0736C094C60931257
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ElementCount = 0
    $LogCount = 0
    $ContextNum = 1
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $ElementName = "Context"
        $ParamName = "className"
        $ParamValue = "org.apache.catalina.valves.AccessLogValve"
        $Elements = $XmlObject.GetElementsByTagName("$ElementName")
        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No Context Elements found" | Out-String
            $Status = "NotAFinding"
        }
        else {
            foreach ($element in $Elements) {
                $ElementCount++
                $FindingDetails += "" | Out-String
                $FindingDetails += "Context Number:`n`t$ContextNum" | Out-String
                $ContextNum++
                foreach ($SingleValve in $Element.Valve) {
                    $FindingDetails += "$ParamName Setting:`n`t$($SingleValve.$ParamName)" | Out-String
                    if ($($SingleValve.$ParamName) -match $ParamValue) {
                        $LogCount++
                        break
                    }
                }
            }
            if ($LogCount -eq $ElementCount) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
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

Function Get-V222931 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222931
        STIG ID    : TCAT-AS-000060
        Rule ID    : SV-222931r960792_rule
        CCI ID     : CCI-000186, CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Default password for keystore must be changed.
        DiscussMD5 : CFC9B1E8467092C150217E20EDDC651B
        CheckMD5   : F59FEC9313B3CC1659D87511295D9B3C
        FixMD5     : DF2DF5E113F017536EFB22914BC3A7F8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($IsLinux) {
        $ErrorCount = 0
        $Command = "keytool -list -v -storepass 'changeit' 2>&1"

        try {
            $CommandOutput = (Invoke-Expression -Command $Command )
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $Exception = "Command not found"
        }
        catch {
            $Exception = $_.Exception.Message
        }

        $CommandString = "keytool -list -v"
        $KeytoolError = "password was incorrect"
        $ExpectedState = "Default keystore password is not in use"

        if ($null -eq $Exception -or $Exception -eq "") {
            $CommandError = $CommandOutput | Select-String -Pattern "Keystore file does not exist"
            if ($null -eq $CommandError -or $CommandError -eq "") {
                $PWChanged = $CommandOutput | Select-String -Pattern $KeytoolError
                if ($null -ne $PWChanged -and $PWChanged -ne "") {
                    $DetectedState = "Default keystore password is not in use"
                    $ErrorCount = 0
                }
                elseif ($CommandOutput | Select-String -Pattern "Keystore type:") {
                    $ErrorCount++
                    $DetectedState = "Default keystore password is in use"
                }
                else {
                    $DetectedState = "Manual review required"
                    $ErrorCount = -1
                }

                $FindingDetails += "Command:`n`t$CommandString" | Out-String
                $FindingDetails += "Expected State:`n`t$ExpectedState" | Out-String
                $FindingDetails += "Detected State:`n`t$DetectedState" | Out-String

                if ($ErrorCount -ge 1) {
                    $Status = "Open"
                }
                elseif ($ErrorCount -eq 0) {
                    $Status = "NotAFinding"
                }
            }
            Else {
                $FindingDetails += "Keytool Error: Keystore file does not exist." | Out-String
            }
        }
        elseif ($Exception | Select-String -Pattern "Command not found") {
            $FindingDetails += "Keytool Error: $($Exception)." | Out-String
            $FindingDetails += "Env:PATH: $($Env:PATH)" | Out-String
        }
        else {
            $FindingDetails += "Error: $($Exception)." | Out-String
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

Function Get-V222932 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222932
        STIG ID    : TCAT-AS-000070
        Rule ID    : SV-222932r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Cookies must have secure flag set.
        DiscussMD5 : C9A56CC943B1749C70B71D6151DAB464
        CheckMD5   : 3F564E5DF4BC292575A19AA82E352123
        FixMD5     : 4C12CEFEFEAE8B7257E94C9AD5EC79BA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "web.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "cookie-config"
        $ParamName = "secure"
        $ExpectedValue = "true"
        $Elements = $XmlObject.GetElementsByTagName("$ElementName")
        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
            $ErrorCount++
        }
        else {
            foreach ($element in $Elements) {
                $FindingDetails += "Element:`n`t$ParamName" | Out-String
                $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                $DetectedValue = $($element.$ParamName)
                if ($DetectedValue -notmatch $ExpectedValue) {
                    $ErrorCount++
                    if ($DetectedValue -eq "") {
                        $DetectedValue = "Not Found"
                    }
                }
                $FindingDetails += "Detected Value:`n`t$DetectedValue`n" | Out-String
            }
        }

        if ($ErrorCount -eq 0) {
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

Function Get-V222933 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222933
        STIG ID    : TCAT-AS-000080
        Rule ID    : SV-222933r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Cookies must have http-only flag set.
        DiscussMD5 : C9A56CC943B1749C70B71D6151DAB464
        CheckMD5   : 24527EA33D14A9E453CC7B1E5F09E002
        FixMD5     : 51BC241EAB08D2173771D2D47839A981
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "web.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "cookie-config"
        $Elements = $XmlObject.GetElementsByTagName("$ElementName")

        if ($null -eq "$Elements" -or "$Elements" -eq "") {
            $ErrorCount++
            $FindingDetails += "cookie-config was not found" | Out-String
        }
        else {
            $Setting = "http-only"
            $ExpectedValue = "true"
            foreach ($element in $Elements) {
                if ($null -eq $($element."$Setting") -or $($element."$Setting") -eq "") {
                    $ErrorCount++
                    $DetectedValue = "Not Found"
                }
                else {
                    $DetectedValue = $($element."http-only")
                    if ($Elements."$Setting" -ne "$ExpectedValue") {
                        $ErrorCount++
                    }
                }

                $FindingDetails += "Element:`n`t$Setting" | Out-String
                $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                $FindingDetails += "Detected Value:`n`t$DetectedValue" | Out-String
            }
        }

        if ($ErrorCount -ge 1) {
            $Status = "Open"

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

Function Get-V222934 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222934
        STIG ID    : TCAT-AS-000090
        Rule ID    : SV-222934r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : DefaultServlet must be set to readonly for PUT and DELETE.
        DiscussMD5 : 37A465353C6696B9732C5C5FC5891814
        CheckMD5   : D6BD0FF425B22863B54FFAFC2CE2CA28
        FixMD5     : EB7CBE34D5B62DACA7387FC5BEC14031
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "web.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "servlet"
        $ParamName = "readonly"
        $ExpectedValue = "true"
        $Elements = ($XmlObject.GetElementsByTagName("servlet") | Where-Object {$_."servlet-class" -like "*DefaultServlet"})
        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
            $ErrorCount++
        }
        else {
            foreach ($element in $Elements) {
                $ServletName = ($element."servlet-name")
                $FindingDetails += "Servlet:`n`t$ServletName" | Out-String
                $DetectedValue = ($element."init-param" | Where-Object "param-name" -EQ $ParamName)."param-value"
                if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                    $DetectedValue = "Not Found"
                }
                $FindingDetails += "Element:`n`t$ParamName" | Out-String
                $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                if ($DetectedValue -notmatch $ExpectedValue) {
                    $ErrorCount++
                }
                $FindingDetails += "Detected Value:`n`t$DetectedValue`n" | Out-String
            }
        }

        if ($ErrorCount -eq 0) {
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

Function Get-V222935 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222935
        STIG ID    : TCAT-AS-000100
        Rule ID    : SV-222935r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Connectors must be secured.
        DiscussMD5 : 822C1059EE344059BB39954E455B26CB
        CheckMD5   : 479A20AF3B19951F3A7097461CC2D3C4
        FixMD5     : B72ADB4F4F4E4D4AEF2ADC59943DA384
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ElementCount = 0
    $ErrorCount = 0
    $FileName = "server.xml"
    $ElementName = "Connector"
    $AttributeName = "scheme", "secure"
    $ExpectedValue = "https", "true"

    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $Elements = $XmlObject.GetElementsByTagName($ElementName)

        $FindingDetails += "Config File:`n`t$(Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName)" | Out-String
        $FindingDetails += "" | Out-String

        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
        }
        else {
            Foreach ($element in $Elements) {
                $ElementCount++
                $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                for ($i = 0; $i -lt $AttributeName.Count; $i++) {
                    $FindingDetails += "Attribute:`n`t$($AttributeName[$i])" | Out-String
                    $attributeValue = $element.$($AttributeName[$i])
                    if ($null -eq $attributeValue -or $attributeValue -eq "" ) {
                        $attributeValue = "No Value Found"
                        $ErrorCount++
                    }
                    else {
                        if ($attributeValue -ne $ExpectedValue[$i]) {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Expected Value:`n`t$($ExpectedValue[$i])" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($attributeValue)`n" | Out-String
                }
            }
        }

        if ($ElementCount -ge 1) {
            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
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

Function Get-V222936 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222936
        STIG ID    : TCAT-AS-000110
        Rule ID    : SV-222936r1067546_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : The Java Security Manager must be enabled.
        DiscussMD5 : 7B7E2B7F2057237018CB0E1288C3D590
        CheckMD5   : E685C72E1AB543EBBABCB631302F4DB3
        FixMD5     : 4D1E00B744A34BCF12CC898CDB6EB885
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $STIGChecked = $false
    $ConfigFound = $false
    $ProcessFound = $false
    $ConfigSetting = "ExecStart"
    $FlagName = "-security"
    $ParamName = "java.security.manager"

    if ($IsLinux) {
        $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $STIGChecked = $true
            $ConfigLine = Select-String -Pattern "^\s*$($ConfigSetting)" -Path $FilePath
            $ConfigFound = $null -ne ($ConfigLine | Select-String -Pattern "$FlagName")
        }
        else {
            $FilePath = "Not Found"
        }

        $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Config line:`n`t$($ConfigLine)" | Out-String
        $FindingDetails += "Expected Value:`n`t$($FlagName)" | Out-String
        $FindingDetails += "Found:`n`t$($ConfigFound)`n" | Out-String

        $ProcessFound = $null -ne ($ProcessString | Select-String -Pattern $ParamName)
        $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
        $FindingDetails += "Parameter:`n`t$($ParamName)" | Out-String
        $FindingDetails += "Found:`n`t$($ProcessFound)`n" | Out-String

    }
    else {

        $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String

        if ( $TomcatInstance.ProcessString -ne "Not Found" -and $TomcatInstance.ProcessString -notlike "*//PS Unsupported" ) {
            $STIGChecked = $true
            $ProcessFound = $null -ne ($TomcatInstance.ProcessString  | Select-String -Pattern $ParamName)
            $FindingDetails += "Parameter:`n`t$($ParamName)" | Out-String
            $FindingDetails += "Found:`n`t$($ProcessFound)`n" | Out-String
        }
    }

    if ($ConfigFound -eq $false -and $ProcessFound -eq $false) {
        $ErrorCount++
    }

    if ($STIGChecked) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V222937 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222937
        STIG ID    : TCAT-AS-000170
        Rule ID    : SV-222937r960879_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-AS-000050
        Rule Title : Tomcat servers behind a proxy or load balancer must log client IP.
        DiscussMD5 : 14875071B427E9750B76040B31854474
        CheckMD5   : 172E36FB39BA371248573D2C672C2125
        FixMD5     : 65A95CC0127149CE5AC7472B88217977
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "RemoteIpValve"
        $ParamName = "requestAttributesEnabled"
        $ExpectedValue = "true"
        $Elements = ($XmlObject.GetElementsByTagName("Valve") | Where-Object {$_."className" -like "*RemoteIpValve"})
        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }
        else {
            $DetectedValue = ($Elements."$ParamName")
            if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "" -or "$DetectedValue" -eq " ") {
                $DetectedValue = "Not Found"
            }
			$FindingDetails += "Element:`n`t$ElementName" | Out-String
            $FindingDetails += "Attribute:`n`t$ParamName" | Out-String
            $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
            if ($DetectedValue -notmatch $ExpectedValue) {
                $ErrorCount++
            }
            $FindingDetails += "Detected Value:`n`t$DetectedValue`n" | Out-String
        }

        $ElementName = "AccessLogValve"
        $Elements = ($XmlObject.GetElementsByTagName("Valve") | Where-Object {$_."className" -like "*AccessLogValve"})
        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
            $ErrorCount++
        }
        else {
            $DetectedValue = ($Elements."$ParamName")
            if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "" -or "$DetectedValue" -eq " ") {
                $DetectedValue = "Not Found"
            }
			$FindingDetails += "Element:`n`t$ElementName" | Out-String
            $FindingDetails += "Attribute:`n`t$ParamName" | Out-String
            $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
            if ($DetectedValue -notmatch $ExpectedValue) {
                $ErrorCount++
            }
            $FindingDetails += "Detected Value:`n`t$DetectedValue`n" | Out-String
        }

        if ($ErrorCount -eq 0) {
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

Function Get-V222938 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222938
        STIG ID    : TCAT-AS-000180
        Rule ID    : SV-222938r960882_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000171, CCI-000172, CCI-001487
        Rule Name  : SRG-APP-000090-AS-000051
        Rule Title : AccessLogValve must be configured per each virtual host.
        DiscussMD5 : 0416D67B09A6E54514ADF854E5150B7F
        CheckMD5   : 376E27C1215D3A29328E52E6C73B9678
        FixMD5     : 2065D7E1539DFB8AB0491F398F0CA227
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ExpectedValue = "All Host elements must contain an AccessLogValve"
        $Elements = $XmlObject.GetElementsByTagName("Host")


        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $Elements Elements found" | Out-String
        }
        else {
            foreach ($element in $Elements) {

                $ClassName = $element.valve | Where-Object {$_."className" -like "*AccessLogValve"}
                if ($null -eq "$ClassName" -or "$ClassName" -eq "") {
                    $DetectedValue = "Not Found"
                    $ErrorCount++
                }
                else {
                    $DetectedValue = $($ClassName.className)
                }
                $FindingDetails += "Host Element Name:`n`t$($element.name)" | Out-String
                $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String
            }
        }

        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V222939 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222939
        STIG ID    : TCAT-AS-000240
        Rule ID    : SV-222939r960894_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-AS-000059
        Rule Title : Date and time of events must be logged.
        DiscussMD5 : C6D665599138FC1298108203E9F23485
        CheckMD5   : 334B3F059749EDD50157035772918667
        FixMD5     : 0AB01FDF5A8BCCFB25C099035146966D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "Host"
        $ChildElement = "Valve"
        $AttributeName = "pattern"
        $AttributePattern = '%t'
        $Elements = $XmlObject.GetElementsByTagName("$ElementName")
        $ExpectedValue = "All valve elements must contain %t"

        if ($null -eq "$Elements" -or "$Elements" -eq "") {
            $FindingDetails += "No $Elements elements found" | Out-String
        }
        else {
            Foreach ($element in $Elements) {
                $ClassName = $element.$ChildElement | Where-Object {$_."className" -like "*AccessLogValve"}
                if ($null -ne "$ClassName" -and "$ClassName" -ne "") {
                    $AttributeValue = $element.$ChildElement.$AttributeName
                    $FindingDetails += "Element:`n`t$ChildElement  ClassName=$($ClassName.className)" | Out-String
                    $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                    if ( $null -eq "$AttributeValue" -or "$AttributeValue" -eq "" ) {
                        $AttributeValue = "No Value Found"
                        $ErrorCount++
                    }
                    else {
                        if ("$AttributeValue" -notmatch "$AttributePattern") {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($AttributeValue)`n" | Out-String
                }
                else {
                    $FindingDetails += "No Access Logging Valves found" | Out-String
                    $ErrorCount++
                }
            }
        }
        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V222940 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222940
        STIG ID    : TCAT-AS-000250
        Rule ID    : SV-222940r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-AS-000060
        Rule Title : Remote hostname must be logged.
        DiscussMD5 : 464529A10513F8F9C33FBDA9BEBD2B6D
        CheckMD5   : ED8E5136CF0EBAF001DCC8EC74F45F61
        FixMD5     : 503D375A7757C24A9457089754A01CF0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "Host"
        $ChildElement = "Valve"
        $AttributeName = "pattern"
        $AttributePattern = '%h'
        $Elements = $XmlObject.GetElementsByTagName("$ElementName")
        $ExpectedValue = "All valve elements must contain %h"

        if ($null -eq "$Elements" -or "$Elements" -eq "") {
            $FindingDetails += "No $Elements elements found" | Out-String
        }
        else {
            Foreach ($element in $Elements) {
                $ClassName = $element.$ChildElement | Where-Object {$_."className" -like "*AccessLogValve"}

                if ($null -ne "$ClassName" -and "$ClassName" -ne "") {
                    $AttributeValue = $element.$ChildElement.$AttributeName
                    $FindingDetails += "Element:`n`t$ChildElement  ClassName=$($ClassName.className)" | Out-String
                    $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                    if ( $null -eq "$AttributeValue" -or "$AttributeValue" -eq "" ) {
                        $AttributeValue = "No Value Found"
                        $ErrorCount++
                    }
                    else {
                        if ("$AttributeValue" -notmatch "$AttributePattern") {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($AttributeValue)`n" | Out-String
                }
                else {
                    $FindingDetails += "No Access Logging Valves found" | Out-String
                    $ErrorCount++
                }
            }
        }
        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V222941 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222941
        STIG ID    : TCAT-AS-000260
        Rule ID    : SV-222941r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-AS-000060
        Rule Title : HTTP status code must be logged.
        DiscussMD5 : F7B61EDA3A700961E567E9178D0EA33A
        CheckMD5   : 5D55A02C7B8C15211DBEEBA3B007EB07
        FixMD5     : D7C083D603C2003D73E08B729F090E08
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "Host"
        $ChildElement = "Valve"
        $AttributeName = "pattern"
        $AttributePattern = '%s'
        $Elements = $XmlObject.GetElementsByTagName("$ElementName")
        $ExpectedValue = "All valve elements must contain %s"

        if ($null -eq "$Elements" -or "$Elements" -eq "") {
            $FindingDetails += "No $Elements elements found" | Out-String
        }
        else {
            Foreach ($element in $Elements) {
                $ClassName = $element.$ChildElement | Where-Object {$_."className" -like "*AccessLogValve"}

                if ($null -ne "$ClassName" -and "$ClassName" -ne "") {
                    $AttributeValue = $element.$ChildElement.$AttributeName
                    $FindingDetails += "Element:`n`t$ChildElement  ClassName=$($ClassName.className)" | Out-String
                    $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                    if ( $null -eq "$AttributeValue" -or "$AttributeValue" -eq "" ) {
                        $AttributeValue = "No Value Found"
                        $ErrorCount++
                    }
                    else {
                        if ("$AttributeValue" -notmatch "$AttributePattern") {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($AttributeValue)`n" | Out-String
                }
                else {
                    $FindingDetails += "No Access Logging Valves found" | Out-String
                    $ErrorCount++
                }
            }
        }
        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V222942 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222942
        STIG ID    : TCAT-AS-000270
        Rule ID    : SV-222942r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-AS-000060
        Rule Title : The first line of request must be logged.
        DiscussMD5 : F603B1D1895C1B619E99718C705C6D97
        CheckMD5   : 314FAD8C717461F6EA77864EA838F68B
        FixMD5     : 8CDC6E1C58ADE6F6C55726BDCEABDD2C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "Host"
        $ChildElement = "Valve"
        $AttributeName = "pattern"
        $AttributePattern = '"%r"'
        $Elements = $XmlObject.GetElementsByTagName("$ElementName")
        $ExpectedValue = "All valve elements must contain $AttributePattern (translated from escaped double quote)"

        if ($null -eq "$Elements" -or "$Elements" -eq "") {
            $FindingDetails += "No $Elements elements found" | Out-String
        }
        else {
            Foreach ($element in $Elements) {
                $ClassName = $element.$ChildElement | Where-Object {$_."className" -like "*AccessLogValve"}

                if ($null -ne "$ClassName" -and "$ClassName" -ne "") {
                    $AttributeValue = $element.$ChildElement.$AttributeName
                    $FindingDetails += "Element:`n`t$ChildElement  ClassName=$($ClassName.className)" | Out-String
                    $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                    if ( $null -eq "$AttributeValue" -or "$AttributeValue" -eq "" ) {
                        $AttributeValue = "No Value Found"
                        $ErrorCount++
                    }
                    else {
                        if ("$AttributeValue" -notmatch "$AttributePattern") {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($AttributeValue)`n" | Out-String
                }
                else {
                    $FindingDetails += "No Access Logging Valves found" | Out-String
                    $ErrorCount++
                }
            }
        }
        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V222943 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222943
        STIG ID    : TCAT-AS-000360
        Rule ID    : SV-222943r960930_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-AS-000078
        Rule Title : $CATALINA_BASE/logs folder permissions must be set to 750.
        DiscussMD5 : 84CFAEA002B2C06A5D388A6F1653F392
        CheckMD5   : E3BF7992B3B2B2A643C551524E79D3E4
        FixMD5     : 7444409B65AE68F3DCD946181FF49BD6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $Folder = "logs"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $Folder

    if (Test-Path -Path $DirToCheck) {

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -type d -perm /027 -print
            if ($null -eq $listing -or $listing -eq "") {
                $FindingDetails += "No directories found in $DirToCheck that do not have proper permissions" | Out-String
            }
            else {
                $FindingDetails += "Directories not set to 750 in $DirToCheck" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
                $FindingDetails += $listing | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            $ErrorCount = -1
        }


        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge 1) {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails = '$CATALINA_BASE/logs was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222944 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222944
        STIG ID    : TCAT-AS-000361
        Rule ID    : SV-222944r960930_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-AS-000078
        Rule Title : Files in the $CATALINA_BASE/logs/ folder must have their permissions set to 640.
        DiscussMD5 : 84CFAEA002B2C06A5D388A6F1653F392
        CheckMD5   : 6EB54E007C2B3B741DD05A81112ABA79
        FixMD5     : D9F001DABC5C796AA962B0F3277D4A22
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "logs"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $FileName
    if (Test-Path -Path $DirToCheck) {

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -type f -perm /137 -print
            if ($null -eq $listing -or $listing -eq "") {
                $FindingDetails += "No files found in $DirToCheck that do not have proper permissions" | Out-String
            }
            else {
                $FindingDetails += "Files not set to 640 in $DirToCheck" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
                $FindingDetails += $listing | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $listing += Get-ChildItem -Path $DirToCheck -File -Recurse -Force | ForEach-Object {$_.FullName}
            foreach ($LogFile in $listing) {
                $FindingDetails += Get-Acl -Path "$LogFile" | Format-Table -Wrap | Out-String
            }
            # Because we cannot reliably check permissions to 740, increment errorcount to make a manual check
            $ErrorCount = -1
        }

        if ($ErrorCount -eq "0") {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge 1) {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails = '$CATALINA_BASE/logs was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222945 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222945
        STIG ID    : TCAT-AS-000370
        Rule ID    : SV-222945r960933_rule
        CCI ID     : CCI-000163, CCI-001813
        Rule Name  : SRG-APP-000119-AS-000079
        Rule Title : Files in the $CATALINA_BASE/conf/ folder must have their permissions set to 640.
        DiscussMD5 : 10CAB94AD7FACC468872049F78B2E833
        CheckMD5   : 2C0A1AC2F5D0F54698DAE3F6428CB867
        FixMD5     : F8849562C383518C119BCA117AED68E5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $DirToCheck = $TomcatInstance.ConfDir
    if (Test-Path -Path $DirToCheck) {

        if ($isLinux) {
            $listing = find "$DirToCheck" -follow -maxdepth 0 -type f -perm /137 -print
            if ($null -eq $listing -or $listing -eq "") {
                $FindingDetails += "No files found in $DirToCheck that do not have proper permissions" | Out-String
            }
            else {
                $FindingDetails += "Files not set to 640 in $DirToCheck" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
                $FindingDetails += $listing | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $listing += Get-ChildItem -Path "$DirToCheck" -File -Force | ForEach-Object {$_.FullName}
            foreach ($LogFile in $listing) {
                $FindingDetails += Get-Acl -Path "$LogFile" | Format-Table -Wrap | Out-String
            }
            # Because we cannot reliably check permissions to 640, increment errorcount to make a manual check
            $ErrorCount = -1
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge 1) {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails = '$CATALINA_BASE/conf was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222946 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222946
        STIG ID    : TCAT-AS-000371
        Rule ID    : SV-222946r960933_rule
        CCI ID     : CCI-000163, CCI-001813
        Rule Name  : SRG-APP-000119-AS-000079
        Rule Title : $CATALINA_BASE/conf folder permissions must be set to 750.
        DiscussMD5 : CE0A9F5BA6AF667EFD14FD584705C6EE
        CheckMD5   : 4E579E8DB415FD4800C36FA503E5D9A7
        FixMD5     : 7D5F6BA0B92573DC374A073FB128A609
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $Folder = "conf"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $Folder
    if (Test-Path -Path $DirToCheck) {

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -type d -perm /027 -print
            if ($null -eq $listing -or $listing -eq "") {
                $FindingDetails += "No directories found in $DirToCheck that do not have proper permissions" | Out-String
            }
            else {
                $FindingDetails += "Directories not set to 750 in $DirToCheck" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
                $FindingDetails += $listing | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            # Because we cannot reliably check permissions to 750, increment errorcount to make a manual check
            $ErrorCount = -1
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge 1) {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails = '$CATALINA_BASE/conf was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222947 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222947
        STIG ID    : TCAT-AS-000380
        Rule ID    : SV-222947r960936_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-AS-000080
        Rule Title : Jar files in the $CATALINA_HOME/bin/ folder must have their permissions set to 640.
        DiscussMD5 : EAF33C2B2CC05E8F3D8EA904D7402E76
        CheckMD5   : 296BBB354A7560949A68A9D91A8C9AB0
        FixMD5     : 7351C28160119D85E4CE4F6A4FDA2AD5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "bin"
    $DirToCheck = Join-Path -Path $TomcatInstance.HomeDir -ChildPath $FileName
    if (Test-Path -Path $DirToCheck) {

        if ($isLinux) {
            $listing = find $DirToCheck/*jar -follow -maxdepth 0 -type f -perm /137 -print
            if ($null -eq $listing -or $listing -eq "") {
                $FindingDetails += "No files found in $DirToCheck that do not have proper permissions" | Out-String
            }
            else {
                $FindingDetails += "Files not set to 640 in $DirToCheck" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
                $FindingDetails += $listing | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $listing += Get-ChildItem -Path "$DirToCheck" -File -Filter "*jar" -Recurse -Force | ForEach-Object {$_.FullName}
            foreach ($LogFile in $listing) {
                $FindingDetails += Get-Acl -Path "$LogFile" | Format-Table -Wrap | Out-String
            }
            # Because we cannot reliably check permissions to 740, increment errorcount to make a manual check
            $ErrorCount++
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
    }
    else {
        $FindingDetails = '$CATALINA_HOME/bin was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222948 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222948
        STIG ID    : TCAT-AS-000390
        Rule ID    : SV-222948r960939_rule
        CCI ID     : CCI-001493, CCI-001494, CCI-001495, CCI-002235
        Rule Name  : SRG-APP-000121-AS-000081
        Rule Title : $CATALINA_HOME/bin folder permissions must be set to 750.
        DiscussMD5 : 4F7283313CC51F14FA27BE91E6E9B1BB
        CheckMD5   : F6E84CA1794EDF4F4DA9473553129B72
        FixMD5     : 5BC56FD26903A1AFF98C1E9E4DD2EAE2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $Folder = "bin"
    $DirToCheck = Join-Path -Path $TomcatInstance.HomeDir -ChildPath $Folder
    if (Test-Path -Path $DirToCheck) {

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -type d -perm /027 -print
            if ($null -eq $listing -or $listing -eq "") {
                $FindingDetails += "No directories found in $DirToCheck that do not have proper permissions" | Out-String
            }
            else {
                $FindingDetails += "Directories not set to 750 in $DirToCheck" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
                $FindingDetails += $listing | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            # Because we cannot reliably check permissions to 750, increment errorcount to make a manual check
            $ErrorCount++
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails = '$CATALINA_HOME/bin was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222949 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222949
        STIG ID    : TCAT-AS-000450
        Rule ID    : SV-222949r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-AS-000092
        Rule Title : Tomcat user UMASK must be set to 0027.
        DiscussMD5 : 66D99A620E9FBAF8DD5860A433F3E678
        CheckMD5   : 0352E80A4417AD7205E99C7699E361FB
        FixMD5     : 1496764CD57822980460B4C718F1FC63
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $ConfigSetting = "umask"
    $ExpectedValue = "0027"
    if ($IsLinux) {
        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $DetectedValue = Select-String -Pattern "^\s*$($ConfigSetting)" -Path $FilePath
            if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                $ErrorCount++
                $DetectedValue = "Not Found"
            }
            else {
                $DetectedValue = (($DetectedValue.ToString() -split "=")[1]).trim()
                if ("$DetectedValue" -ne "$ExpectedValue") {
                    $ErrorCount++
                }
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Setting:`n`t$($ConfigSetting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String

            If ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            Else {
                $Status = "NotAFinding"
            }
        }
        else {
            $FindingDetails += "Service file was not found" | Out-String
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

Function Get-V222950 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222950
        STIG ID    : TCAT-AS-000470
        Rule ID    : SV-222950r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Stack tracing must be disabled.
        DiscussMD5 : 19E4D8897AB805C6A557E391FC4A46CB
        CheckMD5   : 08F322EA9CD7B345DDE20439B9F0E94A
        FixMD5     : DF558ED0075265FE4F5D8A651266ACD2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $ElementName = "Connector"
    $AttributeName = "allowTrace"
    $BadValue = "true"
    $ExpectedValue = "Not set or set to false"

    $OtherName = "webapps"
    $SearchPaths = @()
    $SearchPaths += $(Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName)
    $OtherPath = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $OtherName
    $OtherWebXmls = Get-ChildItem -Path "$OtherPath" -Include web.xml -Recurse | Where-Object {$_.FullName -like "*WEB-INF*"} | Select-Object -expand FullName
    foreach ($SinglePath in $OtherWebXmls) {
        $SearchPaths += $SinglePath
    }
    $FileName = "web.xml"
    foreach ($SinglePath in $SearchPaths) {
        $FindingDetails += "Config File:`n`t$SinglePath" | Out-String
        $FindingDetails += "" | Out-String
        $PathSinglePath = Split-Path -Path $SinglePath
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath $PathSinglePath
        if ($null -eq $XmlObject -or $XmlObject -eq "") {
            $FindingDetails += "No $ElementName Elements found" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $Elements = $XmlObject.GetElementsByTagName($ElementName)

            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "" | Out-String
            }
            else {
                Foreach ($element in $Elements) {
                    $DetectedValue = $($element.$AttributeName)
                    if ($null -eq $DetectedValue -or $DetectedValue -EQ "" ) {
                        $DetectedValue = "Not Found"
                    }
                    $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$DetectedValue`n" | Out-String
                    $FindingDetails += "" | Out-String
                    if ( $($element.$AttributeName) -match $BadValue ) {
                        $ErrorCount++
                    }
                }
            }
        }
    }

    if ($ErrorCount -ge 1) {
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

Function Get-V222951 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222951
        STIG ID    : TCAT-AS-000490
        Rule ID    : SV-222951r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : The shutdown port must be disabled.
        DiscussMD5 : 54BEAF820DA1DCA1E955B1F60FEA9BFE
        CheckMD5   : 8E51F08CF9CE20EE7D43955BA50A0D5D
        FixMD5     : 0FCDAD7D04283A6BDDE8072E2CB41B09
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ElementCount = 0
    $ErrorCount = 0
    $FileName = "server.xml"
    $ElementName = "Server"
    $AttributeName = "port"
    $ExpectedValue = "-1"
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $Elements = $XmlObject.GetElementsByTagName($ElementName)
        $FindingDetails += "Config File:`n`t$(Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName)" | Out-String
        $FindingDetails += "" | Out-String

        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
        }
        else {
            Foreach ($element in $Elements) {
                $ElementCount++
                $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
                $attributeValue = $element.$($AttributeName)
                if ($null -eq $attributeValue -or $attributeValue -eq "" ) {
                    $attributeValue = "No Value Found"
                    $ErrorCount++
                }
                else {
                    if ($attributeValue -ne $ExpectedValue) {
                        $ErrorCount++
                    }
                }
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "Detected Value:`n`t$($attributeValue)`n" | Out-String
            }
        }

        if ($ElementCount -ge 1) {
            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
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

Function Get-V222952 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222952
        STIG ID    : TCAT-AS-000500
        Rule ID    : SV-222952r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Unapproved connectors must be disabled.
        DiscussMD5 : 8C79234D67B4E490D63B3F73D93F9AEB
        CheckMD5   : A08EB0A7A4EDE9E9794D9C170501B62B
        FixMD5     : 3CFC2B94D063B82561F6E5DEA7772947
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "Connector"
        $AttributeName = "port"

        $Elements = $XmlObject.GetElementsByTagName("$ElementName")
        $ExpectedValue = "All Connector ports are approved in the SSP"
        $FindingDetails += "Expected:`n`t$($ExpectedValue)`n" | Out-String

        if ($null -eq "$Elements" -or "$Elements" -eq "") {
            $FindingDetails += "No $Elements elements found" | Out-String
        }
        else {
            Foreach ($element in $Elements) {
                $AttributeValue = $element.$AttributeName
                $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
                $FindingDetails += "Value:`n`t$($AttributeValue)`n" | Out-String
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

Function Get-V222953 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222953
        STIG ID    : TCAT-AS-000510
        Rule ID    : SV-222953r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : DefaultServlet debug parameter must be disabled.
        DiscussMD5 : 9C4A04596710F9083B49B0A39C23E552
        CheckMD5   : 02213CDF8A4EFBE7E63B152929B66F7D
        FixMD5     : D3E7166333EEE1F7E7005E2ED630ADBF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "web.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "servlet"
        $ParamName = "debug"
        $ExpectedValue = "0"
        $Elements = ($XmlObject.GetElementsByTagName("servlet") | Where-Object {$_."servlet-class" -like "*DefaultServlet"})
        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
            $ErrorCount++
        }
        else {
            foreach ($element in $Elements) {
                $ServletName = ($element."servlet-name")
                $FindingDetails += "Servlet:`n`t$ServletName" | Out-String
                $DetectedValue = ($element."init-param" | Where-Object "param-name" -EQ $ParamName)."param-value"
                if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                    $DetectedValue = "Not Found"
                }
                $FindingDetails += "Element:`n`t$ParamName" | Out-String
                $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                if ($DetectedValue -notmatch $ExpectedValue) {
                    $ErrorCount++
                }
                $FindingDetails += "Detected Value:`n`t$DetectedValue`n" | Out-String
            }
            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
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

Function Get-V222954 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222954
        STIG ID    : TCAT-AS-000520
        Rule ID    : SV-222954r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : DefaultServlet directory listings parameter must be disabled.
        DiscussMD5 : 1B5F49C60D3BF01C5C19176474B0EA27
        CheckMD5   : F235FF718D052AB487F1E6F5955FCAC8
        FixMD5     : 8673BC59A11FF8EA952CD107B40227D0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "web.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "servlet"
        $ParamName = "listings"
        $ExpectedValue = "false"
        $Elements = ($XmlObject.GetElementsByTagName("servlet") | Where-Object {$_."servlet-class" -like "*DefaultServlet"})
        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $ElementName Elements found" | Out-String
            $ErrorCount++
        }
        else {
            foreach ($element in $Elements) {
                $ServletName = ($element."servlet-name")
                $FindingDetails += "Servlet:`n`t$ServletName" | Out-String
                $DetectedValue = ($element."init-param" | Where-Object "param-name" -EQ $ParamName)."param-value"
                if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                    $DetectedValue = "Not Found"
                }
                $FindingDetails += "Element:`n`t$ParamName" | Out-String
                $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                if ($DetectedValue -notmatch $ExpectedValue) {
                    $ErrorCount++
                }
                $FindingDetails += "Detected Value:`n`t$DetectedValue`n" | Out-String
            }
            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
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

Function Get-V222955 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222955
        STIG ID    : TCAT-AS-000530
        Rule ID    : SV-222955r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : The deployXML attribute must be set to false in hosted environments.
        DiscussMD5 : 4B7BC5DBB20F8223B9A0635979BD52D6
        CheckMD5   : 719A8112E3CAABB9B4AB0B77A29344A2
        FixMD5     : 50CD38B54B5A7DD36E2FFA08AF5518CB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $ConfigFound = $false
    $ProcessFound = $false
    $ConfigSetting = "ExecStart"
    $FlagName = "-security"
    $ParamName = "java.security.manager"
    $AttributeName = "deployXML"
    $ExpectedValue = "false (unless authorized and documented in SSP)"
    $SecManagerEnabled = $false
    $NoProcess = 0

    if ($IsLinux) {
        $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $ConfigLine = Select-String -Pattern "^\s*$($ConfigSetting)" -Path $FilePath
            $ConfigFound = $null -ne ($ConfigLine | Select-String -Pattern "$FlagName")
        }
        else {
            $FilePath = "Not Found"
        }

    }
    else {
        $ProcessString = $TomcatInstance.ProcessString
        if($ProcessString -eq "Not Found"){
            $NoProcess++
        }
    }

    $ProcessFound = $null -ne ($ProcessString | Select-String -Pattern $ParamName)

    if ($ConfigFound -eq $true -or $ProcessFound -eq $true) {
        $SecManagerEnabled = $true
    }

    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $Elements = $XmlObject.GetElementsByTagName("Host")

        if (($Elements | Measure-Object).count -eq 0) {
            $FindingDetails += "No $Elements Elements found" | Out-String
        }
        else {
            foreach ($element in $Elements) {
                $DetectedValue = $element.deployXML
                if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "") {
                    if ($SecManagerEnabled -eq $true) {
                        $DetectedValue = "Set to false by security manager"
                    }
                    else {
                        $DetectedValue = "Not found (true by default)"
                        $ErrorCount++
                    }
                }
                else {
                    if ($DetectedValue -match "true") {
                        $ErrorCount++
                    }
                }
                $FindingDetails += "Host Element Name:`n`t$($element.name)" | Out-String
                $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String
            }
        }

        if ($NoProcess -eq 0) {
            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
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

Function Get-V222956 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222956
        STIG ID    : TCAT-AS-000540
        Rule ID    : SV-222956r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Autodeploy must be disabled.
        DiscussMD5 : CAAFCFBBFD9C4BC51549BF5F43DCDF15
        CheckMD5   : 36B63D619BD69DE5C09F9CFD9F5FEF8E
        FixMD5     : EDB0C104FEA3521F5B3B255DE96C3317
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $AttributeName = "autoDeploy"
    $ExpectedValue = "false (unless authorized and documented in SSP)"

    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $Elements = $XmlObject.GetElementsByTagName("Host")

            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $Elements Elements found" | Out-String
            }
            else {
                foreach ($element in $Elements) {
                    $DetectedValue = $element.autoDeploy
                    if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "") {
                        $DetectedValue = "Not Found (default setting is true)"
                        $ErrorCount++
                    }
                    else {
                        if ($DetectedValue -match "true") {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Host Element Name:`n`t$($element.name)" | Out-String
                    $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String
                }
            }

            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222957 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222957
        STIG ID    : TCAT-AS-000550
        Rule ID    : SV-222957r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : xpoweredBy attribute must be disabled.
        DiscussMD5 : 25E21FA97F5B279D356CC5F97C68E8D7
        CheckMD5   : 7943B14DA69A90A66F6E2E74FF52E475
        FixMD5     : 2F96793C9101F35E372EB40D3390BCD3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $CheckCount = 0
    $FileName = "server.xml"
    $ElementName = "Connector"
    $AttributeName = "xpoweredBy"
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $Elements = $XmlObject.GetElementsByTagName($ElementName)

        $CombinedPath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
        $FindingDetails += "Config File:`n`t$($CombinedPath)" | Out-String

        Foreach ($element in $Elements) {
            $attributeValue = $element.$AttributeName
            if ($null -eq $attributeValue -or $attributeValue -eq "") {
                continue
            }

            $CheckCount++

            $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
            $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
            $FindingDetails += "Attribute Value:`n`t$($attributeValue)`n" | Out-String

            if ($attributeValue -eq "true") {
                $ErrorCount++
            }
        }

        if ($CheckCount -lt 1) {
            $FindingDetails += "`nNo Vulnerable $($ElementName) Elements Found" | Out-String
            $Status = "NotAFinding"
        }
        else {
            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
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

Function Get-V222958 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222958
        STIG ID    : TCAT-AS-000560
        Rule ID    : SV-222958r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Example applications must be removed.
        DiscussMD5 : D05294ED43A9CDDA9B1BA1F24A5A8563
        CheckMD5   : CDDE971322F4B2045973D7F968ACC084
        FixMD5     : 8FD2FA95261359C910F12A79F70CBB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName1 = "webapps"
    $Filename2 = "examples"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $FileName1
    $DirToCheck = Join-Path -Path $DirToCheck -ChildPath $FileName2

    if (Test-Path -Path $DirToCheck) {
        $FindingDetails += "$DirToCheck exists." | Out-String
        $Status = "Open"
    }
    else {
        $FindingDetails += "$DirToCheck does not exist." | Out-String
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

Function Get-V222959 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222959
        STIG ID    : TCAT-AS-000570
        Rule ID    : SV-222959r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Tomcat default ROOT web application must be removed.
        DiscussMD5 : CCB6F7449D852AF08D044C61BFE4E567
        CheckMD5   : 9076A30EB89BD7EA1F0BB5EB57932D45
        FixMD5     : 99CADAC0B8E915C68F214CD9E7C0BC68
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $DirName1 = "webapps"
    $Dirname2 = "ROOT"
    $DirToCheck = Get-JoinPath -Path $TomcatInstance.BaseDir -ChildPath $DirName1 -AdditionalChildPath $DirName2
    $Files = @("index.jsp", "RELEASE-NOTES.txt")
    $DefaultStrings = @("licensed by the Apache Software Foundation", "licensed to the Apache Software Foundation")

    foreach ($filename in $Files) {
        $FileToCheck = Join-Path -Path $DirToCheck -ChildPath $filename
        if (Test-Path -Path $FileToCheck) {
            foreach ($stringcheck in $DefaultStrings) {
                $FileCheck = Select-String -Path $FileToCheck -Pattern "$stringcheck"
                if ($null -ne $FileCheck -and $FileCheck -ne "") {
                    $FindingDetails += "$FileToCheck contains default text." | Out-String
                    $ErrorCount++
                }
            }
        }
    }
    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += "No default files found in $DirToCheck" | Out-String
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

Function Get-V222960 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222960
        STIG ID    : TCAT-AS-000580
        Rule ID    : SV-222960r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Documentation must be removed.
        DiscussMD5 : 910B96245039048006A1BF67BBE0CE79
        CheckMD5   : 7DF292E6AAA51F01667A25ADB8E52D26
        FixMD5     : CC52025B2278E1AA8D53F06875EAE353
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName1 = "webapps"
    $Filename2 = "docs"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $FileName1
    $DirToCheck = Join-Path -Path $DirToCheck -ChildPath $FileName2

    if (Test-Path -Path $DirToCheck) {
        $FindingDetails += "$DirToCheck exists." | Out-String
        $Status = "Open"
    }
    else {
        $FindingDetails += "$DirToCheck does not exist." | Out-String
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

Function Get-V222961 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222961
        STIG ID    : TCAT-AS-000590
        Rule ID    : SV-222961r1043177_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-AS-000014
        Rule Title : Applications in privileged mode must be approved by the ISSO.
        DiscussMD5 : 004261B483059A3B4AEEBFFE602CA598
        CheckMD5   : 660DF90259719FFAF184958BB9137716
        FixMD5     : 0FBB7A34267162F2766BA9B1B47A16DE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName = "context.xml"
    $ElementName = "Context"
    $AttributeName = "privileged"
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $Elements = $XmlObject.GetElementsByTagName($ElementName)

        $Path = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
        $FindingDetails += "Config File:`n`t$($Path)" | Out-String
        $FindingDetails += " " | Out-String

        Foreach ($element in $Elements) {
            $attributeValue = $element.$AttributeName
            if ($null -eq $attributeValue -or $attributeValue -eq "") {
                $attributeValue = "Not Found"
            }
            else {
                $CheckCount++
            }

            $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
            $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
            $FindingDetails += "Attribute Value:`n`t$($attributeValue)`n" | Out-String
        }

        $webAppsDir = Join-Path -Path $TomcatInstance.BaseDir -ChildPath "webapps"
        $listing = Get-ChildItem -Path $webAppsDir -Recurse -File $FileName
        foreach ($file in $listing) {
            $fullName = $file.FullName
            $XmlObject = Get-XMLObject -FileName $file.Name -TomcatInstance $TomcatInstance -FilePath $file.Directory
            if ($null -ne $XmlObject) {
                $Elements = $XmlObject.GetElementsByTagName($ElementName)

                Foreach ($element in $Elements) {
                    $attributeValue = $element.$AttributeName
                    if ($null -eq $attributeValue -or $attributeValue -eq "") {
                        $attributeValue = "Not Found"
                    }
                    else {
                        $CheckCount++
                    }

                    $FindingDetails += "Config File:`n`t$($fullName)" | Out-String
                    $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                    $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
                    $FindingDetails += "Attribute Value:`n`t$($attributeValue)`n" | Out-String
                }
            }
        }

        if ($CheckCount -le 0) {
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

Function Get-V222962 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222962
        STIG ID    : TCAT-AS-000600
        Rule ID    : SV-222962r1051118_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-APP-000148-AS-000101
        Rule Title : Tomcat management applications must use LDAP realm authentication.
        DiscussMD5 : F90050D45B33C847630DEAF17022B202
        CheckMD5   : A90B3C1D0AA5A50A3767D3A6F49285B4
        FixMD5     : 2E01CEBF34E43B862E49E6289118FA45
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ManagerXML = @((Get-ChildItem $TomcatInstance.ConfDir -Recurse | Where-Object { $_.Name -like "manager.xml" }).FullName)
    $ManagerDir = Get-JoinPath -Path $TomcatInstance.BaseDir -ChildPath "webapps" -AdditionalChildPath "manager"
    $HostManagerDir = Get-JoinPath -Path $TomcatInstance.BaseDir -ChildPath "webapps" -AdditionalChildPath "host-manager"

    if ($ManagerXML -or (Test-Path -Path $ManagerDir) -or (Test-Path -Path $HostManagerDir)) {
        $ErrorCount = 0
        $FileName = "server.xml"
        $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Realm"
            $ExpectedValue = "JNDIRealm must exist with configuration"
            $Elements = ($XmlObject.GetElementsByTagName("Realm") | Where-Object {$_."className" -like "*JNDIRealm"})
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No JNDI $ElementName Elements found" | Out-String
                $ErrorCount++
            }
            else {
                foreach ($element in $Elements) {
                    $FindingDetails += "Element:`n`t$ElementName" | Out-String
                    $FindingDetails += "`nExpected Value:`n`t$ExpectedValue" | Out-String
                    $DetectedValue = ($element | Format-List | Out-String)
                    $FindingDetails += "`nDetected Value:"
                    foreach ($line in $DetectedValue) {
                        $FindingDetails += "`t$line" | Out-String
                    }
                }
            }
            if ($ErrorCount -gt 0) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
            }
        }
        else {
            $FindingDetails += "Manager and Host-manager not installed." | Out-String
            $Status = "NotAFinding"
        }
    }
    else {
        $FindingDetails += "Manager not installed" | Out-String
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

Function Get-V222963 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222963
        STIG ID    : TCAT-AS-000610
        Rule ID    : SV-222963r960972_rule
        CCI ID     : CCI-000765
        Rule Name  : SRG-APP-000149-AS-000102
        Rule Title : JMX authentication must be secured.
        DiscussMD5 : 37307E8CB891B93E4E46302A710AC6EE
        CheckMD5   : 0D0EC706B865CD15517A317232DE7CB0
        FixMD5     : 6BFE8960536071B46C68F810EE9F17EB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $NoProcess = 0
    $ExpectedValue = "'true' or not set"
    $DetectedValue = "Not Found"
    $Setting = "jmxremote.authenticate"

    if ($IsLinux) {
        $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $JmxRemote = Select-String -Pattern "jmxremote.authenticate=(true|false)" -Path $FilePath | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -ne $JmxRemote -and $JmxRemote -ne "") {
                $DetectedValue = (($JmxRemote -split "=")[1]).trim()
                if ($DetectedValue -eq "false") {
                    $ErrorCount++
                }
            }
            else {
                $DetectedValue = "Not Found"
            }
        }
        else {
            $FilePath = "Not Found"
        }

        $MatchedPattern = $ProcessString | Select-String -Pattern "jmxremote.authenticate=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}

        if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
            $DetectedPS = "Not Found"
        }
        else {
            $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
            if ( $DetectedPS -eq "false" ) {
                $ErrorCount++
            }
        }

        $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String

    }
    else {

        if ( $TomcatInstance.ProcessString -ne "Not Found" -and $TomcatInstance.ProcessString -notlike "*//PS Unsupported") {

            $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern "jmxremote.authenticate=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}

            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedValue = "Not Found"
            }
            else {
                $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedValue -eq "false" ) {
                    $ErrorCount++
                }
            }
        }
        else {
            $NoProcess++
        }

        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String

    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
        if ($NoProcess -eq 0) {
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

Function Get-V222964 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222964
        STIG ID    : TCAT-AS-000630
        Rule ID    : SV-222964r1016511_rule
        CCI ID     : CCI-000770, CCI-004045
        Rule Name  : SRG-APP-000153-AS-000104
        Rule Title : TLS must be enabled on JMX.
        DiscussMD5 : 14B3E13A59B52DB8F2545A970F8248F8
        CheckMD5   : 2126F94D1DC5386A49420B1C6476E5FA
        FixMD5     : 6BFE8960536071B46C68F810EE9F17EB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $NoProcess = 0
    $ExpectedValue = "true"
    $DetectedValue = "Not Found"
    $Extension = "jmxremote"
    $Setting = "jmxremote.ssl"
    $ExtInUse = $true

    if ($IsLinux) {

        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $JmxExtension = Select-String -Pattern $Extension -Path $FilePath
            if ($null -eq $JmxExtension -or $JmxExtension -eq "") {
                $ExtInUse = $false
            }
            else {
                $JmxRemote = Select-String -Pattern "jmxremote.ssl=(true|false)" -Path $FilePath | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $JmxRemote -and $JmxRemote -ne "") {
                    $DetectedValue = (($JmxRemote -split "=")[1]).trim()
                    if ($DetectedValue -eq "false") {
                        $ErrorCount++
                    }
                }
                else {
                    $DetectedValue = "Not Found"
                }
                $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
                $FindingDetails += "" | Out-String
            }

        }
        else {
            $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
            $JmxExtension = $ProcessString | Select-String -Pattern $Extension

            if ($null -eq $JmxExtension -or $JmxExtension -eq "") {
                $ExtInUse = $false
            }
            else {
                $FilePath = "Not Found"
                $MatchedPattern = $ProcessString | Select-String -Pattern "jmxremote.ssl=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}

                if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                    $DetectedPS = "Not Found"
                }
                else {
                    $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
                    if ( $DetectedPS -eq "false" ) {
                        $ErrorCount++
                    }
                }
                $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String
            }
        }

    }
    else {

        if ( $TomcatInstance.ProcessString -ne "Not Found" -and $TomcatInstance.ProcessString -notlike "*//PS Unsupported") {

            $JmxExtension = $TomcatInstance.ProcessString | Select-String -Pattern $Extension

            if ($null -eq $JmxExtension -or $JmxExtension -eq "") {
                $ExtInUse = $false
            }
            else {
                $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern "jmxremote.ssl=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                    $DetectedValue = "Not Found"
                }
                else {
                    $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                    if ( $DetectedValue -eq "false" ) {
                        $ErrorCount++
                    }
                }
            }
        }
        else{
            $NoProcess++
        }

        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
    }

    if ($ExtInUse -eq $false) {
        $Status = "Not_Applicable"
        $FindingDetails = "jmxremote management extensions are not used"
    }
    elseif ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
        if ($NoProcess -eq 0) {
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

Function Get-V222965 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222965
        STIG ID    : TCAT-AS-000690
        Rule ID    : SV-222965r961029_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-APP-000172-AS-000121
        Rule Title : LDAP authentication must be secured.
        DiscussMD5 : 94E9D1684B82A127CDA3CB4CFEFAD6D0
        CheckMD5   : 726FDBB9FF41B1836F86355D22999F7D
        FixMD5     : 06E157AC44670710DCB569C80E65A0B4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $ConfigFile = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $ConfigFile) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($ConfigFile)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Realm"
            $ExpectedValue = "JNDIRealm must use LDAPS"
            $ExpectedChecker = "ldaps"
            $Elements = ($XmlObject.GetElementsByTagName("Realm") | Where-Object {$_."className" -like "*JNDIRealm"})
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No JNDI $ElementName Elements found" | Out-String
                $ErrorCount++
            }
            else {
                foreach ($element in $Elements) {
                    $FindingDetails += "Element:`n`t$ElementName" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $DetectedValue = $element.connectionURL
                    if ($DetectedValue -notmatch $ExpectedChecker) {
                        $ErrorCount++
                    }
                    $FindingDetails += "Detected Value:`n`t$DetectedValue" | Out-String
                }
            }

            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222967 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222967
        STIG ID    : TCAT-AS-000710
        Rule ID    : SV-222967r985893_rule
        CCI ID     : CCI-000186, CCI-004910
        Rule Name  : SRG-APP-000176-AS-000125
        Rule Title : Keystore file must be protected.
        DiscussMD5 : CE237C7BB6D1EAA3CF9770ED838B54CD
        CheckMD5   : 606A09F8C7425782741957C46B1E5CC4
        FixMD5     : 64149E4B1BFE527F000D30E6477C516D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $KeyStoreCount = 0
    $FileName = "server.xml"
    $AttributeName = "keystore"
    $ConfigFile = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $ConfigFile) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$ConfigFile" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Connector"
            $ExpectedValue = "Keystore must be configured within Tomcat directory tree with permissions 640 user:root and group:tomcat"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
            }
            else {
                foreach ($element in $Elements) {
                    if ($null -ne $($element.keystoreFile) -and $($element.keystoreFile -ne "")) {
                        $KeystoreFile = $($element.keystoreFile)
                    }
                    else {
                        if ($null -ne $($element.SSLHostConfig.Certificate.KeystoreFile) -and $($element.SSLHostConfig.Certificate.KeystoreFile -ne "")) {
                            $KeystoreFile = $($element.SSLHostConfig.Certificate.KeystoreFile)
                        }
                        else {
                            if ($null -ne $($element.SSLHostConfig.Certificate.certificateKeystoreFile) -and $($element.SSLHostConfig.Certificate.certificateKeystoreFile -ne "")) {
                                $KeystoreFile = $($element.SSLHostConfig.Certificate.certificateKeystoreFile)
                            }
                            else {
                                continue
                            }
                        }
                    }
                    if (Test-Path ($KeystoreFile)) {
                        $FilePath = $KeystoreFile
                        $KeyStoreCount++
                        if (-not ($KeystoreFile.Contains($TomcatInstance.BaseDir))) {
                            $ErrorCount++
                            $FindingDetails += "$KeystoreFile not contained in tomcat folder path." | Out-String
                        }
                    }
                    else {
                        if (Test-Path (Join-Path -Path $TomcatInstance.BaseDir -ChildPath $KeystoreFile)) {
                            $FilePath = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $KeystoreFile
                            $KeyStoreCount++
                        }
                        else {
                            if (Test-Path(Join-Path -Path $TomcatInstance.ConfDir -ChildPath $KeystoreFile)) {
                                $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $KeystoreFile
                                $KeyStoreCount++
                            }
                            else {
                                $FindingDetails += "Keystore $KeystoreFile could not be found on filesystem." | Out-String
                                $ErrorCount++
                                continue
                            }
                        }
                    }

                    $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t"
                    if ($isLinux) {
                        $FindingDetails += ls -l $FilePath | Out-String
                        $Checker = (ls -l $FilePath | grep "rw-r-----" | grep "root tomcat")
                        if ($null -eq $Checker -or $Checker -eq "") {
                            $ErrorCount++
                        }
                    }
                    else {
                        $FindingDetails += Get-Acl -Path "$FilePath" | Format-Table -Wrap | Out-String
                    }
                }
            }
            if ($KeyStoreCount -eq 0) {
                $FindingDetails += "No Keystores defined." | Out-String
                $Status = "NotAFinding"
            }
            else {
                if ($ErrorCount -eq 0) {
                    if ($isLinux) {
                        $Status = "NotAFinding"
                    }
                }
                else {
                    $Status = "Open"
                }
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found'
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

Function Get-V222968 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222968
        STIG ID    : TCAT-AS-000750
        Rule ID    : SV-222968r961050_rule
        CCI ID     : CCI-000803, CCI-001188, CCI-002418, CCI-002421, CCI-002475, CCI-002476
        Rule Name  : SRG-APP-000179-AS-000129
        Rule Title : Tomcat must use FIPS-validated ciphers on secured connectors.
        DiscussMD5 : 2C26784A4D70B7676476E2D9D25DFD0A
        CheckMD5   : 60B6116B9762E212256C4B44E52699C4
        FixMD5     : 665E0974DCD72E1FBC3A6C581C3E2F51
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
        $FindingDetails += "" | Out-String
        $ElementName = "Listener"
        $AttributeName = "FIPSMode"
        $ExpectedValue = "on"
        $logs = "logs"
        $CatalinaOutFile = "catalina.out"
        $FullCatalinaOut = Get-JoinPath -Path $TomcatInstance.BaseDir -ChildPath $logs -AdditionalChildPath $CatalinaOutFile
        $LogError = "failed to set property \[fipsmode\] to \[on\]"
        $FoundCount = 0
        $Elements = ($XmlObject.GetElementsByTagName("$ElementName") | Where-Object {$_."className" -like "*AprLifecycleListener"})

        if ($null -eq "$Elements" -or "$Elements" -eq "") {
            $FindingDetails += "No AprLifecycleListener $ElementName elements found" | Out-String
            $ErrorCount++
        }
        else {
            Foreach ($element in $Elements) {
                $AttributeValue = $element.$AttributeName
                if ($null -ne $AttributeValue -and $AttributeValue -ne "") {
                    $FoundCount++
                    break
                }
                else {
                    $AttributeValue = "Not Found"
                }
            }

            $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
            $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($AttributeValue)`n" | Out-String
            $FindingDetails += "" | Out-String

            if ($FoundCount -eq 0 ) {
                $ErrorCount++
            }
        }

        if (Test-Path -Path $FullCatalinaOut) {
            $CatalinaOutExists = $true
            $CatalinaOut = Select-String -Pattern "$LogError" -Path $FullCatalinaOut

            if ($null -ne $CatalinaOut -and $CatalinaOut -ne "") {
                $ErrorCount++
            }
            else {
                $CatalinaOut = "Not Found"
            }

            $FindingDetails += "Log File:`n`t$($CatalinaOutFile)" | Out-String
            $FindingDetails += "Expected:`n`tDoes not contain 'failed to set property [fipsmode] to [on]'" | Out-String
            $FindingDetails += "Detected Value:`n`t$($CatalinaOut)`n" | Out-String
        }
        else {
            $FindingDetails += "$FullCatalinaOut could not be found" | Out-String
            $CatalinaOutExists = $false
        }

        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if ($CatalinaOutExists -eq $true) {
                $Status = "NotAFinding"
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

Function Get-V222969 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222969
        STIG ID    : TCAT-AS-000780
        Rule ID    : SV-222969r961095_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-AS-000146
        Rule Title : Access to JMX management interface must be restricted.
        DiscussMD5 : 84996D605AB24452CDEDE39D471C7873
        CheckMD5   : 856A9457D88C7CF141BCB1FECD15D629
        FixMD5     : C3B763F42463108C591589E261CCB721
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $NoProcess = 0
    $ExpectedValue = "The IP address that is associated with the JMX process must be dedicated to system management usage"
    $Extension = "jmxremote"
    $Setting = "jmxremote.host"
    $ExtInUse = $true
    $IPPattern = "jmxremote.host\=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|.*:.*:.*)"

    if ($IsLinux) {
        $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
        $JmxExtension = @()
        $JmxExtension += $ProcessString | Select-String -Pattern $Extension

        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $JmxExtension += Select-String -Pattern $Extension -Path $FilePath
        }

        if ( $null -eq $JmxExtension -or ($JmxExtension | Measure-Object).Count -eq 0 ) {
            $ExtInUse = $false
        }
        else {
            if (Test-Path -Path $FilePath) {
                $JmxRemote = Select-String -Pattern $IPPattern -Path $FilePath | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $JmxRemote -and $JmxRemote -ne "") {
                    $DetectedValue = (($JmxRemote -split "=")[1]).trim()
                }
                else {
                    $DetectedValue = "Not Found"
                    $ErrorCount++
                }
                $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
                $FindingDetails += "" | Out-String
            }
            else {

                $FilePath = "Not Found"
                $MatchedPattern = $ProcessString | Select-String $IPPattern | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}

                if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                    $DetectedPS = "Not Found"
                    $ErrorCount++
                }
                else {
                    $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
                }
                $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String

            }
        }
    }
    else {
        if ( $TomcatInstance.ProcessString -ne "Not Found") {

            $JmxExtension = $TomcatInstance.ProcessString | Select-String -Pattern $Extension

            if ($null -eq $JmxExtension -or $JmxExtension -eq "") {
                $ExtInUse = $false
            }
            else {
                $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern $IPPattern | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                    $DetectedValue = "Not Found"
                    $ErrorCount++
                }
                else {
                    $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                }
            }
        }
        else{
            $NoProcess++
        }
        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
    }

    if ($ExtInUse -eq $false -and "$NoProcess" -eq 0 ) {
        $Status = "NotAFinding"
        $FindingDetails = "jmxremote management extensions are not used"
    }
    elseif ($ErrorCount -ge 1) {
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

Function Get-V222970 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222970
        STIG ID    : TCAT-AS-000790
        Rule ID    : SV-222970r961095_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-AS-000146
        Rule Title : Access to Tomcat manager application must be restricted.
        DiscussMD5 : EA7CD728F160FFC163460E98EB18C7AA
        CheckMD5   : DBE42EFDB825F537398E62C9BE55BC2D
        FixMD5     : E3F197CFCB844247DFAB2171B164C7D2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ManagerInUse = 0
    $UserFile = "tomcat-users.xml"
    $XmlObject = Get-XMLObject -FileName $UserFile -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $ElementName = "user"
        $ManagerRoles = $XmlObject.GetElementsByTagName($ElementName)
        foreach ($user in $ManagerRoles) {
            If ($user."roles" -match "Manager*") {
                $ManagerInUse++
                break
            }
        }

        $ManagerXML = @((Get-ChildItem $TomcatInstance.BaseDir -Recurse | Where-Object { $_.Name -like "manager.xml" }).FullName)

        if ($ManagerXML) {
            $ManagerInUse++
        }

        if ($ManagerInUse -ge 2) {
            # Manger is in use.
            $HasRemoteAddrValve = $false
            $HasRemoteCIDRValve = $false

            $ContextFile = "context.xml"
            $FilePath = "webapps/manager/META-INF"
            $ExpectedValue = "Configured to restrict access to localhost or the management network"
            $XmlObject = Get-XMLObject -FileName $ContextFile -TomcatInstance $TomcatInstance -FilePath $FilePath
            if ($null -ne $XmlObject) {
                $ElementName = "RemoteAddrValve"
                $Elements = ($XmlObject.GetElementsByTagName("Valve") | Where-Object {$_."className" -like "*RemoteAddrValve"})
                if (($Elements | Measure-Object).Count -eq 0) {
                    $FindingDetails += "No $($ElementName) Elements found" | Out-String
                    $FindingDetails += "" | Out-String
                }
                else {
                    $FoundAllow = $false
                    $ParamName = "allow"
                    $DetectedValue = ($Elements."$ParamName")
                    if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "" -or "$DetectedValue" -eq " ") {
                        $DetectedValue = "Not Found"
                    }
                    $FindingDetails += "Classname:`n`t$($ElementName)" | Out-String
                    $FindingDetails += "Attribute:`n`t$($ParamName)" | Out-String
                    $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String

                    $FoundAllow = $DetectedValue -ne "Not Found" # Some value is configured

                    $FoundDeny = $false
                    $ParamName = "deny"
                    $DetectedValue = ($Elements."$ParamName")
                    if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "" -or "$DetectedValue" -eq " ") {
                        $DetectedValue = "Not Found"
                    }
                    $FindingDetails += "Classname:`n`t$($ElementName)" | Out-String
                    $FindingDetails += "Attribute:`n`t$($ParamName)" | Out-String
                    $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String

                    $FoundDeny = $DetectedValue -ne "Not Found" # Some value is configured

                    if ($FoundAllow -eq $true -or $FoundDeny -eq $true) {
                        # The RemoteAddrValve valve is configured but restrictions aren't set up.
                        $HasRemoteAddrValve = $true
                    }
                }

                $ElementName = "RemoteCIDRValve"
                $Elements = ($XmlObject.GetElementsByTagName("Valve") | Where-Object {$_."className" -like "*RemoteCIDRValve"})
                if (($Elements | Measure-Object).Count -eq 0) {
                    $FindingDetails += "No $($ElementName) Elements found" | Out-String
                    $FindingDetails += "" | Out-String
                }
                else {
                    $FoundAllow = $false
                    $ParamName = "allow"
                    $DetectedValue = ($Elements."$ParamName")
                    if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "" -or "$DetectedValue" -eq " ") {
                        $DetectedValue = "Not Found"
                    }
                    $FindingDetails += "Classname:`n`t$($ElementName)" | Out-String
                    $FindingDetails += "Attribute:`n`t$($ParamName)" | Out-String
                    $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String

                    $FoundAllow = $DetectedValue -ne "Not Found" # Some value is configured

                    $FoundDeny = $false
                    $ParamName = "deny"
                    $DetectedValue = ($Elements."$ParamName")
                    if ($null -eq "$DetectedValue" -or "$DetectedValue" -eq "" -or "$DetectedValue" -eq " ") {
                        $DetectedValue = "Not Found"
                    }
                    $FindingDetails += "Classname:`n`t$($ElementName)" | Out-String
                    $FindingDetails += "Attribute:`n`t$($ParamName)" | Out-String
                    $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String

                    $FoundDeny = $DetectedValue -ne "Not Found" # Some value is configured

                    if ($FoundAllow -eq $true -or $FoundDeny -eq $true) {
                        # The RemoteCIDRValve valve is configured but restrictions aren't set up.
                        $HasRemoteCIDRValve = $true
                    }
                }

                if ($HasRemoteAddrValve -eq $false -and $HasRemoteCIDRValve -eq $false) {
                    $Status = "Open"
                }
            }
        }
        else {
            $FindingDetails += "The manager application is not present or not in use" | Out-String
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

Function Get-V222971 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222971
        STIG ID    : TCAT-AS-000800
        Rule ID    : SV-222971r1043178_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219-AS-000147
        Rule Title : Tomcat servers must mutually authenticate proxy or load balancer connections.
        DiscussMD5 : 12B225FFA373964C2DB6DEEAC43F5036
        CheckMD5   : AD681BC39C5A66B608636E49F58978C6
        FixMD5     : 870B5F945A1A59119B8FFBB539847193
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName = "server.xml"
    $ConfigFile = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $ConfigFile) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$ConfigFile" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Connector"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
                $Status = "NotAFinding"
            }
            else {
                foreach ($element in $Elements) {

                    $FindingDetails += "Element:`n`t$ElementName" | Out-String
                    if ($null -eq $($element.address) -or $($element.address) -eq "") {
                        $AddressValue = "Not defined"
                    }
                    else {
                        $AddressValue = $($element.address)
                    }
                    $FindingDetails += "Address:`n`t$AddressValue" | Out-String
                    if ($null -eq $($element.clientAuth) -or $($element.clientAuth) -eq "") {
                        $ClientAuthValue = "Not defined"
                    }
                    else {
                        $ClientAuthValue = $($element.clientAuth)
                    }
                    $FindingDetails += "ClientAuth:`n`t$ClientAuthValue" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222973 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222973
        STIG ID    : TCAT-AS-000820
        Rule ID    : SV-222973r1043180_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-AS-000150
        Rule Title : Tomcat must be configured to limit data exposure between applications.
        DiscussMD5 : D7874FBF515629EAB98F287F2C03B71E
        CheckMD5   : 0DF4484C2DDDBA5AFDE3E04BEBCC9CCA
        FixMD5     : 1BBB84BB4EA4683151A88D6BB0084C9C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $NoProcess = 0
    $ExpectedValue = "true"
    $Setting = "RECYCLE_FACADES"

    if ($IsLinux) {

        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $EnforceEncoding = Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" -Path $FilePath | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -ne $EnforceEncoding -and $EnforceEncoding -ne "") {
                $DetectedValue = (($EnforceEncoding -split "=")[1]).trim()
                if ($DetectedValue -eq "false") {
                    $ErrorCount++
                }
            }
            else {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }

            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FilePath = "Not Found"
            $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
            $MatchedPattern = $ProcessString | Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}

            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedPS = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedPS -eq "false" ) {
                    $ErrorCount++
                }
            }

            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String
        }
    }
    else {
        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String

        if ( $TomcatInstance.ProcessString -ne "Not Found" -and $TomcatInstance.ProcessString -notlike "*//PS Unsupported" ) {
            $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
            $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedValue -eq "false" ) {
                    $ErrorCount++
                }
            }
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $NoProcess++
            $FileName = "catalina.properties"
            $DetectedValue = "Not Found"
            $CatPath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
            $FilePath = $CatPath
            if (Test-Path -Path $FilePath) {
                $AllowBackslash = Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" -Path $FilePath | Select-String -Pattern "^\s*\#" -NotMatch | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $AllowBackslash -and $AllowBackslash -ne "") {
                    $DetectedValue = (($AllowBackslash -split "=")[1]).trim()
                    if ($DetectedValue -eq "false") {
                        $ErrorCount++
                    }
                    else{
                        $NoProcess = 0
                    }
                }
                else {
                    $DetectedValue = "Not Found"
                    $ErrorCount++
                }
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
        if ($NoProcess -eq 0) {
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

Function Get-V222974 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222974
        STIG ID    : TCAT-AS-000860
        Rule ID    : SV-222974r961122_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-APP-000225-AS-000154
        Rule Title : Clusters must operate on a trusted network.
        DiscussMD5 : CB9989F07A1974AEF6A081C580081F34
        CheckMD5   : 40050A44BA1CA2D4C5770CFF618FD8CD
        FixMD5     : 9A600282C2B0959944EB8054E05DB2F6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $InterceptorFound = $false
    $FileName = "server.xml"
    $ConfigFile = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $ConfigFile) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$ConfigFile" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Cluster"
            $InterceptorElement = "Interceptor"
            $AttributeValue = "org.apache.catalina.tribes.group.interceptors.EncryptInterceptor"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
                $Status = "Not_Applicable"
            }
            else {
                $FindingDetails += "System is configured for clustering." | Out-String
                $FindingDetails += "" | Out-String
                $AttributeResult += $XmlObject.GetElementsByTagName("$InterceptorElement")
                if (($AttributeResult | Measure-Object).count -gt 0) {
                    foreach ($SingleAttribute in $AttributeResult) {
                        if ($SingleAttribute.className -eq "$AttributeValue") {
                            $InterceptorFound = $true
                        }
                    }
                }
                $FindingDetails += "Element:`n`t$InterceptorElement" | Out-String
                $FindingDetails += "Expected Value:`n`tEnabled" | Out-String
                if ($InterceptorFound) {
                    $Status = "NotAFinding"
                    $FindingDetails += "Detected Value:`n`tEnabled" | Out-String
                }
                else {
                    $Status = "Open"
                    $FindingDetails += "Detected Value:`n`tNot Found" | Out-String
                }
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222975 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222975
        STIG ID    : TCAT-AS-000920
        Rule ID    : SV-222975r961167_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-AS-000169
        Rule Title : ErrorReportValve showServerInfo must be set to false.
        DiscussMD5 : CC145DBA5E8E54FE74AC1EE7E2FEF5DF
        CheckMD5   : BD6149BDFF683B667D9A67904D964111
        FixMD5     : 0C9F1A651187C7780CC0746EFF52675A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $ElementName = "Host"
            $AttributeName = "className"
            $AttributeValue = "org.apache.catalina.valves.ErrorReportValve"
            $AttributeName2 = "showServerInfo"
            $AttributeValue2 = "false"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
                $Status = "NotAFinding"
            }
            else {
                foreach ($element in $Elements) {
                    $LogCount = 0
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Host:`n`t$($element.name)" | Out-String
                    foreach ($SingleValve in $Element.Valve) {
                        if ($null -eq $($SingleValve.$AttributeName2) -or $($SingleValve.$AttributeName2) -eq "") {
                            $DetectedAttribute2 = "Not Defined"
                        }
                        else {
                            $DetectedAttribute2 = $($SingleValve.$AttributeName2)
                        }
                        if ($($SingleValve.$AttributeName) -match $AttributeValue -and $($SingleValve.$AttributeName2 -match $AttributeValue2)) {
                            $LogCount++
                            $FindingDetails += "$AttributeName Setting:`n`t$($SingleValve.$AttributeName)" | Out-String
                            $FindingDetails += "$AttributeName2 Setting:`n`t$DetectedAttribute2" | Out-String
                            $FindingDetails += "" | Out-String
                            break
                        }
                    }
                    if ($LogCount -eq 0) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "No $AttributeValue valve found for $ElementName with $AttributeName2 set to $AttributeValue2." | Out-String
                        $FindingDetails += "" | Out-String
                        $ErrorCount++
                    }
                }

                if ($ErrorCount -eq 0) {
                    $Status = "NotAFinding"
                }
                else {
                    $Status = "Open"
                }
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222976 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222976
        STIG ID    : TCAT-AS-000930
        Rule ID    : SV-222976r961170_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-AS-000170
        Rule Title : Default error pages for manager application must be customized.
        DiscussMD5 : E6FBFD8CE4AFB4E2BE3D85314F6D8D6E
        CheckMD5   : 6332075AA7551D38A1015A012C0F0A16
        FixMD5     : 332CC97FCA20858895C77061C3B07054
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $Filenames = @("401.jsp", "402.jsp", "403.jsp")
    $DefaultIndicators = @('user username="tomcat"', 'role rolename="manager-gui"')
    $ChildPath = "webapps/manager/WEB-INF/jsp"
    $FilePath = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $ChildPath
    foreach ($singleFile in $Filenames) {
        $CheckFile = Join-Path -Path $FilePath -ChildPath $singleFile
        if (Test-Path -Path $CheckFile) {
            foreach ($singleIndicator in $DefaultIndicators) {
                $IsDefault = Select-String -Path $CheckFile -Pattern $singleIndicator
                if ($null -ne $IsDefault -and $IsDefault -ne "") {
                    $ErrorCount++
                    $FindingDetails += "$CheckFile contains default error pages." | Out-String
                    break
                }
            }
        }
    }
    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += "No default error page files found."
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

Function Get-V222977 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222977
        STIG ID    : TCAT-AS-000940
        Rule ID    : SV-222977r961170_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-AS-000170
        Rule Title : ErrorReportValve showReport must be set to false.
        DiscussMD5 : 80D6DF83DAD8CA3874EFE07F97C89158
        CheckMD5   : 8989AD036E29052CFEEC6D7AFA3C244A
        FixMD5     : 9101E2791BD542A0E88793B9E82B6E07
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $ElementName = "Host"
            $AttributeName = "className"
            $AttributeValue = "org.apache.catalina.valves.ErrorReportValve"
            $AttributeName2 = "showReport"
            $AttributeValue2 = "false"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
                $Status = "NotAFinding"
            }
            else {
                foreach ($element in $Elements) {
                    $LogCount = 0
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Host:`n`t$($element.name)" | Out-String
                    foreach ($SingleValve in $Element.Valve) {
                        if ($null -eq $($SingleValve.$AttributeName2) -or $($SingleValve.$AttributeName2) -eq "") {
                            $DetectedAttribute2 = "Not Defined"
                        }
                        else {
                            $DetectedAttribute2 = $($SingleValve.$AttributeName2)
                        }
                        if ($($SingleValve.$AttributeName) -match $AttributeValue -and $($SingleValve.$AttributeName2 -match $AttributeValue2)) {
                            $LogCount++
                            $FindingDetails += "$AttributeName Setting:`n`t$($SingleValve.$AttributeName)" | Out-String
                            $FindingDetails += "$AttributeName2 Setting:`n`t$DetectedAttribute2" | Out-String
                            $FindingDetails += "" | Out-String
                            break
                        }
                    }
                    if ($LogCount -eq 0) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "No $AttributeValue valve found for $ElementName with $AttributeName2 set to $AttributeValue2." | Out-String
                        $FindingDetails += "" | Out-String
                        $ErrorCount++
                    }
                }

                if ($ErrorCount -eq 0) {
                    $Status = "NotAFinding"
                }
                else {
                    $Status = "Open"
                }
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found'
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

Function Get-V222979 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222979
        STIG ID    : TCAT-AS-000970
        Rule ID    : SV-222979r1043182_rule
        CCI ID     : CCI-002038, CCI-002361, CCI-004895
        Rule Name  : SRG-APP-000295-AS-000263
        Rule Title : Idle timeout for the management application must be set to 10 minutes.
        DiscussMD5 : 74703F915CD21B4D73A8845A27DB04E4
        CheckMD5   : CA351F6C94A8A55846C9852DAADB1335
        FixMD5     : B1AE18C91222964F3EA15C9BBD162203
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $CheckCount = 0
    $FileName = "web.xml"
    $ElementName = "session-timeout"
    $ExpectedValue = 10
    $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $Elements = $XmlObject.GetElementsByTagName($ElementName)

        $Path = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
        $FindingDetails += "Config File:`n`t$($Path)" | Out-String
        $FindingDetails += " " | Out-String

        Foreach ($element in $Elements) {
            $DetectedValue = $element.InnerXML
            if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                continue
            }

            $CheckCount++

            $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String

            if ($DetectedValue -gt $ExpectedValue) {
                $ErrorCount++
            }
        }

        $Dir = Join-Path -Path $TomcatInstance.BaseDir -ChildPath "webapps/manager/META-INF"
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath $Dir

        if ($null -ne $XmlObject) {
            $Elements = $XmlObject.GetElementsByTagName($ElementName)
            Foreach ($element in $Elements) {
                $DetectedValue = $element.InnerXML
                if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                    continue
                }

                $CheckCount++
                $filePath += $XmlObject.BaseURI -replace "file://"
                $FindingDetails += "Config File:`n`t$($filePath)" | Out-String
                $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String

                if ($DetectedValue -gt $ExpectedValue) {
                    $ErrorCount++
                }
            }
        }
        if ($CheckCount -eq 0) {
            $FindingDetails += "$($ElementName) Not Defind" | Out-String
            $Status = "Open"
        }
        else {
            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
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

Function Get-V222980 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222980
        STIG ID    : TCAT-AS-001020
        Rule ID    : SV-222980r961278_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-APP-000315-AS-000094
        Rule Title : LockOutRealms must be used for management of Tomcat.
        DiscussMD5 : 74A869DE5DA0B580DF5A81D519491668
        CheckMD5   : 95AD1AEA44227973934AD0A535A20C50
        FixMD5     : 3A0D15D645F43FB1E13D85A763606E54
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Realm"
            $AttributeName = "className"
            $AttributeValue = "org.apache.catalina.realm.LockOutRealm"
            $ExpectedValue = "LockOutRealm nested in Engine, Host or Context"
            $ExpectedCheck = "Engine|Host|Context"
            $Elements = ($XmlObject.GetElementsByTagName("Realm") | Where-Object {$_."$AttributeName" -like "$AttributeValue"})
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $AttributeValue $ElementName Elements found" | Out-String
                $ErrorCount++
            }
            else {
                foreach ($element in $Elements) {
                    if ($element.$AttributeName -eq $AttributeValue) {
                        $FindingDetails += "Element:`n`t$ElementName" | Out-String
                        $FindingDetails += "$($AttributeName):`n`t$AttributeValue" | Out-String
                        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                        $DetectedValue = $($element.ParentNode.LocalName)
                        if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                            $DetectedValue = "Not Found"
                            $ErrorCount++
                        }
                        else {
                            if (($DetectedValue | Select-String -Pattern $ExpectedCheck) -eq "") {
                                $ErrorCount++
                            }
                        }
                        $FindingDetails += "Parent:`n`t$DetectedValue" | Out-String
                    }
                }
            }

            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222981 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222981
        STIG ID    : TCAT-AS-001030
        Rule ID    : SV-222981r961281_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-AS-000199
        Rule Title : LockOutRealms failureCount attribute must be set to 5 failed logins for admin users.
        DiscussMD5 : CC623FF4135F26CF776DE15EAB192775
        CheckMD5   : 40B0B071BAA02E667D7F89E4C30ED3AA
        FixMD5     : 5C43FEBC35770A86860A5C06B277497D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Realm"
            $AttributeName = "className"
            $AttributeValue = "org.apache.catalina.realm.LockOutRealm"
            $AttributeName2 = "failureCount"
            $ExpectedValue = "5"
            $Elements = ($XmlObject.GetElementsByTagName("Realm") | Where-Object {$_."$AttributeName" -like "$AttributeValue"})
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $AttributeValue $ElementName Elements found" | Out-String
                $ErrorCount++
            }
            else {
                foreach ($element in $Elements) {
                    $FindingDetails += "Element:`n`t$ElementName" | Out-String
                    $FindingDetails += "Attribute:`n`t$AttributeName2" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $DetectedValue = $($element.$AttributeName2)
                    if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                        $DetectedValue = "Not Found"
                        $ErrorCount++
                    }
                    else {
                        if ($DetectedValue -ne $ExpectedValue) {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Detected Value:`n`t$DetectedValue" | Out-String
                }
            }

            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222982 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222982
        STIG ID    : TCAT-AS-001040
        Rule ID    : SV-222982r961281_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-AS-000199
        Rule Title : LockOutRealms lockOutTime attribute must be set to 600 seconds (10 minutes) for admin users.
        DiscussMD5 : 8DFE6F79F6B0E9FCFD2662463E11F35B
        CheckMD5   : 632FA1253AA8E13A6243245562923F5D
        FixMD5     : 5CA030BBE44CBA453580415FD1020758
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Realm"
            $AttributeName = "className"
            $AttributeValue = "org.apache.catalina.realm.LockOutRealm"
            $AttributeName2 = "lockOutTime"
            $ExpectedValue = "600"
            $Elements = ($XmlObject.GetElementsByTagName("Realm") | Where-Object {$_."$AttributeName" -like "$AttributeValue"})
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $AttributeValue $ElementName Elements found" | Out-String
                $ErrorCount++
            }
            else {
                foreach ($element in $Elements) {
                    $FindingDetails += "Element:`n`t$ElementName" | Out-String
                    $FindingDetails += "Attribute:`n`t$AttributeName2" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $DetectedValue = $($element.$AttributeName2)
                    if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                        $DetectedValue = "Not Found"
                        $ErrorCount++
                    }
                    else {
                        if ($DetectedValue -ne $ExpectedValue) {
                            $ErrorCount++
                        }
                    }
                    $FindingDetails += "Detected Value:`n`t$DetectedValue" | Out-String
                }
            }

            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found'
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

Function Get-V222983 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222983
        STIG ID    : TCAT-AS-001050
        Rule ID    : SV-222983r961353_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-APP-000340-AS-000185
        Rule Title : Tomcat user account must be set to nologin.
        DiscussMD5 : E91DBEE975CD93ADFF162C2A9505D0B4
        CheckMD5   : 8CE612B2DAD1FB9EBD5428154DE6EDEB
        FixMD5     : C68F4E98CA4993149D9B65413427BE3A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($isLinux) {
        $ExpectedValues = @("/usr/sbin/nologin", "/bin/false", "/bin/true", "/sbin/nologin")
        $ExpectedValue = "/usr/sbin/nologin or other shell that prevents login"
        $ApacheUserShell = grep tomcat /etc/passwd | awk -F: '{print $7}'
        $FindingDetails += "Attribute:`n`tUser Shell" | Out-String
        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`n`t$ApacheUserShell" | Out-String
        if ($ApacheUserShell -in $ExpectedValues) {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += "User: $($TomcatInstance.ProcessUser)" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222984 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222984
        STIG ID    : TCAT-AS-001060
        Rule ID    : SV-222984r961353_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-APP-000340-AS-000185
        Rule Title : Tomcat user account must be a non-privileged user.
        DiscussMD5 : 065A2CB743C5A066F64993CD7680056C
        CheckMD5   : 5A26A3F3E0E696588D9D6EAAED656DCB
        FixMD5     : 3E14A0B9AE5237F9A44F9D52997A8575
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($isLinux) {
        $ExpectedValue = "Not 0 and documented if running as a privileged user"
        $ApacheUID = grep tomcat /etc/passwd | awk -F: '{print $3}'

        if ($ApacheUID -ge 1000) {
            $Status = "NotAFinding"
        }
		elseif($ApacheUID -eq 0){
			$Status = "Open"
		}

		$FindingDetails += "Attribute:`n`tUser Shell" | Out-String
        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`n`t$ApacheUID" | Out-String
    }
    else {
		$ExpectedValue = "Must run as a non-privileged account"
		$FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
        $FindingDetails += "User:`n`t$($TomcatInstance.ProcessUser)" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222985 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222985
        STIG ID    : TCAT-AS-001080
        Rule ID    : SV-222985r961362_rule
        CCI ID     : CCI-002234
        Rule Name  : SRG-APP-000343-AS-000030
        Rule Title : Application user name must be logged.
        DiscussMD5 : 8A7DD4888082D6CDB7399C60A539D10D
        CheckMD5   : 9A64B327BA6C1A3175DD5194A6B1CC08
        FixMD5     : 53587B67886A3382D309970E879352E6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Host"
            $ChildElement = "Valve"
            $AttributeName = "pattern"
            $AttributePattern = '%u'
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            $ExpectedValue = "All valve elements must contain %u"

            if ($null -eq "$Elements" -or "$Elements" -eq "") {
                $FindingDetails += "No $Elements elements found" | Out-String
            }
            else {
                Foreach ($element in $Elements) {
                    $ClassName = $element.$ChildElement | Where-Object {$_."className" -like "*AccessLogValve"}
                    if ($null -ne "$ClassName" -and "$ClassName" -ne "") {
                        $AttributeValue = $element.$ChildElement.$AttributeName
                        $FindingDetails += "Element:`n`t$ChildElement  ClassName=$($ClassName.className)" | Out-String
                        $FindingDetails += "Attribute:`n`t$AttributeName" | Out-String
                        if ( $null -eq "$AttributeValue" -or "$AttributeValue" -eq "" ) {
                            $AttributeValue = "No Value Found"
                            $ErrorCount++
                        }
                        else {
                            if ("$AttributeValue" -notmatch "$AttributePattern") {
                                $ErrorCount++
                            }
                        }
                        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                        $FindingDetails += "Detected Value:`n`t$($AttributeValue)`n" | Out-String
                    }
                    else {
                        $FindingDetails += "No Access Logging Valves found" | Out-String
                        $ErrorCount++
                    }
                }
            }
            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222986 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222986
        STIG ID    : TCAT-AS-001200
        Rule ID    : SV-222986r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-AS-000088
        Rule Title : $CATALINA_HOME folder must be owned by the root user, group tomcat.
        DiscussMD5 : 36C1358CFD58F2D9646F0004F948DF49
        CheckMD5   : CD9E0FAAC44F3E473779A1FBCFF5E644
        FixMD5     : 76F3B642F8611CD058F1FEBE2B30FBD0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $DirToCheck = $TomcatInstance.HomeDir
    $ExpectedOwner = "root"
    $ExpectedGroup = "tomcat"

    if ($isLinux) {
        $listing = find $DirToCheck -follow -maxdepth 0 -ls
        $DetectedOwner = echo $listing | awk '{print $5}'
        $DetectedGroup = echo $listing | awk '{print $6}'
        $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
        $FindingDetails += "Expected Owner:`n`t$ExpectedOwner" | Out-String
        $FindingDetails += "Detected Owner:`n`t$DetectedOwner" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
        $FindingDetails += "Expected Group:`n`t$ExpectedGroup" | Out-String
        $FindingDetails += "Detected Group:`n`t$DetectedGroup" | Out-String
        $FindingDetails += "" | Out-String
        if (($DetectedOwner -ne $ExpectedOwner) -or ($DetectedGroup -ne $ExpectedGroup)) {
            $ErrorCount++
        }

    }
    else {
        $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
        $ErrorCount = -1
    }

    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
    }
    elseif ($ErrorCount -ge 1) {
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

Function Get-V222987 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222987
        STIG ID    : TCAT-AS-001220
        Rule ID    : SV-222987r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-AS-000088
        Rule Title : $CATALINA_BASE/conf/ folder must be owned by root, group tomcat.
        DiscussMD5 : FBFD106EF2F337DA7F0481B31D8A4303
        CheckMD5   : 1364750BACC41F984B6510CA442A329A
        FixMD5     : 6B76F123AEEAD1D257737CC5853FCFB7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $DirToCheck = $TomcatInstance.ConfDir
    if (Test-Path -Path $DirToCheck) {
        $ExpectedOwner = "root"
        $ExpectedGroup = "tomcat"

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -ls
            $DetectedOwner = echo $listing | awk '{print $5}'
            $DetectedGroup = echo $listing | awk '{print $6}'
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Owner:`n`t$ExpectedOwner" | Out-String
            $FindingDetails += "Detected Owner:`n`t$DetectedOwner" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Group:`n`t$ExpectedGroup" | Out-String
            $FindingDetails += "Detected Group:`n`t$DetectedGroup" | Out-String
            $FindingDetails += "" | Out-String
            if (($DetectedOwner -ne $ExpectedOwner) -or ($DetectedGroup -ne $ExpectedGroup)) {
                $ErrorCount++
            }

        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            $ErrorCount = -1
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge 1) {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += '$CATALINA_BASE/conf was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222988 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222988
        STIG ID    : TCAT-AS-001250
        Rule ID    : SV-222988r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-AS-000088
        Rule Title : $CATALINA_BASE/logs/ folder must be owned by tomcat user, group tomcat.
        DiscussMD5 : 84CFAEA002B2C06A5D388A6F1653F392
        CheckMD5   : C3DAB267F850CE777E0DE6F9D8F22B44
        FixMD5     : ECBA9BA920CD37884372141E5EFF93BC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $logs = "logs"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $logs
    if (Test-Path -Path $DirToCheck) {
        $ExpectedOwner = "tomcat"
        $ExpectedGroup = "tomcat"

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -ls
            $DetectedOwner = echo $listing | awk '{print $5}'
            $DetectedGroup = echo $listing | awk '{print $6}'
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Owner:`n`t$ExpectedOwner" | Out-String
            $FindingDetails += "Detected Owner:`n`t$DetectedOwner" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Group:`n`t$ExpectedGroup" | Out-String
            $FindingDetails += "Detected Group:`n`t$DetectedGroup" | Out-String
            $FindingDetails += "" | Out-String
            if (($DetectedOwner -ne $ExpectedOwner) -or ($DetectedGroup -ne $ExpectedGroup)) {
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            $ErrorCount = -1
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge "1") {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += '$CATALINA_BASE/logs was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222989 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222989
        STIG ID    : TCAT-AS-001260
        Rule ID    : SV-222989r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-AS-000088
        Rule Title : $CATALINA_BASE/temp/ folder must be owned by tomcat user, group tomcat.
        DiscussMD5 : DFDFD04304842FFD5C0236B2CBAB0D17
        CheckMD5   : 94B2BBE1A9CF1FE68B140C95FCF2DDFF
        FixMD5     : 2A98848215A2E626CB2616868CEDBA48
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $temp = "temp"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $temp
    if (Test-Path -Path $DirToCheck) {
        $ExpectedOwner = "tomcat"
        $ExpectedGroup = "tomcat"

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -ls
            $DetectedOwner = echo $listing | awk '{print $5}'
            $DetectedGroup = echo $listing | awk '{print $6}'
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Owner:`n`t$ExpectedOwner" | Out-String
            $FindingDetails += "Detected Owner:`n`t$DetectedOwner" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Group:`n`t$ExpectedGroup" | Out-String
            $FindingDetails += "Detected Group:`n`t$DetectedGroup" | Out-String
            $FindingDetails += "" | Out-String
            if (($DetectedOwner -ne $ExpectedOwner) -or ($DetectedGroup -ne $ExpectedGroup)) {
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            $ErrorCount = -1
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge "1") {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += '$CATALINA_BASE/temp was not found'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222990 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222990
        STIG ID    : TCAT-AS-001270
        Rule ID    : SV-222990r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-AS-000088
        Rule Title : $CATALINA_BASE/temp folder permissions must be set to 750.
        DiscussMD5 : 5109D71B0C25BC4D0E7C89A083B5ADDB
        CheckMD5   : 6836C6A7027BC2DDF5D49C81680A6B40
        FixMD5     : 96C01AA9A859DF021FF987259F174BD1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $Folder = "temp"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $Folder
    if (Test-Path -Path $DirToCheck) {
        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -type d -perm /027 -print
            if ($null -eq $listing -or $listing -eq "") {
                $FindingDetails += "No directories found in $DirToCheck that do not have proper permissions" | Out-String
            }
            else {
                $FindingDetails += "Directories not set to 750 in $DirToCheck" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
                $FindingDetails += $listing | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            $ErrorCount = -1
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge "1") {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += '$CATALINA_BASE/temp was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222991 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222991
        STIG ID    : TCAT-AS-001280
        Rule ID    : SV-222991r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-AS-000088
        Rule Title : $CATALINA_BASE/work/ folder must be owned by tomcat user, group tomcat.
        DiscussMD5 : B4B545400816BDD986D76AF8A999C09F
        CheckMD5   : 4690B83E00D1885B148782B88B0B84B5
        FixMD5     : E4EC98555EBA52DDF6CF82DE0CE060A3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $work = "work"
    $DirToCheck = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $work
    if (Test-Path -Path $DirToCheck) {
        $ExpectedOwner = "tomcat"
        $ExpectedGroup = "tomcat"

        if ($isLinux) {
            $listing = find $DirToCheck -follow -maxdepth 0 -ls
            $DetectedOwner = echo $listing | awk '{print $5}'
            $DetectedGroup = echo $listing | awk '{print $6}'
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Owner:`n`t$ExpectedOwner" | Out-String
            $FindingDetails += "Detected Owner:`n`t$DetectedOwner" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Folder:`n`t$DirToCheck " | Out-String
            $FindingDetails += "Expected Group:`n`t$ExpectedGroup" | Out-String
            $FindingDetails += "Detected Group:`n`t$DetectedGroup" | Out-String
            $FindingDetails += "" | Out-String
            if (($DetectedOwner -ne $ExpectedOwner) -or ($DetectedGroup -ne $ExpectedGroup)) {
                $ErrorCount++
            }

        }
        else {
            $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
            $ErrorCount = -1
        }

        if ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
        elseif ($ErrorCount -ge "1") {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += '$CATALINA_BASE/work was not found.'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V222993 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222993
        STIG ID    : TCAT-AS-001320
        Rule ID    : SV-222993r985888_rule
        CCI ID     : CCI-001953, CCI-001954, CCI-002009, CCI-002010, CCI-004046, CCI-004047
        Rule Name  : SRG-APP-000391-AS-000239
        Rule Title : Multifactor certificate-based tokens (CAC) must be used when accessing the management interface.
        DiscussMD5 : 1E929DB5F40DE9643628068F37489EE1
        CheckMD5   : 6B3B15C4B33E768F18EBC5AA692CC54F
        FixMD5     : C35A15BAB2EC46C0C3374307CC751949
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ManagerInUse = 0
    $UserFile = "tomcat-users.xml"
    $XmlObject = Get-XMLObject -FileName $UserFile -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $ElementName = "user"
        $ManagerRoles = $XmlObject.GetElementsByTagName($ElementName)
        foreach ($user in $ManagerRoles) {
            If ($user."roles" -match "Manager*") {
                $ManagerInUse++
                $FindingDetails += "Manager roles assigned" | Out-String
                $FindingDetails += "" | Out-String
                break
            }
        }

        $ManagerXML = @((Get-ChildItem $TomcatInstance.ConfDir -Recurse | Where-Object { $_.Name -like "manager.xml" }).FullName)

        if ($ManagerXML) {
            $ManagerInUse++
            $FindingDetails += "Manager xml files detected" | Out-String
            $FindingDetails += "" | Out-String
        }
        $ManagerDir = Get-JoinPath -Path $TomcatInstance.BaseDir -ChildPath "webapps" -AdditionalChildPath "manager"
        if (Test-Path -Path $ManagerDir) {
            $ManagerInUse++
            $FindingDetails += "Manager directory detected in webapps directory" | Out-String
            $FindingDetails += "" | Out-String
        }

        if ($ManagerInUse -gt 0) {
            $ErrorCount = 0
            $FileName = "web.xml"
            $RelativePath = "/webapps/manager/WEB-INF"
            $FilePath = Join-Path -Path $TomcatInstance.BaseDir -ChildPath $RelativePath
            $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath $FilePath
            if ($null -ne $XmlObject) {
                $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
                $FindingDetails += "" | Out-String
                $ElementName = "auth-method"
                $ExpectedValue = "CLIENT-CERT"
                $Elements = ($XmlObject.GetElementsByTagName("$ElementName"))
                if (($Elements | Measure-Object).count -eq 0) {
                    $FindingDetails += "No $ElementName Elements found" | Out-String
                    $ErrorCount++
                }
                else {
                    foreach ($element in $Elements) {
                        $FindingDetails += "Element:`n`t$ElementName" | Out-String
                        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                        $DetectedValue = $($element."#text")
                        if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
                            $DetectedValue = "Not Found"
                            $ErrorCount++
                        }
                        else {
                            if ($DetectedValue -ne $ExpectedValue) {
                                $ErrorCount++
                            }
                        }
                        $FindingDetails += "Detected Value:`n`t$DetectedValue" | Out-String
                    }
                }

                if ($ErrorCount -eq 0) {
                    $Status = "NotAFinding"
                }
                else {
                    $Status = "Open"
                }
            }
        }
        else {
            $Status = "NotAFinding"
            $FindingDetails += "Manager not in use" | Out-String
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

Function Get-V222995 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222995
        STIG ID    : TCAT-AS-001460
        Rule ID    : SV-222995r961620_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-AS-000069
        Rule Title : The application server, when categorized as a high availability system within RMF, must be in a high-availability (HA) cluster.
        DiscussMD5 : 8EBDD37CE2143CE56906CD2489D00006
        CheckMD5   : 49867CD76A114A1F4D573C15127E7EEE
        FixMD5     : 7EC7336EB3E01F3546C5463DEF88305C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName = "server.xml"
    $ConfigFile = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $ConfigFile) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$ConfigFile" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Cluster"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            if (($Elements | Measure-Object).count -eq 0) {
                $DetectedValue += "Not Detected"
            }
            else {
                $DetectedValue += "Detected"
                $Status = "NotAFinding"
            }
            $FindingDetails += "Element:`n`t$ElementName" | Out-String
            $FindingDetails += "Expected State:`n`tDetected, if system is categorized as high within Risk Management Framework." | Out-String
            $FindingDetails += "Detected State:`n`t$DetectedValue" | Out-String
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml'
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

Function Get-V222996 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222996
        STIG ID    : TCAT-AS-001470
        Rule ID    : SV-222996r1067548_rule
        CCI ID     : CCI-002385, CCI-002605
        Rule Name  : SRG-APP-000435-AS-000163
        Rule Title : Tomcat server must be patched for security vulnerabilities.
        DiscussMD5 : 859C83604F1BA8CF6F58F7CE47E85FFE
        CheckMD5   : A9B95DB6843B79C068E4BCEBC17D765A
        FixMD5     : 3E083707D2A661F09F9F4CCDBF2B5C15
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    if ( $IsLinux ) {
        $versionScript = "version.sh"
        $scriptPath = Get-JoinPath -Path $TomcatInstance.HomeDir -ChildPath "bin" -AdditionalChildPath $versionScript
        if (Test-Path -Path $scriptPath) {
            $output = (& $scriptPath) | Out-String
        }
        else {
            $ErrorCount++
        }
    }
    else {
        try {
            Get-ChildItem -Path env:CATALINA_HOME
        }
        catch {
            Set-Item -Path env:CATALINA_HOME -Value $TomcatInstance.HomeDir
        }
        $versionScript = "version.bat"
        $scriptPath = Get-JoinPath -Path $TomcatInstance.HomeDir -ChildPath "bin" -AdditionalChildPath $versionScript
        if (Test-Path -Path $scriptPath) {
            $output = (Write-Output "$([System.Environment]::NewLine)" | & $scriptPath) | Out-String
        }
        else {
            $ErrorCount++
        }
    }

    if ($ErrorCount -ge 1) {
        $FindingDetails += "Version script was not found"
    }
    else {
        $ServerInfoSearch = "Server version:.*`n"
        $ServerNumberSearch = "Server number:.*`n"

        $ServerInfoLine = ($output | Select-String -Pattern $ServerInfoSearch).Matches.Value
        $ServerNumberLine = ($output | Select-String -Pattern $ServerNumberSearch).Matches.Value

        if ($null -ne $ServerInfoLine -and $ServerInfoLine -ne "") {
            $FindingDetails += $ServerInfoLine | Out-String
        }
        else {
            $FindingDetails += "Server version:`n`tNo Output  " | Out-String
        }

        if ($null -ne $ServerNumberLine -and $ServerNumberLine -ne "") {
            $FindingDetails += $ServerNumberLine | Out-String
        }
        else {
            $FindingDetails += "Server number:`n`tNo Output " | Out-String
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

Function Get-V222997 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222997
        STIG ID    : TCAT-AS-001560
        Rule ID    : SV-222997r1016518_rule
        CCI ID     : CCI-000172, CCI-001814, CCI-003938
        Rule Name  : SRG-APP-000495-AS-000220
        Rule Title : AccessLogValve must be configured for Catalina engine.
        DiscussMD5 : 2E569A2300FD6DF89B544C1AC78948DC
        CheckMD5   : BF79DCA2277F17516D5B6E538741E41E
        FixMD5     : E29D04C78C6A4B578C63EED2AD0F9297
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Engine"
            $ExpectedValue = "Each $ElementName element must contain an AccessLogValve"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")


            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
            }
            else {
                foreach ($element in $Elements) {

                    $ClassName = $element.Host.Valve | Where-Object {$_."className" -like "*AccessLogValve"}
                    if ($null -eq "$ClassName" -or "$ClassName" -eq "") {
                        $DetectedValue = "Not Found"
                        $ErrorCount++
                    }
                    else {
                        $DetectedValue = $($ClassName.className)
                    }
                    $FindingDetails += "$ElementName Element Name:`n`t$($element.name)" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$($DetectedValue)`n" | Out-String
                }
            }

            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V222998 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222998
        STIG ID    : TCAT-AS-001590
        Rule ID    : SV-222998r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-AS-000229
        Rule Title : Changes to $CATALINA_HOME/bin/ folder must be logged.
        DiscussMD5 : 9EB4CFCB40B1AE791EFF2BB23664C56E
        CheckMD5   : C391B65E27BF7C217B55C572CA3FE89E
        FixMD5     : 8137178D39D7A815BF620121B72CD3ED
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($IsLinux) {
        $ErrorCount = 0
        $BinPath = Join-Path -Path $TomcatInstance.BaseDir -ChildPath "bin"
        $Command = "sudo auditctl -l $BinPath | grep -i bin"
        $CommandOutput = sudo auditctl -l | grep -i $BinPath
        $TomcatRules = $CommandOutput | Select-String -Pattern $BinPath
        $WRULE = ""
        $ARULE = ""

        if ($null -eq $TomcatRules -or $TomcatRules -eq "") {
            $DetectedValue = "`tNot Found"
        }
        else {
            ForEach ( $Line in $TomcatRules) {
                $DetectedValue += "`t$Line" | Out-String
                $WRULE += $Line | Select-String -Pattern '^-w[\s]+(.*\/bin[\s]+)(-p[\s]+(.*w.*)[\s]+)'
                $ARULE += $Line | Select-String -Pattern '^-w[\s]+(.*\/bin[\s]+)(-p[\s]+(.*a.*)[\s]+)'

            }
        }
        if (($null -eq $WRULE -or $WRULE -eq "") -or ($null -eq $ARULE -or $ARULE -eq "")) {
            $ErrorCount++
        }

        $ExpectedValue = "-w $BinPath -p wa -k tomcat"
        $FindingDetails += "Command:`n`t$Command" | Out-String
        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`n$DetectedValue" | Out-String

        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V222999 {
    <#
    .DESCRIPTION
        Vuln ID    : V-222999
        STIG ID    : TCAT-AS-001591
        Rule ID    : SV-222999r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-AS-000229
        Rule Title : Changes to $CATALINA_BASE/conf/ folder must be logged.
        DiscussMD5 : 95F42BBBEA05330D6BD29ECAC8818223
        CheckMD5   : 808958016E92FFD8585AAD28DCD0402F
        FixMD5     : 9082954F472544351E07776DA194C407
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($IsLinux) {
        $ErrorCount = 0
        $ConfPath = Join-Path -Path $TomcatInstance.BaseDir -ChildPath "conf"
        $Command = "sudo auditctl -l $ConfPath | grep -i conf"
        $CommandOutput = sudo auditctl -l | grep -i $ConfPath
        $TomcatRules = $CommandOutput | Select-String -Pattern $ConfPath
        $WRULE = ""
        $ARULE = ""

        if ($null -eq $TomcatRules -or $TomcatRules -eq "") {
            $DetectedValue = "`tNot Found"
        }
        else {
            ForEach ( $Line in $TomcatRules) {
                $DetectedValue += "`t$Line" | Out-String
                $WRULE += $Line | Select-String -Pattern '^-w[\s]+(.*\/conf[\s]+)(-p[\s]+(.*w.*)[\s]+)'
                $ARULE += $Line | Select-String -Pattern '^-w[\s]+(.*\/conf[\s]+)(-p[\s]+(.*a.*)[\s]+)'

            }
        }
        if (($null -eq $WRULE -or $WRULE -eq "") -or ($null -eq $ARULE -or $ARULE -eq "")) {
            $ErrorCount++
        }

        $ExpectedValue = "-w $ConfPath -p wa -k tomcat"
        $FindingDetails += "Command:`n`t$Command" | Out-String
        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`n$DetectedValue" | Out-String

        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V223000 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223000
        STIG ID    : TCAT-AS-001592
        Rule ID    : SV-223000r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-AS-000229
        Rule Title : Changes to $CATALINA_HOME/lib/ folder must be logged.
        DiscussMD5 : 19D90B95E4B55E6263A76A38EA3FEEF2
        CheckMD5   : 67AD46196C554DBDDB77FE8F017784D5
        FixMD5     : 6C7F61F30C87CCEE48BBF960A9C7AA7D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($IsLinux) {
        $ErrorCount = 0
        $LibPath = Join-Path -Path $TomcatInstance.BaseDir -ChildPath "lib"
        $Command = "sudo auditctl -l $LibPath | grep -i lib"
        $CommandOutput = sudo auditctl -l | grep -i $LibPath
        $TomcatRules = $CommandOutput | Select-String -Pattern $LibPath
        $WRULE = ""
        $ARULE = ""

        if ($null -eq $TomcatRules -or $TomcatRules -eq "") {
            $DetectedValue = "`tNot Found"
        }
        else {
            ForEach ( $Line in $TomcatRules) {
                $DetectedValue += "`t$Line" | Out-String
                $WRULE += $Line | Select-String -Pattern '^-w[\s]+(.*\/lib[\s]+)(-p[\s]+(.*w.*)[\s]+)'
                $ARULE += $Line | Select-String -Pattern '^-w[\s]+(.*\/lib[\s]+)(-p[\s]+(.*a.*)[\s]+)'

            }
        }
        if (($null -eq $WRULE -or $WRULE -eq "") -or ($null -eq $ARULE -or $ARULE -eq "")) {
            $ErrorCount++
        }

        $ExpectedValue = "-w $LibPath -p wa -k tomcat"
        $FindingDetails += "Command:`n`t$Command" | Out-String
        $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`n$DetectedValue" | Out-String

        if ($ErrorCount -ge 1) {
            $Status = "Open"
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

Function Get-V223002 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223002
        STIG ID    : TCAT-AS-001660
        Rule ID    : SV-223002r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : STRICT_SERVLET_COMPLIANCE must be set to true.
        DiscussMD5 : 03D633254A0C89C682F0BDE38210880A
        CheckMD5   : 04A9152D27975A63CE5223FE787A7F78
        FixMD5     : 50D94FA91DA39259779A4CBFEE65BF97
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $GoodCount = 0
    $ExpectedValue = "true"
    $Setting = "STRICT_SERVLET_COMPLIANCE"

    if ($IsLinux) {

        $FilePath = "/etc/systemd/system/tomcat.service"

        if (Test-Path -Path $FilePath) {
            $ServletCompliance = Select-String -Pattern "STRICT_SERVLET_COMPLIANCE=(true|false)" -Path $FilePath | Select-String -Pattern "^\s*\#" -NotMatch | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -ne $ServletCompliance -and $ServletCompliance -ne "") {
                $DetectedValue = (($ServletCompliance -split "=")[1]).trim()
                if ( $DetectedValue -eq "true" ) {
                    $GoodCount++
                }
                else {
                    $ErrorCount++
                }
            }
            else {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }

        if ($GoodCount -eq 0 -and $ErrorCount -eq 0) {
            $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
            $MatchedPattern = $ProcessString | Select-String -Pattern "STRICT_SERVLET_COMPLIANCE=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedPS = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedValue -eq "true" ) {
                    $GoodCount++
                }
                else {
                    $ErrorCount++
                }
            }

            $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String
            $FindingDetails += "" | Out-String
        }
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        elseif ($GoodCount -ge 1) {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }

    }
    else {
        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
        $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
        if ( $TomcatInstance.ProcessString -ne "Not Found") {
            $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern "STRICT_SERVLET_COMPLIANCE=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedValue -eq "true" ) {
                    $GoodCount++
                }
                else {
                    $ErrorCount++
                }
            }
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }

        else {
            $FileName = "catalina.properties"
            $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
            $DetectedValue = "Not Found"
            if (Test-Path -Path $FilePath) {
                $ServletCompliance = Select-String -Pattern "STRICT_SERVLET_COMPLIANCE=(true|false)" -Path $FilePath | Select-String -Pattern "^\s*\#" -NotMatch | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $ServletCompliance -and $ServletCompliance -ne "") {
                    $DetectedValue = (($ServletCompliance -split "=")[1]).trim()
                    if ($DetectedValue -eq "true") {
                        $GoodCount++
                    }
                    else {
                        $ErrorCount++
                    }
                }
                else {
                    $DetectedValue = "Not Found"
                    $ErrorCount++
                }
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }

        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        elseif ($GoodCount -ge 1) {
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

Function Get-V223003 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223003
        STIG ID    : TCAT-AS-001670
        Rule ID    : SV-223003r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : RECYCLE_FACADES must be set to true.
        DiscussMD5 : 8261D5A7C5A203477E26B0301EC004D9
        CheckMD5   : 07A2960608A0E702F3AC35B1E6316899
        FixMD5     : 1470CA53FE05024D7E0178ECB4A71938
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $NoProcess = 0
    $ExpectedValue = "true"
    $DetectedValue = "Not Found"
    $Setting = "RECYCLE_FACADES"

    if ($IsLinux) {

        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $EnforceEncoding = Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" -Path $FilePath | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -ne $EnforceEncoding -and $EnforceEncoding -ne "") {
                $DetectedValue = (($EnforceEncoding -split "=")[1]).trim()
                if ($DetectedValue -eq "false") {
                    $ErrorCount++
                }
            }
            else {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }

            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FilePath = "Not Found"
            $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
            $MatchedPattern = $ProcessString | Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}

            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedPS = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedPS -eq "false" ) {
                    $ErrorCount++
                }
            }

            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String
        }
    }
    else {
        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String

        if ( $TomcatInstance.ProcessString -ne "Not Found"  -and $TomcatInstance.ProcessString -notlike "*//PS Unsupported" ) {
            $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
            $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedValue -eq "false" ) {
                    $ErrorCount++
                }
            }
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $NoProcess++
            $FileName = "catalina.properties"
            $DetectedValue = "Not Found"
            $CatPath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
            $FilePath = $CatPath
            if (Test-Path -Path $FilePath) {
                $AllowBackslash = Select-String -Pattern "org.apache.catalina.connector.RECYCLE_FACADES=(true|false)" -Path $FilePath | Select-String -Pattern "^\s*\#" -NotMatch | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $AllowBackslash -and $AllowBackslash -ne "") {
                    $DetectedValue = (($AllowBackslash -split "=")[1]).trim()
                    if ($DetectedValue -eq "false") {
                        $ErrorCount++
                    }
                    else{
                        $NoProcess = 0
                    }
                }
                else {
                    $DetectedValue = "Not Found"
                    $ErrorCount++
                }
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
        if ($NoProcess -eq 0) {
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

Function Get-V223004 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223004
        STIG ID    : TCAT-AS-001680
        Rule ID    : SV-223004r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : ALLOW_BACKSLASH must be set to false.
        DiscussMD5 : 4F0975FC84FB9DEEB5F348770A823D45
        CheckMD5   : E9EFD9D9EA2E0A7BE4BF58C27A3CBF90
        FixMD5     : 13E86504F47A4A198B5A920B3025E653
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $ExpectedValue = "false"
    $Setting = "ALLOW_BACKSLASH"
    $FileName = "catalina.properties"
    $CatPath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName

    if ($IsLinux) {

        $FilePaths = ("/etc/systemd/system/tomcat.service", "$CatPath")
        foreach ($FilePath in $FilePaths) {
            if (Test-Path -Path $FilePath) {
                $AllowBackslash = Select-String -Pattern "ALLOW_BACKSLASH=(true|false)" -Path $FilePath | Select-String -Pattern "^\s*\#" -NotMatch | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $AllowBackslash -and $AllowBackslash -ne "") {
                    $DetectedValue = (($AllowBackslash -split "=")[1]).trim()
                    if ($DetectedValue -eq "true") {
                        $ErrorCount++
                    }
                }
                else {
                    $DetectedValue = "Not Found"
                }
                $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
                $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
                $FindingDetails += "" | Out-String

            }
            else {
                $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
                $FilePath = "Not Found"
                $MatchedPattern = $ProcessString | Select-String -Pattern "ALLOW_BACKSLASH=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                    $DetectedPS = "Not Found"
                }
                else {
                    $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
                    if ( $DetectedPS -eq "true" ) {
                        $ErrorCount++
                    }
                }
                $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
                $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
                $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
                $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    else {

        $FindingDetails += "Setting:`n`t$($Setting)" | Out-String

        if ( $TomcatInstance.ProcessString -ne "Not Found" -and $TomcatInstance.ProcessString -notlike "*//PS Unsupported") {
            $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
            $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern "ALLOW_BACKSLASH=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedValue = "Not Found"
            }
            else {
                $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedValue -eq "true" ) {
                    $ErrorCount++
                }
            }
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $DetectedValue = "Not Found"
            $FilePath = $CatPath
            if (Test-Path -Path $FilePath) {
                $AllowBackslash = Select-String -Pattern "ALLOW_BACKSLASH=(true|false)" -Path $FilePath | Select-String -Pattern "^\s*\#" -NotMatch | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $AllowBackslash -and $AllowBackslash -ne "") {
                    $DetectedValue = (($AllowBackslash -split "=")[1]).trim()
                    if ($DetectedValue -eq "true") {
                        $ErrorCount++
                    }
                }
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ($ErrorCount -ge 1) {
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

Function Get-V223005 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223005
        STIG ID    : TCAT-AS-001690
        Rule ID    : SV-223005r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : ENFORCE_ENCODING_IN_GET_WRITER must be set to true.
        DiscussMD5 : 050ECC8D7EF33090725EE0A2DFEA0632
        CheckMD5   : 4E5CC6FC3C03163B34370244C8F14607
        FixMD5     : 8F2581656DCAAAC80CCAB09E813C5644
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $NoProcess = 0
    $ExpectedValue = "true"
    $DetectedValue = "Not Found"
    $Setting = "ENFORCE_ENCODING_IN_GET_WRITER"

    if ($IsLinux) {

        $FilePath = "/etc/systemd/system/tomcat.service"
        if (Test-Path -Path $FilePath) {
            $EnforceEncoding = Select-String -Pattern "ENFORCE_ENCODING_IN_GET_WRITER=(true|false)" -Path $FilePath | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -ne $EnforceEncoding -and $EnforceEncoding -ne "") {
                $DetectedValue = (($EnforceEncoding -split "=")[1]).trim()
                if ($DetectedValue -eq "false") {
                    $ErrorCount++
                }
            }
            else {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String

        }
        else {
            $ProcessString = $TomcatInstance.ProcessString -replace "^\s*\d*\s*"
            $FilePath = "Not Found"
            $MatchedPattern = $ProcessString | Select-String -Pattern "ENFORCE_ENCODING_IN_GET_WRITER=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedPS = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedPS = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedPS -eq "false" ) {
                    $ErrorCount++
                }
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Process String:`n`t$($ProcessString)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedPS)" | Out-String
        }

    }
    else {


        if ( $TomcatInstance.ProcessString -ne "Not Found" -and $TomcatInstance.ProcessString -notlike "*//PS Unsupported") {
            $MatchedPattern = $TomcatInstance.ProcessString | Select-String -Pattern "ENFORCE_ENCODING_IN_GET_WRITER=(true|false)" | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
            if ($null -eq $MatchedPattern -or $MatchedPattern -eq "") {
                $DetectedValue = "Not Found"
                $ErrorCount++
            }
            else {
                $DetectedValue = (($MatchedPattern -split "=")[1]).trim()
                if ( $DetectedValue -eq "false" ) {
                    $ErrorCount++
                }
            }
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Process String:`n`t$($TomcatInstance.ProcessString)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $NoProcess++
            $FileName = "catalina.properties"
            $DetectedValue = "Not Found"
            $CatPath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
            $FilePath = $CatPath
            if (Test-Path -Path $FilePath) {
                $EnforceEncoding = Select-String -Pattern "ENFORCE_ENCODING_IN_GET_WRITER=(true|false)" -Path $FilePath | Select-String -Pattern "^\s*\#" -NotMatch | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value}
                if ($null -ne $EnforceEncoding -and $EnforceEncoding -ne "") {
                    $DetectedValue = (($EnforceEncoding -split "=")[1]).trim()
                    if ($DetectedValue -eq "false") {
                        $ErrorCount++
                    }
                    else{
                        $NoProcess = 0
                    }
                }
                else {
                    $DetectedValue = "Not Found"
                    $ErrorCount++
                }
            }
            $FindingDetails += "Service File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "Setting:`n`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`n`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
        if ($NoProcess -eq 0) {
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

Function Get-V223006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223006
        STIG ID    : TCAT-AS-001700
        Rule ID    : SV-223006r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : Tomcat users in a management role must be approved by the ISSO.
        DiscussMD5 : D8F9B04DD782689B0CD2E08CE722FE36
        CheckMD5   : 9B1FF8B6320ADB4119DAD41472E78D92
        FixMD5     : 68FA8CEC52EE19ED299F74830EA5359E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $UserFile = "tomcat-users.xml"
    $XmlObject = Get-XMLObject -FileName $UserFile -TomcatInstance $TomcatInstance
    if ($null -ne $XmlObject) {

        $ElementName = "user"
        $UsersPath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $UserFile
        $ManagerRoles = $XmlObject.GetElementsByTagName($ElementName)
        $ManagerFound = 0
        $FindingDetails += "File:`n`t$UsersPath" | Out-String
        If ($null -eq "$ManagerRoles" -or "$ManagerRoles" -eq "") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No users found in $UserFile" | Out-String
            $Status = "NotAFinding"
        }
        Else {
            foreach ($user in $ManagerRoles) {
                If ($user."roles" -match "Manager*") {
                    $FindingDetails += "User:`n`t$($user.username)" | Out-String
                    $FindingDetails += "Roles:`n`t$($user.roles)" | Out-String
                    $FindingDetails += "" | Out-String
                    $ManagerFound++
                }
            }

            If ("$ManagerFound" -eq 0 ) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "No users with manager rights found in $UserFile" | Out-String
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

Function Get-V223007 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223007
        STIG ID    : TCAT-AS-001710
        Rule ID    : SV-223007r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : Hosted applications must be documented in the system security plan.
        DiscussMD5 : 4B541C236517067E073B329272312257
        CheckMD5   : 350AC33B5084F6EB196F68AD6649DA73
        FixMD5     : 0981EB1A10194C0E914A8E2888B8F27C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Directory = Join-Path -Path $TomcatInstance.BaseDir -ChildPath "webapps"
    if (Test-Path -Path $Directory) {
        $Webapps = (Get-ChildItem "$Directory").Name
        $FindingDetails += "Directory:`n`t$Directory" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Web Apps:" | Out-String
        Foreach ($app in $Webapps) {
            $FindingDetails += "`t$app" | Out-String
        }
    }
    else {
        $FindingDetails += '$CATALINA_BASE/webapps was not found'
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V223008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223008
        STIG ID    : TCAT-AS-001720
        Rule ID    : SV-223008r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : Connectors must be approved by the ISSO.
        DiscussMD5 : 29B98B96631480E5BB4BB36146FA520E
        CheckMD5   : 33524D4F9A35107BA6AC87A7830F6205
        FixMD5     : A9A0A6BB6394A294CD4EB26B3EAF87A5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName = "server.xml"
    $FilePath = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $FilePath) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$($FilePath)" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Connector"
            $AttributeName = "port"

            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            $ExpectedValue = "All Connector ports are approved in the SSP"
            $FindingDetails += "Expected:`n`t$($ExpectedValue)" | Out-String

            if ($null -eq "$Elements" -or "$Elements" -eq "") {
                $FindingDetails += "No $Elements elements found" | Out-String
            }
            else {
                Foreach ($element in $Elements) {
                    $AttributeValue = $element.$AttributeName
                    $FindingDetails += "Element:`n`t$($element.Name)" | Out-String
                    $FindingDetails += "Attribute:`n`t$($AttributeName)" | Out-String
                    $FindingDetails += "Value:`n`t$($AttributeValue)`n" | Out-String
                }
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found'
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

Function Get-V223009 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223009
        STIG ID    : TCAT-AS-001730
        Rule ID    : SV-223009r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : Connector address attribute must be set.
        DiscussMD5 : 4AF9E04A452B6028319C4A1369BEF81D
        CheckMD5   : 7CC1AAAFE74B9451F450B38FAFB04981
        FixMD5     : 9D6632267EF27413AE6E74775F6DD9B2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileName = "server.xml"
    $ConfigFile = Join-Path -Path $TomcatInstance.ConfDir -ChildPath $FileName
    if (Test-Path -Path $ConfigFile) {
        $XmlObject = Get-XMLObject -FileName $FileName -TomcatInstance $TomcatInstance -FilePath "conf"
        if ($null -ne $XmlObject) {

            $FindingDetails += "Config File:`n`t$ConfigFile" | Out-String
            $FindingDetails += "" | Out-String
            $ElementName = "Connector"
            $Elements = $XmlObject.GetElementsByTagName("$ElementName")
            if (($Elements | Measure-Object).count -eq 0) {
                $FindingDetails += "No $ElementName Elements found" | Out-String
                $Status = "NotAFinding"
            }
            else {
                foreach ($element in $Elements) {
                    $FindingDetails += "Element:`n`t$ElementName" | Out-String
                    if ($null -eq $($element.address) -or $($element.address) -eq "") {
                        $AddressValue = "Not defined"
                        $ErrorCount++
                    }
                    else {
                        $AddressValue = $($element.address)
                    }
                    $FindingDetails += "Address:`n`t$AddressValue" | Out-String
                }
            }

            if ($ErrorCount -ge 1) {
                $Status = "Open"
            }
        }
        else {
            $FindingDetails += '$CATALINA_BASE/conf/server.xml was not found.'
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

Function Get-V223010 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223010
        STIG ID    : TCAT-AS-001731
        Rule ID    : SV-223010r985887_rule
        CCI ID     : CCI-000139, CCI-003831
        Rule Name  : SRG-APP-000108-AS-000067
        Rule Title : The application server must alert the system administrator (SA) and information system security offer (ISSO), at a minimum, in the event of a log processing failure.
        DiscussMD5 : BF49495891C6B0F56DCA57083A6C2796
        CheckMD5   : D1675DD734BDE3D0C77BA75C55E01000
        FixMD5     : 41FF385A9520EDB9CAD6BEC2DE010180
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($IsLinux) {
        $AuditdConf = "/etc/audit/auditd.conf"
        $Setting = "action_mail_acct"
        $Expected = "OS is configured to alert ISSO/SA of audit processing failure"
        $ExpectedValue = "action_mail_acct = root"
        if (Test-Path -Path $AuditdConf) {
            $CommandOutput = ((Select-String -Pattern '^[\s]*action_mail_acct' -Path $AuditdConf).ToString() -split ":")[2]
            if ($null -ne $CommandOutput -or $CommandOutput -ne "") {
                if (((($CommandOutput) -split "=")[1]).trim() -eq "root") {
                    $Status = "NotAFinding"
                    $FindingDetails += "File:`n`t$AuditdConf" | Out-String
                    $FindingDetails += "Expected Value:`n`t$ExpectedValue" | Out-String
                    $FindingDetails += "Detected Value:`n`t$CommandOutput" | Out-String
                }
                else {
                    $FindingDetails += "File:`n`t$AuditdConf" | Out-String
                    $FindingDetails += "Expected Configuration:`n`t$Expected" | Out-String
                    $FindingDetails += "Detected Configuration:`n`t$CommandOutput" | Out-String
                }
            }
            else {
                $FindingDetails += "$Setting is not configured in $AuditdConf" | Out-String
            }
        }
        else {
            $FindingDetails = "$AuditdConf was not found" | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxHax7mgWttQ+B
# zb6ABJmQypbntkx9hVZXJCnmsfMlDaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDv7RfYEwfMpwYlUW5UHK9NFpTz3XA3ONwJms6zbLSa3zANBgkqhkiG9w0BAQEF
# AASCAQB1gBiKsO3zXOLBIh/euI74QUKCLIcP/i8+bBfAiZ1iBIeq3wiKKRkVuqio
# yB73yW9PR/lKlMWWqLW5aKYJC+68EHXgcHb/hoUKaPMQ2974Z/k4/1ogpJ0mJ8Ym
# gH7ircZxw7PpGK4fLiD05Bipu6j1WlaramgSdoCgi364qon23DRAixRTKdPq/L+l
# OidDNf04tXBN9uzQ1fx9S2yT4JbIgZvv97RWCeFsB/G1tdxM8v12QhB7UlmFzfML
# pjEPfxlmX2I0lLmfuEVjn18KyxaxTQ3n2E2d+npGQPt8z01wsAZ5aUZ39XcjO4Mz
# x+l5yd1nbun4gqq8Q0IUKOAbVAyJoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTgyMlowLwYJKoZIhvcNAQkEMSIEIKhTLmFEuIBHRIddR6VO2MwjaXS/
# vnNrmdxQRPZvAQCYMA0GCSqGSIb3DQEBAQUABIICAEjGhBphvJkBqMRYsPnGtIiC
# xquYHD4P0h+TFAtsUWGHWi8ecSDpyFstKuQ19FH8CGsaRh2HyGyybRRpmIHcC3Z/
# f/lZXf5gMSz67Ex5DOF9jwbR3QZUYmRygrM0PJ0pTZzS3YWv4s6jUx0aYorZOgG6
# HJ4kDqDFX/elRgQccYpCO9lzZt908fPvHftWSKiwYNopkvze8ua8ooIBKfd7bn8W
# bQLHAi5wChrXDvvnLmkFk6BCUPZy3iuRSJIpeEFsyBBqPpnabwRX/fKqp/8hPLFF
# HoRfQdJrnlGd9icAPfmcoJaRGDwn4MTZlpqxg/u1RkRHb1CPQhiUBvJ29GTYmfAS
# AO5fhVkXOE3yJgESQdRhtj7HWpvIHGgdifWzMurP0MSd+BUDmBTgEvBKL2MjTrTF
# vKUKaN8rjU2MLTcTeSVg9M6uBqmgbFnjdd+hs7/2y+k/6vvUrTl4cNi8jZTKwJHv
# WFmgg2FwpaK2qTnax+0qn/xFBTVOBiH1buq1yBVg52pWPF/jE0XzjehOnSt2+o/b
# J8DTNXLiS4Tewe3/7nB9agF8PCIPHIv88+YN474WXGKQufW73h71nXB5mveppWz/
# lQ1/eAa6Kwxrr4LnltU09VljaNCvJuFl3Zf9RQeSwfX91nIkUrlGGSLJxT6jE61H
# Q/siSyPdoW6PdTdWhUIL
# SIG # End signature block
