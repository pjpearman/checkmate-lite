##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     ArcGIS for Server 10.3
# Version:  V2R1
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-ArcGISFormattedOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string] $Setting, ###Define the parameter to check.
        [Parameter(Mandatory = $True)]
        [string] $ExpectedValue, ###Expected value being checked (e.g. True, False, on, off, etc.).
        [Parameter(Mandatory = $True)]
        [string] $DetectedValue ###The value detected by STIG functions/commands.
    )

    $FormattedOutput = "" # Start with a clean slate.

    $FormattedOutput += "Setting:`t`t`t$($Setting)" | Out-String
    $FormattedOutput += "Expected Value:`t$($ExpectedValue)" | Out-String
    $FormattedOutput += "Detected Value:`t$($DetectedValue)" | Out-String
    $FormattedOutput += "" | Out-String

    return $FormattedOutput
}

Function Get-ArcGISInstance {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessID,
        [Parameter(Mandatory = $True)]
        [int]$Index
    )

	$etcpath = (((Get-Process -id $ProcessId).Path) -Split '\\service')[0]
	$ConnectionPath = Join-Path $etcPath -ChildPath "config-store-connection.xml"
	$xml = [xml](Get-Content $ConnectionPath)
	$ConfigStorePath = ($xml.GetElementsByTagName("entry") | Where-Object "key" -eq "connectionString")."#text"

	$ApplicationHost = Join-Path $env:windir -ChildPath "\System32\inetsrv\Config\applicationHost.Config"
	$Security = Join-Path $ConfigStorePath -ChildPath "security\security-config.json"
	$LogSettings = Join-Path $ConfigStorePath -ChildPath "arcgis-logsettings.json"
	$ServicesDirectory = Join-Path $ConfigStorePath -ChildPath "system\handlers\rest\servicesdirectory.json"
	$Super = Join-Path $ConfigStorePath -ChildPath "security\super\super.json"
	$Machines = Join-Path $ConfigStorePath -ChildPath "machines"
	$Services = Join-Path $ConfigStorePath -ChildPath "services"
	$UserRoles = Join-Path $ConfigStorePath -ChildPath "security\user-roles"
	$Roles = Join-Path $ConfigStorePath -ChildPath "security\roles"

	if (Test-Path -Path $LogSettings){
		Try{
			$Logs = (Get-Content -Raw -Path $LogSettings | ConvertFrom-Json).LogDir
		}
		Catch{
		}
	}

    $Instance = [PSCustomObject]@{
        Index         	  	= $Index
        ProcessID			= $ProcessID
		ConfigStorePath		= $ConfigStorePath
		ApplicationHost		= $ApplicationHost
		Security 			= $Security
		LogSettings			= $LogSettings
		ServicesDirectory 	= $ServicesDirectory
		Super				= $Super
		Machines 			= $Machines
		Services 			= $Services
		Logs				= $Logs
		UserRoles			= $UserRoles
		Roles				= $Roles
    }

    return $Instance
}

Function Get-ArcGISInstances {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param ()

    $ArcGISProcesses = Get-ArcGISProcessId

    $Index = 0
    [System.Collections.ArrayList]$Instances = @()
    foreach ($processId in $ArcGISProcesses) {
        $Instance = Get-ArcGISInstance -ProcessID $processId -Index $Index
        [void] $Instances.add($Instance)
        $Index++
    }

    return $Instances
}

Function Get-ArcGISProcessId {
    param ()

    $ProcessIds1 = Get-Process | Where-Object { $_.Name -match "ArcGIS\s?Server" } | ForEach-Object {
        Write-Output "$($_.Id)"
    }

    [System.Collections.ArrayList]$ProcessIDs = @()

    if (($ProcessIds1 | Measure-Object).Count -gt 0){
        [void] $ProcessIDs.add($ProcessIds1)
    }

    return $ProcessIDs
}

Function Get-ArcGISSites {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$XmlObject
    )

    $Sites = $XmlObject.GetElementsByTagName("site")
    if ($null -eq $Sites) {
        return $null
    }

    $ArcGISSites = ($Sites | Where-Object { $null -ne $_.GetElementsByTagName("application") -and $_.GetElementsByTagName("application").applicationpool -Like "ArcGISWebAdaptor*"})

    return $ArcGISSites
}

Function Get-JsonObject {
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$JsonFile
    )

	If (Test-Path $JsonFile){

		$JsonObject = $null
		try {
			$JsonObject = Get-Content -Raw -Path $JsonFile | ConvertFrom-Json -ErrorAction SilentlyContinue
		}
		catch {
			return $null
		}

		return $JsonObject
	}
	else{
		return $null
	}
}

Function Get-XMLObject {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path $Path) {
        $XmlPath = Convert-Path $Path

        try {
            [XML]$XMLObject = Get-Content -Path $XmlPath -ErrorAction SilentlyContinue
        }
        catch {
            return $null
        }

    }

    return $XMLObject
}

Function New-XMLElementFromArray {
    param (
        [Parameter(Mandatory = $true)]
        [xml]$XmlDocument,
        [Parameter(Mandatory = $true)]
        [string[]]$ElementsArray,
        [Parameter(Mandatory = $true)]
        [string[]]$AttributeName,
        [Parameter(Mandatory = $true)]
        [string[]]$AttributeValue
    )

    $xml = New-Object System.Xml.XmlDocument
    $parent = $xml

    $ElementsArray | ForEach-Object {
        $element = $xml.CreateElement($_)
        if ($_ -eq $ElementsArray[-1]) {
            $element.SetAttribute($AttributeName, $AttributeValue)
        }
        $parent = $parent.AppendChild($element)
    }

    return $xml
}

Function Get-V237320 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237320
        STIG ID    : AGIS-00-000007
        Rule ID    : SV-237320r879520_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015
        Rule Title : The ArcGIS Server must protect the integrity of remote access sessions by enabling HTTPS with DoD-approved certificates.
        DiscussMD5 : 6357BD8CBDE38A276FC8081E912E86DB
        CheckMD5   : 626DD2D498E10C895E4D492BDABE4A8C
        FixMD5     : F70CB1A4511DADB16A33E9526A9B5F4E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    if (Test-Path $ArcGISInstance.ApplicationHost) {
        $XmlObject = Get-XMLObject -Path $ArcGISInstance.ApplicationHost

        if ($null -ne $XmlObject) {
            $ArcGISSites = Get-ArcGISSites -XmlObject $XmlObject

            if ($null -ne $ArcGISSites) {
                $ArcGISSites | ForEach-Object {
                    $Setting = "HTTPS Binding"
                    $ExpectedValue = "Enabled"
                    $SiteName = $_.name

                    $Binding = $_.GetElementsByTagName("binding") | Where-Object protocol -EQ "https"
                    if ($null -eq $Binding) {
                        $ErrorCount++
                        $DetectedValue = "Not Enabled"
                    }
                    else {
                        $DetectedValue = "Enabled"
                    }

                    $FindingDetails += "Site Name:`t`t$($SiteName)" | Out-String
                    $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue

                    $Setting = "Require SSL"
                    $ExpectedValue = "Enabled"

                    $Location = $XmlObject.GetElementsByTagName("location") | Where-Object path -EQ $SiteName

                    if ($null -ne $Location) {
                        $sslFlags = $Location.'system.webServer'.security.access.sslFlags

                        if ($null -ne $sslFlags) {
                            if ($sslFlags -notmatch "\bSsl\b") {
                                $ErrorCount++
                                $DetectedValue = "Not Enabled"
                            }
                            else {
                                $DetectedValue = "Enabled"
                            }
                        }
                    }
                    else {
                        $ErrorCount++
                        $DetectedValue = "Not Enabled"
                    }

                    $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
                }
            }

            if ($ErrorCount -gt 0) {
                $Status = "Open"
            }
            else {
                $Status = "NotAFinding"
            }
        }
    }
	else{
		$FindingDetails += "Setting not found. Manual review required."
	}
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237321 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237321
        STIG ID    : AGIS-00-000009
        Rule ID    : SV-237321r879522_rule
        CCI ID     : CCI-000015, CCI-000017, CCI-000018, CCI-000044, CCI-000192, CCI-000193, CCI-000194, CCI-000195, CCI-000196, CCI-000198, CCI-000199, CCI-000200, CCI-000205, CCI-001619
        Rule Name  : SRG-APP-000023
        Rule Title : The ArcGIS Server must use Windows authentication for supporting account management functions.
        DiscussMD5 : 8D90208866F3AB98CB0C0F186951BD7D
        CheckMD5   : 49A8C5A27303469551699D380728EBAA
        FixMD5     : 280DC44AE515D48E11027071EAC81E4D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $SecuritySettings = Get-JsonObject $($ArcGISInstance.Security)
    if ($null -ne $SecuritySettings) {
        $Setting = "User Store Configuration"
        $ExpectedValue = "Not 'BUILTIN'"
        $BadConfig = "BUILTIN"
        $DetectedValue = $($SecuritySettings.userStoreConfig.type)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
        $Setting = "Role Store Configuration"
        $DetectedValue = $($SecuritySettings.roleStoreConfig.type)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
        if ($ErrorCount -gt 0) {
            $Status = "Open"
        }
        else {
            $Status = "NotAFinding"
        }
    }
    else {
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237322 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237322
        STIG ID    : AGIS-00-000016
        Rule ID    : SV-237322r879530_rule
        CCI ID     : CCI-000166, CCI-000186, CCI-000187, CCI-000197, CCI-000206, CCI-000213, CCI-000764, CCI-000765, CCI-000766, CCI-000767, CCI-000768, CCI-000770, CCI-000778, CCI-000795, CCI-000804, CCI-001133, CCI-001185, CCI-001368
        Rule Name  : SRG-APP-000033
        Rule Title : The ArcGIS Server must use Windows authentication to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
        DiscussMD5 : E0409070BE3A57D809C044AC757187F1
        CheckMD5   : 83B59EAA457312A9CEC3DFBDC084B0F5
        FixMD5     : 64D5781B53960AE1176C21B9547F55FD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
	$SetNotReviewed = $false
    $SecuritySettings = Get-JsonObject $($ArcGISInstance.Security)
    if ($null -ne $SecuritySettings) {
        $Setting = "User Store Configuration"
        $ExpectedValue = "Not 'BUILTIN'"
        $BadConfig = "BUILTIN"
        $DetectedValue = $($SecuritySettings.userStoreConfig.type)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue

        $Setting = "Role Store Configuration"
        $DetectedValue = $($SecuritySettings.roleStoreConfig.type)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue

        $Setting = "Authentication Tier"
        $ExpectedValue = "Not 'GIS_SERVER'"
        $BadConfig = "GIS_SERVER"
        $DetectedValue = $($SecuritySettings.authenticationTier)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $FindingDetails += "Security settings not found. Manual review required."
		$SetNotReviewed = $true
    }

    if (Test-Path $ArcGISInstance.ApplicationHost) {
        $XmlObject = Get-XMLObject -Path $ArcGISInstance.ApplicationHost

        if ($null -ne $XmlObject) {
            $ArcGISSites = Get-ArcGISSites -XmlObject $XmlObject

            if ($null -ne $ArcGISSites) {
                $ArcGISSites | ForEach-Object {
                    $Application = ($_.application | Where-Object applicationpool -Like "ArcGISWebAdaptor*")
                    $SiteName = $_.name
                    $Setting = "Client Certificates"
                    $ExpectedValue = "Require"

                    foreach ($a in $Application) {
                        $SitePath = "$($SiteName)$($a.path)"
                        $loc = $XmlObject.GetElementsByTagName("location") | Where-Object Path -Match "$($SitePath)$"
                        $SSLFlags = $loc.'system.webServer'.security.access.sslFlags
                        if ($SSLFlags -eq "Ssl" -or $SSLFlags -eq "None") {
                            $ErrorCount++
                            $DetectedValue = "Ignore"
                        }
                        else {
                            if ($SSLFlags -contains "SslRequireCert") {
                                $DetectedValue = "Require"
                            }
                            else {
                                $ErrorCount++
                                $DetectedValue = "Accept"
                            }
                        }

                        $FindingDetails += "Application:`t`t$SitePath" | Out-String
                        $FindingDetails += "Setting:`t`t`t$Setting" | Out-String
                        $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
                        $FindingDetails += "Detected Value:`t$DetectedValue" | Out-String
                        $FindingDetails += "" | Out-String

                    }
                }
            }
        }
        else {
            $FindingDetails += "Setting not found. Manual review required."
			$SetNotReviewed = $true
        }
    }
	else {
        $FindingDetails += "Setting not found. Manual review required."
		$SetNotReviewed = $true
    }

	if ($SetNotReviewed -eq $false){
		if ($ErrorCount -gt 0) {
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

Function Get-V237323 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237323
        STIG ID    : AGIS-00-000026
        Rule ID    : SV-237323r879559_rule
        CCI ID     : CCI-000067, CCI-000130, CCI-000132, CCI-000133, CCI-000134, CCI-000169, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-001487, CCI-001665, CCI-001814, CCI-002130, CCI-002234
        Rule Name  : SRG-APP-000089
        Rule Title : The ArcGIS Server must provide audit record generation capability for DoD-defined auditable events within all application components.
        DiscussMD5 : DD8A8D33615DB1831796FE58C7305512
        CheckMD5   : F53343BC8CAF960F64753C424CF8953D
        FixMD5     : F6630046EB0B1175231300616B34FA24
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Log Level"
    $ExpectedValue = "VERBOSE"
    $LogSettings = Get-JsonObject $($ArcGISInstance.LogSettings)
    if ($null -ne $LogSettings) {
        $DetectedValue = $LogSettings.logLevel
        if ($DetectedValue -eq $ExpectedValue) {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237324 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237324
        STIG ID    : AGIS-00-000044
        Rule ID    : SV-237324r879576_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-APP-000118
        Rule Title : The ArcGIS Server must protect audit information from any type of unauthorized read access, modification or deletion.
        DiscussMD5 : 8BFCB861CB83299ED0946E2558ACCFD6
        CheckMD5   : 364EEE542E3387B38E83C5A5886F004A
        FixMD5     : 6C7E81132672B80E2324B32A0CAB9C5D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DirToCheck = $ArcGISInstance.Logs

    if (Test-Path $DirToCheck) {
        $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
    }
    else {
		$FindingDetails += "Logs directory was not found."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237325 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237325
        STIG ID    : AGIS-00-000054
        Rule ID    : SV-237325r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The ArcGIS Server must be configured to disable non-essential capabilities.
        DiscussMD5 : 90D331684418301210DB73508F150816
        CheckMD5   : F0DE547DC27C6347E293106FD607C92B
        FixMD5     : 6AC54C6A712A528ECBD6B522C07E1ED6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Services Directory"
    $ExpectedValue = "Disabled"
    $ServicesDirectory = Get-JsonObject $ArcGISInstance.ServicesDirectory
    if ($null -ne $ServicesDirectory) {
        if ($ServicesDirectory.enabled -eq "false"){
            $DetectedValue = "Disabled"
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
            $DetectedValue = "Enabled"
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else{
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237326 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237326
        STIG ID    : AGIS-00-000055
        Rule ID    : SV-237326r879588_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142
        Rule Title : The ArcGIS Server must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
        DiscussMD5 : D995EB97B7F106370A668BE6D49B9322
        CheckMD5   : 5B7564A8DF565B630F7811E210D559C7
        FixMD5     : 84FFA4A1258A3C04EB9995C6F88796A8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Protocol"
    $ExpectedValue = "Not 'HTTP Only'"
    $SecuritySettings = Get-JsonObject $($ArcGISInstance.Security)
    if ($null -ne $SecuritySettings) {
        if ($SecuritySettings.sslEnabled -like "False") {
            $Status = "Open"
            $DetectedValue = "HTTP Only"
        }
        else {
            $Status = "NotAFinding"
            if ($($SecuritySettings.httpEnabled) -like "True") {
                $DetectedValue = "HTTP and HTTPS"
            }
            else {
                $DetectedValue = "HTTPS Only"
            }
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237327 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237327
        STIG ID    : AGIS-00-000062
        Rule ID    : SV-237327r879597_rule
        CCI ID     : CCI-001941, CCI-001942, CCI-002361
        Rule Name  : SRG-APP-000156
        Rule Title : The ArcGIS Server must implement replay-resistant authentication mechanisms for network access to privileged accounts and non-privileged accounts.
        DiscussMD5 : 864609548BE27850B0E5C49BDF781A97
        CheckMD5   : B05B1D9A8A0D71D76082B36AFA60C45D
        FixMD5     : BB8BC05FC22DFD3413D1909B94D16760
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    if (Test-Path $ArcGISInstance.ApplicationHost) {
        $XmlObject = Get-XMLObject -Path $ArcGISInstance.ApplicationHost

        if ($null -ne $XmlObject) {
            $ArcGISSites = Get-ArcGISSites -XmlObject $XmlObject

            if ($null -ne $ArcGISSites) {
                $ArcGISSites | ForEach-Object {
					$Application = ($_.application | Where-Object applicationpool -Like "ArcGISWebAdaptor*")
                    $SiteName = $_.name
					$Setting1 = "Anonymous Authorization"
					$ExpectedValue1 = "Disabled"
					$Setting2 = "Windows Authentication"
					$ExpectedValue2 = "Enabled"
					$Setting3 = "Providers"
					$ExpectedValue3 = "NTLM is not the first provider listed"

					foreach ($a in $Application) {
						$SitePath = "$($SiteName)$($a.path)"
						$loc = $XmlObject.GetElementsByTagName("location") | Where-Object Path -Match "$($SitePath)$"
						$AnonAuth = $loc.'system.webServer'.security.authentication.anonymousAuthentication.enabled
						$WinAuth = $loc.'system.webServer'.security.authentication.windowsAuthentication.enabled
						$Providers = @($loc.'system.webServer'.security.authentication.windowsAuthentication.providers.add.value)

						if ($null -eq $AnonAuth -or $AnonAuth -eq "True"){
							$ErrorCount++
							$DetectedValue1 = "Enabled"
						}
						else{
							$DetectedValue1 = "Disabled"
						}
						if ($null -eq $WinAuth -or $WinAuth -eq "False"){
							$ErrorCount++
							$DetectedValue2 = "Disabled"
						}
						else{
							$DetectedValue2 = "Enabled"
						}
						if (($Providers | Measure-Object).Count -eq 0){
							$DetectedValue3 = "NTLM"
							$ErrorCount++
						}
						else{
							$DetectedValue3 = $Providers[0]
							if($Providers -notmatch "^\s*Negotiate" ){
								$ErrorCount
							}
						}
						$FindingDetails += "Application:`t`t$SitePath" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting1" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue1" | Out-String
						$FindingDetails += "Detected Value:`t$DetectedValue1" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting2" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue2" | Out-String
						$FindingDetails += "Detected Value:`t$DetectedValue2" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting3" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue3" | Out-String
						$FindingDetails += "First Provider:`t`t$DetectedValue3" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "" | Out-String

					}
				}
			}
		}
	}
	else{
		$FindingDetails += "Setting not found. Manual review required."
	}

	if ($ErrorCount -gt 0){
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

Function Get-V237328 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237328
        STIG ID    : AGIS-00-000077
        Rule ID    : SV-237328r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : The ArcGIS Server, when using PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
        DiscussMD5 : E79A7621703645BC5A18FF687F37CB12
        CheckMD5   : AC4051E6ED0B8D54BEF323555C9340E1
        FixMD5     : 3AC73B401CACFC6487B84807D7D14E38
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing'
    $RegName = 'State'

    $Setting = "Check for Publisher's Certificate Revocation"
    $ExpectedValue = "Checked"

    $RegValue = Get-ItemPropertyValue -Path $RegPath -Name $RegName

    if ($null -eq $RegValue -or $RegValue.ToString('x2') -ne "23C00") {
        $DetectedValue = "Not Checked"
        $ErrorCount++
    }
    else {
        $DetectedValue = "Checked"
    }

    $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue

    $RegPath = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    $RegName = 'CertificateRevocation'

    $Setting = "Check for Server Certificate Revocation"
    $ExpectedValue = "Checked"

    $RegValue = Get-ItemPropertyValue -Path $RegPath -Name $RegName

    if ($null -eq $RegValue -or $RegValue -ne "1") {
        $DetectedValue = "Not Checked"
        $ErrorCount++
    }
    else {
        $DetectedValue = "Checked"
    }

    $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue

    if ($ErrorCount -gt 0) {
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

Function Get-V237329 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237329
        STIG ID    : AGIS-00-000081
        Rule ID    : SV-237329r879616_rule
        CCI ID     : CCI-000068, CCI-000803, CCI-001184, CCI-001188
        Rule Name  : SRG-APP-000179
        Rule Title : The ArcGIS Server must use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.
        DiscussMD5 : 72BF26115A813945C020D36640F3901F
        CheckMD5   : 56184FBA002309A078812296D9285AAD
        FixMD5     : 0448EEDFDB6155163E90700F77AEC554
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Protocol"
    $ExpectedValue = "Not 'HTTP Only'"
    $SecuritySettings = Get-JsonObject $($ArcGISInstance.Security)
    if ($null -ne $SecuritySettings) {
        if ($SecuritySettings.sslEnabled -like "False") {
            $Status = "Open"
            $DetectedValue = "HTTP Only"
        }
        else {
            if ($($SecuritySettings.httpEnabled) -like "True") {
                $DetectedValue = "HTTP and HTTPS"
            }
            else {
                $DetectedValue = "HTTPS Only"
            }
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
        $Setting = "Ciphers"
        $ExpectedValue = "DoD Approved Cipher Suite Values"
        if ($null -eq $SecuritySettings.cipherSuites) {
            $Status = "Open"
        }
        else {
            $FindingDetails += "Setting:`t`t`t$($Setting)" | Out-String
            $FindingDetails += "Expected Value:`t$($ExpectedValue)" | Out-String
            $FindingDetails += "Detected Value:" | Out-String
            $DetectedValues = ($SecuritySettings.cipherSuites -split ",").Trim()
            foreach ($DetectedValue in $DetectedValues) {
                $FindingDetails += "`t$($DetectedValue)" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237330 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237330
        STIG ID    : AGIS-00-000098
        Rule ID    : SV-237330r879638_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223
        Rule Title : The ArcGIS Server must recognize only system-generated session identifiers.
        DiscussMD5 : 0BCBFC3B8D18DE7635A151F74FD5C781
        CheckMD5   : C9A9948A648BA36F4C572BAC50138C37
        FixMD5     : 878A9BCEB4B41A4D181358143F574400
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount=0
    $SecuritySettings = Get-JsonObject $($ArcGISInstance.Security)
    if ($null -ne $SecuritySettings) {
        $Setting = "User Store Configuration"
        $ExpectedValue = "Not 'BUILTIN'"
        $BadConfig = "BUILTIN"
        $DetectedValue = $($SecuritySettings.userStoreConfig.type)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
        $Setting = "Role Store Configuration"
        $DetectedValue = $($SecuritySettings.roleStoreConfig.type)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
        $Setting = "Authentication Tier"
        $ExpectedValue = "Not 'GIS_SERVER'"
        $BadConfig = "GIS_SERVER"
        $DetectedValue = $($SecuritySettings.authenticationTier)
        if ($DetectedValue -eq $BadConfig) {
            $ErrorCount++
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
        if ($ErrorCount -gt 0) {
            $Status="Open"
        }
        else {
            $Status="NotAFinding"
        }
    }
    else {
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237332 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237332
        STIG ID    : AGIS-00-000104
        Rule ID    : SV-237332r879644_rule
        CCI ID     : CCI-001682
        Rule Name  : SRG-APP-000234
        Rule Title : The ArcGIS Server must be configured such that emergency accounts are never automatically removed or disabled.
        DiscussMD5 : 3880CF992808507C03EE170B4FAD4F3E
        CheckMD5   : BAF30FF700C0416E828B6C5F879D8CE8
        FixMD5     : 0F679DAEA8BD62E91F367F9F243DDD7C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Primary Site Administrator"
    $ExpectedValue = "Enabled"
    $SuperSettings = Get-JsonObject $($ArcGISInstance.Super)
    if ($null -ne $SuperSettings) {
        if ($SuperSettings.disabled -match "True") {
            $Status = "Open"
            $DetectedValue = "Disabled"
        }
        else {
            $Status = "NotAFinding"
            $DetectedValue = "Enabled"
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237333 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237333
        STIG ID    : AGIS-00-000111
        Rule ID    : SV-237333r879656_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267
        Rule Title : The ArcGIS Server must reveal error messages only to the ISSO, ISSM, and SA.
        DiscussMD5 : 41AD67165A1A48309DAABF69D326FFD5
        CheckMD5   : 04F90C77625D3B69CA827581AD0B2BF8
        FixMD5     : 58F0ED0FDA7ADAF86CA5A628C301B2AE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DirToCheck = $ArcGISInstance.Logs

    if (Test-Path $DirToCheck) {
        $FindingDetails += Get-Acl -Path "$DirToCheck" | Format-Table -Wrap | Out-String
    }
    else {
		$FindingDetails += "Logs directory was not found."
    }
    $FindingDetails += "-------------------------------------" | Out-String

    $RoleDir = $ArcGISInstance.Roles
	$UserRolesDir = $ArcGISInstance.UserRoles

	if ((Test-Path -Path $RoleDir) -and (Test-Path -Path $UserRolesDir)){
		$RoleFiles = Get-ChildItem $RoleDir | Where-Object { $_.Name -notmatch "json.rlock" }
		$AdministratorRoles = @()
		$RoleDetails = "Role(s) with Administrative Privileges:" | Out-String
		$RoleCount = 0
		foreach ($roleFile in $RoleFiles) {
			$Role = Get-Content -Raw -Path $roleFile.FullName | ConvertFrom-Json -ErrorAction SilentlyContinue
			if ($Role.privilege -eq "ADMINISTER") {
				$AdministratorRoles += $Role.rolename
				$RoleDetails += "`t$($Role.rolename)" | Out-String
				$RoleCount++
			}
		}
		if ($RoleCount -gt 0) {
			$FindingDetails += $RoleDetails
		}
		else {
			$FindingDetails += "No Roles with Administrator Priviliges detected." | Out-String
		}
		$FindingDetails += "" | Out-String
		$UserRoleFiles = Get-ChildItem $UserRolesDir | Where-Object { $_.Name -notmatch "json.rlock" }
		$UserDetails = "User(s) in Administrative Roles:" | Out-String
		$UserCount = 0
		foreach ($userRoleFile in $UserRoleFiles) {
			$user = Get-Content -Raw -Path $userRoleFile.FullName | ConvertFrom-Json -ErrorAction SilentlyContinue
			$NewListing = $True
			$AdministratorRoles | ForEach-Object {
				if ( $user.roles -contains $_ ) {
					if ( $NewListing ) {
						$UserDetails += "`t$($user.username)" | Out-String
						$UserCount++
						$NewListing = $False
					}
				}
			}
		}
		if ($UserCount -gt 0) {
			$FindingDetails += $UserDetails
		}
		else {
			$FindingDetails += "No Users with Administrator Roles found." | Out-String
		}
		$FindingDetails += " " | Out-String
		$FindingDetails += "-------------------------------------" | Out-String

		$RoleDetails = "Role(s) with Publisher Privileges:" | Out-String
		$PublisherRoles = @()
		$RoleCount = 0
		foreach ($roleFile in $RoleFiles) {
			$Role = Get-Content -Raw -Path $roleFile.FullName | ConvertFrom-Json -ErrorAction SilentlyContinue
			if ($Role.privilege -eq "PUBLISH") {
				$PublisherRoles += $Role.rolename
				$RoleCount++
				$RoleDetails += "`t$($Role.rolename)" | Out-String
			}
		}
		if ($RoleCount -gt 0) {
			$FindingDetails += $RoleDetails
		}
		else {
			$FindingDetails += "No Roles with Publisher permissions found." | Out-String
		}
		$FindingDetails += "" | Out-String
		$UserDetails = "User(s) in Publisher Roles:" | Out-String
		$UserCount = 0
		foreach ($userRoleFile in $UserRoleFiles) {
			$user = Get-Content -Raw -Path $userRoleFile.FullName | ConvertFrom-Json -ErrorAction SilentlyContinue
			$NewListing = $True
			$PublisherRoles | ForEach-Object {
				if ( $user.roles -contains $_ ) {
					if ( $NewListing ) {
						$UserDetails += "`t$($user.username)" | Out-String
						$UserCount++
						$NewListing = $False
					}
				}
			}
		}
		if ($UserCount -gt 0) {
			$FindingDetails += $UserDetails
		}

		else {
			$FindingDetails += "No Users found with Publisher roles." | Out-String
		}
	}
	else{
		$FindingDetails += "Setting not found. Manual review required."
	}
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237334 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237334
        STIG ID    : AGIS-00-000164
        Rule ID    : SV-237334r879753_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380
        Rule Title : The ArcGIS Server must enforce access restrictions associated with changes to application configuration.
        DiscussMD5 : 75D6294D3C23AF73F56772BF8129BA87
        CheckMD5   : 8BA72331B7BE18F418ACE35C5AAD135F
        FixMD5     : E6A7BA16FF8F3C2FBE2170DE1DFE5A3A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RoleDir = $ArcGISInstance.Roles
		$UserRolesDir = $ArcGISInstance.UserRoles

	if ((Test-Path -Path $RoleDir) -and (Test-Path -Path $UserRolesDir)){
		$RoleFiles = Get-ChildItem $RoleDir | Where-Object { $_.Name -notmatch "json.rlock" }

		$AdministratorRoles = @()
		$RoleDetails = "Role(s) with Administrative Privileges:" | Out-String
		$RoleCount = 0
		foreach ($roleFile in $RoleFiles) {
			$Role = Get-Content -Raw -Path $roleFile.FullName | ConvertFrom-Json -ErrorAction SilentlyContinue
			if ($Role.privilege -eq "ADMINISTER") {
				$AdministratorRoles += $Role.rolename
				$RoleDetails += "`t$($Role.rolename)" | Out-String
				$RoleCount++
			}
		}
		if ($RoleCount -gt 0) {
			$FindingDetails += $RoleDetails
		}
		else {
			$FindingDetails += "No Roles with Administrator Priviliges detected." | Out-String
		}
		$FindingDetails += "" | Out-String
		$UserRoleFiles = Get-ChildItem $UserRolesDir | Where-Object { $_.Name -notmatch "json.rlock" }
		$UserDetails = "User(s) in Administrative Roles:" | Out-String
		$UserCount = 0
		foreach ($userRoleFile in $UserRoleFiles) {
			$user = Get-Content -Raw -Path $userRoleFile.FullName | ConvertFrom-Json -ErrorAction SilentlyContinue
			$NewListing = $True
			$AdministratorRoles | ForEach-Object {
				if ( $user.roles -contains $_ ) {
					if ( $NewListing ) {
						$UserDetails += "`t$($user.username)" | Out-String
						$UserCount++
						$NewListing = $False
					}
				}
			}
		}
		if ($UserCount -gt 0) {
			$FindingDetails += $UserDetails
		}
		else {
			$FindingDetails += "No Users with Administrator Roles found." | Out-String
		}
	}
	else{
		$FindingDetails += "Setting not found. Manual review required."
	}
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237335 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237335
        STIG ID    : AGIS-00-000166
        Rule ID    : SV-237335r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383
        Rule Title : The organization must disable organization-defined functions, ports, protocols, and services within the ArcGIS Server deemed to be unnecessary and/or nonsecure.
        DiscussMD5 : D995EB97B7F106370A668BE6D49B9322
        CheckMD5   : C49F321E07D1E3DFF811525128099285
        FixMD5     : 04C0833FBF71F41CBBDCFAEB8C1A6AF3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Protocol"
    $ExpectedValue = "Not 'HTTP Only'"
    $SecuritySettings = Get-JsonObject $($ArcGISInstance.Security)
    if ($null -ne $SecuritySettings) {
        if ($SecuritySettings.sslEnabled -like "False") {
            $Status = "Open"
            $DetectedValue = "HTTP Only"
        }
        else {
            $Status = "NotAFinding"
            if ($($SecuritySettings.httpEnabled) -like "True") {
                $DetectedValue = "HTTP and HTTPS"
            }
            else {
                $DetectedValue = "HTTPS Only"
            }
        }
        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $FindingDetails += "Setting not found. Manual review required."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237336 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237336
        STIG ID    : AGIS-00-000171
        Rule ID    : SV-237336r879764_rule
        CCI ID     : CCI-001953, CCI-001954
        Rule Name  : SRG-APP-000391
        Rule Title : The ArcGIS Server must accept and electronically verify Personal Identity Verification (PIV) credentials.
        DiscussMD5 : 6DDDEFB0629E388B65CA209115D349EA
        CheckMD5   : E3F684102CA1AFBA92B7207C137C5E5D
        FixMD5     : 495A3189B73F3D4399ED416D91503352
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    if (Test-Path $ArcGISInstance.ApplicationHost) {
        $XmlObject = Get-XMLObject -Path $ArcGISInstance.ApplicationHost

        if ($null -ne $XmlObject) {
            $ArcGISSites = Get-ArcGISSites -XmlObject $XmlObject

            if ($null -ne $ArcGISSites) {
                $ArcGISSites | ForEach-Object {
					$Application = ($_.application | Where-Object applicationpool -Like "ArcGISWebAdaptor*")
                    $SiteName = $_.name
					$Setting1 = "Anonymous Authorization"
					$ExpectedValue1 = "Disabled"
					$Setting2 = "Windows Authentication"
					$ExpectedValue2 = "Enabled"
					$Setting3 = "Client Certificates"
					$ExpectedValue3 = "Not 'Ignore'"

					foreach ($a in $Application) {
						$SitePath = "$($SiteName)$($a.path)"
						$loc = $XmlObject.GetElementsByTagName("location") | Where-Object Path -Match "$($SitePath)$"
						$AnonAuth = $loc.'system.webServer'.security.authentication.anonymousAuthentication.enabled
						$WinAuth = $loc.'system.webServer'.security.authentication.windowsAuthentication.enabled
						$SSLFlags = $loc.'system.webServer'.security.access.sslFlags
						if ($null -eq $AnonAuth -or $AnonAuth -eq "True"){
							$ErrorCount++
							$DetectedValue1 = "Enabled"
						}
						else{
							$DetectedValue1 = "Disabled"
						}

						if ($null -eq $WinAuth -or $WinAuth -eq "False"){
							$ErrorCount++
							$DetectedValue2 = "Disabled"
						}
						else{
							$DetectedValue2 = "Enabled"
						}
						if ($SSLFlags -eq "Ssl" -or $SSLFlags -eq "None"){
							$ErrorCount++
							$DetectedValue3 = "Ignore"
						}
						else{
							if ($SSLFlags -contains "SslRequireCert"){
								$DetectedValue3 = "Require"
							}
							else {
								$DetectedValue3 = "Accept"
							}
						}

						$FindingDetails += "Application:`t`t$SitePath" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting1" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue1" | Out-String
						$FindingDetails += "Detected Value:`t$DetectedValue1" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting2" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue2" | Out-String
						$FindingDetails += "Detected Value:`t$DetectedValue2" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting3" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue3" | Out-String
						$FindingDetails += "Detected Value:`t$DetectedValue3" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "" | Out-String

					}
				}
			}
		}
		else{
			$FindingDetails += "Setting not found. Manual review required."
		}
	}
	else{
		$FindingDetails += "Setting not found. Manual review required."
	}

	if ($ErrorCount -gt 0){
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

Function Get-V237337 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237337
        STIG ID    : AGIS-00-000174
        Rule ID    : SV-237337r879768_rule
        CCI ID     : CCI-001958, CCI-001967, CCI-002038, CCI-002039, CCI-002142, CCI-002238
        Rule Name  : SRG-APP-000395
        Rule Title : The ArcGIS Server Windows authentication must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.
        DiscussMD5 : B344CE6C26AAC75FA7272565FE967BD0
        CheckMD5   : D76C15CAFBDAFF1FCB233D7FD41A2860
        FixMD5     : 495A3189B73F3D4399ED416D91503352
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    if (Test-Path $ArcGISInstance.ApplicationHost) {
        $XmlObject = Get-XMLObject -Path $ArcGISInstance.ApplicationHost

        if ($null -ne $XmlObject) {
            $ArcGISSites = Get-ArcGISSites -XmlObject $XmlObject

            if ($null -ne $ArcGISSites) {
                $ArcGISSites | ForEach-Object {
					$Application = ($_.application | Where-Object applicationpool -Like "ArcGISWebAdaptor*")
                    $SiteName = $_.name
					$Setting1 = "Anonymous Authorization"
					$ExpectedValue1 = "Disabled"
					$Setting2 = "Windows Authentication"
					$ExpectedValue2 = "Enabled"

					foreach ($a in $Application) {
						$SitePath = "$($SiteName)$($a.path)"
						$loc = $XmlObject.GetElementsByTagName("location") | Where-Object Path -Match "$($SitePath)$"
						$AnonAuth = $loc.'system.webServer'.security.authentication.anonymousAuthentication.enabled
						$WinAuth = $loc.'system.webServer'.security.authentication.windowsAuthentication.enabled
						if ($null -eq $AnonAuth -or $AnonAuth -eq "True"){
							$ErrorCount++
							$DetectedValue1 = "Enabled"
						}
						else{
							$DetectedValue1 = "Disabled"
						}
						if ($null -eq $WinAuth -or $WinAuth -eq "False"){
							$ErrorCount++
							$DetectedValue2 = "Disabled"
						}
						else{
							$DetectedValue2 = "Enabled"
						}
						$FindingDetails += "Application:`t`t$SitePath" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting1" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue1" | Out-String
						$FindingDetails += "Detected Value:`t$DetectedValue1" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "Setting:`t`t`t$Setting2" | Out-String
						$FindingDetails += "Expected Value:`t$ExpectedValue2" | Out-String
						$FindingDetails += "Detected Value:`t$DetectedValue2" | Out-String
						$FindingDetails += "" | Out-String
						$FindingDetails += "" | Out-String

					}
				}
			}
		}
		else{
			$FindingDetails += "Setting not found. Manual review required"
		}
	}
	else{
		$FindingDetails += "Setting not found. Manual review required."
	}

	if ($ErrorCount -gt 0){
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

Function Get-V237338 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237338
        STIG ID    : AGIS-00-000187
        Rule ID    : SV-237338r879944_rule
        CCI ID     : CCI-002418, CCI-002420, CCI-002421, CCI-002422, CCI-002450
        Rule Name  : SRG-APP-000416
        Rule Title : The ArcGIS Server SSL settings must use NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
        DiscussMD5 : 9A96A6E84A4183A087C34CBBE71058C3
        CheckMD5   : 6D55DB9D1FFB78D97008D5C3B9A629C4
        FixMD5     : 0ACEA20035B4DBC02C00F8758FEE53DD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Setting = "Require SSL"
    $ExpectedValue = "Enabled"

    if (Test-Path $ArcGISInstance.ApplicationHost) {
        $XmlObject = Get-XMLObject -Path $ArcGISInstance.ApplicationHost

        if ($null -ne $XmlObject) {
            $ArcGISSites = Get-ArcGISSites -XmlObject $XmlObject

            if ($null -ne $ArcGISSites) {
                $ArcGISSites | ForEach-Object {
                    $Root = $_
                    $RootPath = $Root.name
                    $AppNames = $($Root.application | Where-Object path -NE "/").path

                    $AppNames | ForEach-Object {
                        $AppName = $_
                        $AppPath = $RootPath + $AppName
                        $Location = $XmlObject.GetElementsByTagName("location") | Where-Object path -EQ "$($AppPath)"

                        if ($null -ne $Location) {
                            $sslFlags = $Location.'system.webServer'.security.access.sslFlags
                            if ($null -ne $sslFlags) {
                                if ($sslFlags -match "\bSsl\b") {
                                    $DetectedValue = "Enabled"
                                }
                                else {
                                    $ErrorCount++
                                    $DetectedValue = "Not Enabled"
                                }
                            }
                        }
                        else {
                            $ErrorCount++
                            $DetectedValue = "Not Enabled"
                        }

                        $FindingDetails += "Application:`t`t$($AppPath)" | Out-String
                        $FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
                        $FindingDetails += " " | Out-String
                    }
                }
            }

            if ($ErrorCount -gt 0) {
                $Status = "Open"
            }
        }
		else{
			$FindingDetails += "Setting not found. Manual review required."
		}
    }
	else{
		$FindingDetails += "Setting not found. Manual review required."
	}
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237339 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237339
        STIG ID    : AGIS-00-000194
        Rule ID    : SV-237339r879798_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427
        Rule Title : The ArcGIS Server keystores must only contain certificates of PKI established certificate authorities for verification of protected sessions.
        DiscussMD5 : CFA13AD41E3B90563955ED54C21237E5
        CheckMD5   : 76B7AC7A250CCACD79A6737DFDA84144
        FixMD5     : 5BD656E1F27815E68CF9CCA52DC27AE4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeyTool = "keytool"
    $KeystorePass = "changeit"
    $KeystorePath = "C:\Program Files\ArcGIS\Server\framework\runtime\jre\lib\security\cacerts"

    try {
        $FindingDetails += "CMD: $KeyTool -list -storepass [keystorepwd] -keystore $($KeystorePath)" | Out-String
        $FindingDetails += " " | Out-String
        $FindingDetails += & $KeyTool -list -storepass $KeystorePass -keystore $KeystorePath | Out-String
    }
    catch {
        $FindingDetails += "No Output" | Out-String

    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V237340 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237340
        STIG ID    : AGIS-00-000197
        Rule ID    : SV-237340r879802_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431
        Rule Title : The ArcGIS Server must maintain a separate execution domain for each executing process.
        DiscussMD5 : DF80EAA8CE90A153B96BCAA8BDC45248
        CheckMD5   : 4EC448E06DD87C85AD6C717304A5284E
        FixMD5     : 7FE9B9B261ED7C6C345918C394D8CAAF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Test-Path $($ArcGISInstance.Services)) {
        $ServicesJson = Join-Path -Path $($ArcGISInstance.Services) -ChildPath "*.json"
        $LowIsolation = Get-ChildItem -Recurse $ServicesJson | Select-String -Pattern "`"isolationLevel`": `"LOW`""
        if ($LowIsolation) {
            $FindingDetails += "The following files contain isolationLevel not set to 'HIGH':" | Out-String
            foreach ($f in $LowIsolation) {
                $Filename = ($f -split ":\d*:")[0]
                $FindingDetails += "`t$Filename" | Out-String
            }
            $Status = "Open"
        }
        else {
            $FindingDetails += "No files detected containing an isolationLevel not set to 'HIGH'" | Out-String
            $Status = "NotAFinding"
        }
    }
    else {
        $FindingDetails += "Services directory could not be identified."
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V257297 {
    <#
    .DESCRIPTION
        Vuln ID    : V-257297
        STIG ID    : AGIS-00-000999
        Rule ID    : SV-257297r919430_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The version of ArcGIS running on the system must be a supported version.
        DiscussMD5 : 117ECC7EE34DF6F898C147FBFE6F17EA
        CheckMD5   : 657E45AEAB88700DD213CC1F3FD639F5
        FixMD5     : E0239E38DE3DFE26FE333ABCA75A3CA5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $VersionJson = Join-Path -Path $ArcGISInstance.ConfigStorePath -ChildPath version.json
    $Setting = "Server Version"
    $ExpectedValue = "Greater than 10.3"
    if (Test-Path $VersionJson){
        $Version = Get-JsonObject $VersionJson
		if ($null -ne $Version) {
			if ($Version.serverVersion -Like "10.3.*"){
				$ErrorCount++
			}
			$FindingDetails += Get-ArcGISFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $Version.serverVersion
		}
		else{
			$FindingDetails += "Setting not found. Manual review required."
		}
    }
    else{
        $FindingDetails += "Setting not found. Manual review required."
    }

    if ($ErrorCount -gt 0){
        $Status = "Open"
    }
    else{
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIjiimGGIVn0j8
# KAfMFFPvtc+5Hld1oVfU3XlWv6dlD6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCAyOM8uLhx7ygBMSHufNYkjCXJkApybX0GO87aGNlVQtTANBgkqhkiG9w0BAQEF
# AASCAQAQruNwsugBSAhIUNZXVzHtGjKoM5WhyL5rf4raJw+iT3mAaPlX9s5PaOjQ
# Oxph5+9DHg9FUTv+kRtTD18CxhFoEm6jhTj78pbN4g4u6wy6Qod6ZdaiLpyY9KY8
# cAcyHkSZUDiYkRL5wrZ3UXl+uPsteG5q5knmqHNxIdDO4VSd7PUCmqVGI+DtfpnC
# aEMvkr7Md3KleABWLANeAvoXXIbaywcKlTv58fuNhAlZUJUKizcgqesjwtzPlWIs
# X+4MTVIVPv81riep/YqFCwv5UU3kpFG23eKiX7/+HIt/MI9Al05flhe7LGZQN3bO
# Qe4RsS8Y8VCyysyDlmjMAu8MaYEgoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTQ0MVowLwYJKoZIhvcNAQkEMSIEIN1aQXBNkmvjjF+X9N231i80bjKG
# qyPblj4WLU8g+i3GMA0GCSqGSIb3DQEBAQUABIICAJU0wM0zcb9ny4OVcdLcDV91
# yEME5dwWSgiO7JF17C9OCjrrLARME0hIrNKfVMOa/270M0DK0/m1mVLCyhQ2Zcm6
# y3wfOVWQjrsHKjio0H9a/AbnuN/L++KIYudFOC4OZTPFse7U1jQazXbeoCTOjWYc
# KWkZX04PXCS3F2n3YTVXcrlvQfHyilsQXYBvS91AJw5D6tjZqBPLbl4dmqYHiH4J
# WVhODlFQRPsp6adfeWJergmM6LTemklgSEbJYpiiGgtLAiCp+aqvPhULi6M7Xf/r
# dpAnHFKe4UfDjHy/tBNtZWY8+jhfrvQyM1v31vw/8RsMNBzvbRXWBGjMEZhlCg4P
# pdZsNXZJnunHE/7wzSeduvfKUrcZ5gr9OcIaFnHhrZfhR678V7CPu+ruoLcgW/ZO
# 9Ipw+zy67Nl5ZnCc3rRPiN201ov17AgBsXUgjrHRi79GXuRK5+t689Tg1u1GrWpr
# 98Bmpo0YjYFy9fP2c36vuy+1ivXC6ncG03CtEUua5ldPVfyNnRvZAZYhNOjGk/Ah
# qQpcyuf5AyzBobrbWpnWvRs2SlEIjQsm0tLLjYIOncjVammP7Ths91Zsv+heBRKN
# swj4CUadwpHShKUY/KyQFI371cWwX8aZsEHm6452zDoCH9uvEymykRmFJYv7ects
# QYuHEKJScNjesX4zkgMg
# SIG # End signature block
