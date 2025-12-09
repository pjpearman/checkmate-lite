##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     VMware Horizon 7.13 Connection Server
# Version:  V1R2
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Navy Standard Integrated Personnel System (NSIPS)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V246882 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246882
        STIG ID    : HRZV-7X-000001
        Rule ID    : SV-246882r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-AS-000001
        Rule Title : The Horizon Connection Server must limit the number of concurrent client sessions.
        DiscussMD5 : 60F74F059DB822DD1997C17C435F976A
        CheckMD5   : 9B4067D5F30181A58390D6F347EB4CFE
        FixMD5     : 01217EE4AF7BA6545FF24080DBD1CD2F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "maxConnections" # Name of the setting identified in STIG
    $ExpectedValue = @("2000") # Value(s) expected in STIG
    $MaxAllowedValue = "4000" # Maximum value allowed in STIG
    $SettingDescription = "Maximum concurrent client connections" # Short description of the setting
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ( ($ConfigurationSettings[$SettingName] -in $ExpectedValue) -or ($ConfigurationSettings[$SettingName] -le $MaxAllowedValue) ) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")] [Max Allowed: $MaxAllowedValue]" | Out-String
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

Function Get-V246883 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246883
        STIG ID    : HRZV-7X-000002
        Rule ID    : SV-246883r879520_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : The Horizon Connection Server must be configured to only support TLS 1.2 connections.
        DiscussMD5 : 4A1EE2D7AD0DB359B7B9575FC00C5D1A
        CheckMD5   : 0C843531FEDB4CC6363B615D918B95A7
        FixMD5     : E41812972FAFDCF11D1A9D5A0B8A84F3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "secureProtocols.1" # Name of the first setting identified in STIG
    $SettingName2 = "preferredSecureProtocol" # Name of the second setting identified in STIG
    $ExpectedValue = @("TLSv1.2") # Value(s) expected in STIG
    $ExpectedValue2 = @("TLSv1.2") # Value(s) expected in STIG
    $SettingDescription = "TLSv1.2 must be configured" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist check adsi edit to see if it is enforced globally
        $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
        $Filter = "(CN=Common)"
        $AdsiPropertyName = "pae-ServerSSLSecureProtocols"
        $ExpectedPropertyValue = "\LIST:TLSv1.2"

        $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([adsi]"$Root")
        $AdsiSearcher.SearchRoot
        $AdsiSearcher.Filter = "$Filter"
        [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
        $AdsiSearchResult = $AdsiSearcher.FindOne()

        Try {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
        Catch {
            $AdsiPropertyValue = "(Not Set)"
        }

        If ($AdsiPropertyValue -eq $ExpectedPropertyValue) {
            # TLSv1.2 is enforced globally for Horizon View servers, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist, however, $AdsiPropertyName is enforced globally via ADSI EDIT which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
            $FindingDetails += "LDAP Path:`t$Root" | Out-String
            $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
            $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
            $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
        }
        Else {
            If ($FileNotExistAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$ConfigurationFileName' file does not exist and $AdsiPropertyName is not being enforced globally via ADSI EDIT." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ( ($ConfigurationSettings[$SettingName] -in $ExpectedValue) -and ($ConfigurationSettings[$SettingName2] -in $ExpectedValue2) ) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                If ($ConfigurationSettings[$SettingName] -notin $ExpectedValue) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                }
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                If ($ConfigurationSettings[$SettingName2] -notin $ExpectedValue2) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2]) [Expected: $($ExpectedValue2 -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
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

Function Get-V246884 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246884
        STIG ID    : HRZV-7X-000003
        Rule ID    : SV-246884r879520_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : The Blast Secure Gateway must be configured to only support TLS 1.2 connections.
        DiscussMD5 : 513DEA2FF96FF7900D9A17A3DFFAAA8F
        CheckMD5   : 6AABA86BE6CA084C7580104531CA0F80
        FixMD5     : 6F2CB2938AEE5423AFB3D3F923E34948
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "absg.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "appblastgateway\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "localHttpsProtocolLow" # Name of the first setting identified in STIG
    $SettingName2 = "localHttpsProtocolHigh" # Name of the second setting identified in STIG
    $ExpectedValue = @("tls1.2") # Value(s) expected in STIG
    $ExpectedValue2 = @("tls1.2") # Value(s) expected in STIG
    $SettingDescription = "Blast Secure Gateway must be configured to only support TLSv1.2" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ( ($ConfigurationSettings[$SettingName] -in $ExpectedValue) -and ($ConfigurationSettings[$SettingName2] -in $ExpectedValue2) ) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                If ($ConfigurationSettings[$SettingName] -notin $ExpectedValue) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                }
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                If ($ConfigurationSettings[$SettingName2] -notin $ExpectedValue2) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2]) [Expected: $($ExpectedValue2 -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
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

Function Get-V246885 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246885
        STIG ID    : HRZV-7X-000004
        Rule ID    : SV-246885r879520_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : The Horizon Connection Server must force server cipher preference.
        DiscussMD5 : D42766F58A09CD431EA911F4D9283E1F
        CheckMD5   : 4A87054C673E9837ACC0EA5265EA7336
        FixMD5     : 6D3562E931D71C6C3343F8AE6095F28C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "honorClientOrder" # Name of the first setting identified in STIG
    $ExpectedValue = @("false") # Value(s) expected in STIG
    $SettingDescription = "Horizon Connection Server must force server cipher preference" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist check adsi edit to see if it is enforced globally
        $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
        $Filter = "(CN=Common)"
        $AdsiPropertyName = "pae-ServerSSLHonorClientOrder"
        $ExpectedPropertyValue = "0"

        $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([adsi]"$Root")
        $AdsiSearcher.Filter = "$Filter"
        [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
        $AdsiSearchResult = $AdsiSearcher.FindOne()

        Try {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
        Catch {
            $AdsiPropertyValue = "(Not Set)"
        }

        If ( $AdsiPropertyValue -eq $ExpectedPropertyValue) {
            # TLSv1.2 is enforced globally for Horizon View servers, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist, however, $AdsiPropertyName is enforced globally via ADSI EDIT which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
            $FindingDetails += "LDAP Path:`t$Root" | Out-String
            $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
            $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
            $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
        }
        Else {
            If ($FileNotExistAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$ConfigurationFileName' file does not exist and $AdsiPropertyName is not being enforced globally via ADSI EDIT." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
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

Function Get-V246886 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246886
        STIG ID    : HRZV-7X-000005
        Rule ID    : SV-246886r879521_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-APP-000016-AS-000013
        Rule Title : The Horizon Connection Server must be configured to debug level logging.
        DiscussMD5 : 0D9067C3DD9927198EEE66A069EDE8AF
        CheckMD5   : F38B1D7A3A8600F528E69CBCA19EAE2A
        FixMD5     : DCAD9C3AEC4C0A28FB865B4B9E20C000
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\VMware, Inc.\VMware VDM\"  # Registry path identified in STIG
    $RegistryValueName = "DebugEnabled"  # Value name identified in STIG
    $RegistryValue = @("True")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Debug level logging must be enabled"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $true  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $AF_UserHeader = $true
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        #$RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        #If the registry value does not exist
        If ($SettingNotConfiguredAllowed -eq $true) {
            #And it is allowed to be not configured set to notAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            #Or, if it must be configured, set this to Open
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        #If the registry value is found...
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                #If the registry result matches the expected value
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                #If the result value and expected value are different, print what the value is set to and what it should be.
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                #If the result type is the same as expected
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If the result type is different from what is expected, print both.
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V246888 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246888
        STIG ID    : HRZV-7X-000007
        Rule ID    : SV-246888r879554_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-AS-000045
        Rule Title : The Horizon Connection Server must require DoD PKI for administrative logins.
        DiscussMD5 : 3FDACC1187142B07AE4FEAC4E859E857
        CheckMD5   : A868F87CF541FDA0F6B903D619CC7C5D
        FixMD5     : 5FDD3CD00E02505B9338173D2EBCE9B5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Smart Card Authentication for Administrators"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-CertAuthAdmin"
    $ExpectedPropertyValue = "3"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    Try {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }
    Catch {
        $AdsiPropertyValue = "(Not Set)"
    }

    If ( $AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value: $ExpectedPropertyValue]" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246889 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246889
        STIG ID    : HRZV-7X-000008
        Rule ID    : SV-246889r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-AS-000050
        Rule Title : The Horizon Connection Server must be configured with an events database.
        DiscussMD5 : 0B2FFCB34BDA93DA0DC3AC87D99978FA
        CheckMD5   : DF422D94590190A45DDB5D127AABCC32
        FixMD5     : 85E9FD6F443739F6F7A74884001E5583
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Events Database"
    $Root = "LDAP://localhost:389/OU=Database,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=*)"
    $AdsiPropertyName = @("pae-DatabaseHostname", "pae-DatabaseName", "pae-DatabaseServerType", "pae-DatabaseTablePrefix", "pae-DatabaseUsername")

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.AddRange($AdsiPropertyName)
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    ForEach ($PropertyName in $AdsiPropertyName) {
        If ($AdsiSearchResult.Properties.Keys -notcontains "$PropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$PropertyName"])) {
            # Setting is not configured, set to Open
            $Status = "Open"
            $AdsiSearchResult.Properties["$PropertyName"] = "(Not Set)"
        }
    }

    If ($Status -eq "Open") {
        # Set finding details for an Open status
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Events Database details:" | Out-String
        $FindingDetails += "------------------------" | Out-String
        ForEach ($AdsiProperty in $AdsiPropertyName) {
            If ($AdsiSearchResult.Properties["$AdsiProperty"] -eq "(Not Set)") {
                $FindingDetails += "$AdsiProperty`:`t`t$($AdsiSearchResult.Properties["$AdsiProperty"]) [Expected a value other than (Not Set)]" | Out-String
            }
            Else {
                $FindingDetails += "$AdsiProperty`:`t`t$($AdsiSearchResult.Properties["$AdsiProperty"])" | Out-String
            }
        }
    }
    Else {
        # Set finding details for a NotAFinding status
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Events Database details:" | Out-String
        $FindingDetails += "------------------------" | Out-String
        ForEach ($AdsiProperty in $AdsiPropertyName) {
            $FindingDetails += "$AdsiProperty`:`t`t$($AdsiSearchResult.Properties["$AdsiProperty"])" | Out-String
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

Function Get-V246891 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246891
        STIG ID    : HRZV-7X-000010
        Rule ID    : SV-246891r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-AS-000124
        Rule Title : The Horizon Connection Server must perform full path validation on server-to-server TLS connection certificates.
        DiscussMD5 : A963345B39E5F4B05CF74749CD8DD914
        CheckMD5   : FE213C7D4601BFB71D51A4DD225C3116
        FixMD5     : F8160D3FB4E9F3238F62254BFE75C5DE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\VMware, Inc.\VMware VDM\Security\"  # Registry path identified in STIG
    $RegistryValueName = "CertificateRevocationCheckType"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Horizon Connection Server must perform full path validation on server-to-server TLS connection certificates"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $AF_UserHeader = $true
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        #$RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        #If the registry value does not exist
        If ($SettingNotConfiguredAllowed -eq $true) {
            #And it is allowed to be not configured set to notAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            #Or, if it must be configured, set this to Open
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        #If the registry value is found...
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                #If the registry result matches the expected value
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                #If the result value and expected value are different, print what the value is set to and what it should be.
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                #If the result type is the same as expected
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If the result type is different from what is expected, print both.
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V246892 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246892
        STIG ID    : HRZV-7X-000011
        Rule ID    : SV-246892r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-AS-000124
        Rule Title : The Horizon Connection Server must validate client and administrator certificates.
        DiscussMD5 : 99ADCC8A87DF3779E467CEC4F9AD176F
        CheckMD5   : F0592456EC61A05F8CB1CEA766CF499E
        FixMD5     : 664032326520D62303E43338DFF7EF49
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "enableRevocationChecking" # Name of the first setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $SettingDescription = "Horizon Connection Server must validate client and administrator certificates" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist check adsi edit to see if it is enforced globally
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist and $AdsiPropertyName is not being enforced globally via ADSI EDIT." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
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

Function Get-V246893 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246893
        STIG ID    : HRZV-7X-000012
        Rule ID    : SV-246893r879616_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-APP-000179-AS-000129
        Rule Title : The Horizon Connection Server must only use FIPS 140-2 validated cryptographic modules.
        DiscussMD5 : 309062D806BD0B2231A04CEFFA6C2988
        CheckMD5   : 90644EDF00E3F248862C4FE69AC29522
        FixMD5     : 24532D88399CA99C64287E68A79A5830
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingDescription = "Horizon Connection Server must only use FIPS 140-2 validated cryptographic modules"

    $FIPSModeEnabled = Get-ChildItem -Path C:\ProgramData\VMware\VDM\logs\* -Filter *.txt -ErrorAction SilentlyContinue | Select-String -SimpleMatch 'Broker started in FIPS mode'

    If ($FIPSModeEnabled) {
        # Found string in debug/log file(s), set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Found 'Broker started in FIPS mode' in the following log files:" | Out-String
        $FindingDetails += "-----------------------------" | Out-String
        ForEach ($Line in $FIPSModeEnabled) {
            $FindingDetails += $Line
        }
    }
    Else {
        # Did not find string in debug/log file(s), set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Did not find 'Broker started in FIPS mode' in any log files." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246894 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246894
        STIG ID    : HRZV-7X-000013
        Rule ID    : SV-246894r879637_rule
        CCI ID     : CCI-001185
        Rule Name  : SRG-APP-000220-AS-000148
        Rule Title : The Horizon Connection Server must time out administrative sessions after 15 minutes or less.
        DiscussMD5 : E074FEAF1F7ADFC3B99CC2AF236B6BB0
        CheckMD5   : 63A1C962FE72E1F939D682D55F593EF8
        FixMD5     : 74EF4BB83DA5D6F12ED02240AC4EBC85
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Connection Server Session Timeout"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-ConsoleSessionTimeout"
    $MaxPropertyValue = "900"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiSearchResult.Properties["$AdsiPropertyName"] = "(Not Set)"
    }

    $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]

    If ( $AdsiPropertyValue -le $MaxPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected a value less than or equal to $MaxPropertyValue]" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246895 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246895
        STIG ID    : HRZV-7X-000014
        Rule ID    : SV-246895r879656_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-AS-000170
        Rule Title : The Horizon Connection Server must protect log files from unauthorized access.
        DiscussMD5 : 5AD9ECEAED22B4153EE9092918C5B0E3
        CheckMD5   : 3DA9A47ABA77DC3B92CC6405AC719746
        FixMD5     : E558BC49B0CFDEB5FFE9644164864AFB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Log files must be protected from unauthorized access"
    $VDMLogsPath = "C:\ProgramData\VMware\VDM\logs"
    $ExpectedGroupsRegex = 'Administrators|NT Authority\\SYSTEM|NT Authority\\NETWORK SERVICE'

    $VdmLogsAccess = Get-Acl -Path $VDMLogsPath | Select-Object -ExpandProperty Access

    If ($VdmLogsAccess.IdentityReference -notmatch $ExpectedGroupsRegex) {
        # Setting is not configured according to the STIG, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "VDM Logs Path:`t$VDMLogsPath" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Security Access Details:" | Out-String
        ForEach ($AccessMember in $VdmLogsAccess) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "FileSystemRights:`t$($AccessMember.FileSystemRights)" | Out-String
            $FindingDetails += "AccessControlType:`t$($AccessMember.AccessControlType)" | Out-String
            $FindingDetails += "IdentityReference:`t$($AccessMember.IdentityReference)" | Out-String
            $FindingDetails += "IsInherited:`t`t$($AccessMember.IsInherited)" | Out-String
            $FindingDetails += "InheritanceFlags:`t$($AccessMember.InheritanceFlags)" | Out-String
            $FindingDetails += "PropagationFlags:`t$($AccessMember.PropagationFlags)" | Out-String
        }
    }
    Else {
        # Setting is configured according to the STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "VDM Logs Path:`t$VDMLogsPath" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Security Access Details:" | Out-String
        ForEach ($AccessMember in $VdmLogsAccess) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "FileSystemRights:`t$($AccessMember.FileSystemRights)" | Out-String
            $FindingDetails += "AccessControlType:`t$($AccessMember.AccessControlType)" | Out-String
            $FindingDetails += "IdentityReference:`t$($AccessMember.IdentityReference)" | Out-String
            $FindingDetails += "IsInherited:`t`t$($AccessMember.IsInherited)" | Out-String
            $FindingDetails += "InheritanceFlags:`t$($AccessMember.InheritanceFlags)" | Out-String
            $FindingDetails += "PropagationFlags:`t$($AccessMember.PropagationFlags)" | Out-String
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

Function Get-V246896 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246896
        STIG ID    : HRZV-7X-000015
        Rule ID    : SV-246896r879731_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000358-AS-000064
        Rule Title : The Horizon Connection Server must offload events to a central log server in real time.
        DiscussMD5 : 3DC25344EC4EF4FE26258933FD15BEBD
        CheckMD5   : C947FA5D23EF3FB884AA45520C7D7511
        FixMD5     : BE50CA6F34BBA53DAA8D836F2D9A7726
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Event Syslog Network Off-loading"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-eventSyslogNetworkAddresses"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ($AdsiPropertyValue -ne "(Not Set)") {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected a value other than '(Not Set)']" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246897 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246897
        STIG ID    : HRZV-7X-000016
        Rule ID    : SV-246897r879798_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-AS-000264
        Rule Title : The Horizon Connection Server must be configured with a DoD-issued TLS certificate.
        DiscussMD5 : 239F450C15607C09963AD2FCF862DE8F
        CheckMD5   : D726F269676C4B388768076A873199A2
        FixMD5     : 36CA8B4B7B003CA06F76CFF33FCD1A6E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "DoD-issued TLS Certificate"
    $CertPath = "Cert:\LocalMachine\My"
    $CertFriendlyName = "vdm"
    $CertExpectedIssuer = "DOD SW"

    $VdmCert = Get-ChildItem -Path "$CertPath\*" | Where-Object { $_.FriendlyName -eq "$CertFriendlyName" }

    If ($VdmCert.Issuer -match $CertExpectedIssuer) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
        $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
        $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
        $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
        $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246898 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246898
        STIG ID    : HRZV-7X-000017
        Rule ID    : SV-246898r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must reauthenticate users after a network interruption.
        DiscussMD5 : CE4B4B0350F2C2456F13A55C5B437FD4
        CheckMD5   : D231F7508FBE45FD8081A3CEA8CE110C
        FixMD5     : E014779B755CF857228EC1D03D39EBF7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Reauthenticate users after a network interruption"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-ReAuthOnNetInterrupt"
    $ExpectedPropertyValue = "0"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value: $ExpectedPropertyValue]" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246899 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246899
        STIG ID    : HRZV-7X-000018
        Rule ID    : SV-246899r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must disconnect users after a maximum of ten hours.
        DiscussMD5 : 5789AEDA4B08BA9B63D49F319B0FD448
        CheckMD5   : FFD903272A176DA6D429A8242AC79D5D
        FixMD5     : 15117D0B83A015B3E0C40DCEEB36AE23
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Forcibly Disconnect Users"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-MaxSessionTime"
    $ExpectedPropertyValue = "600"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        # The value is stored in seconds, even though the number you enter into the console is in minutes. So let's divide it by 60 so it matches up with the STIG
        If ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] -ge 0) {
            $AdsiPropertyValue = ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] / 60)
        }
        Else {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
    }

    If ($AdsiPropertyValue -ne "-1" -and $AdsiPropertyValue -le $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value less than or equal to $ExpectedPropertyValue, but not -1]" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246900 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246900
        STIG ID    : HRZV-7X-000019
        Rule ID    : SV-246900r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must disconnect applications after two hours of idle time.
        DiscussMD5 : 99C394E4F30B5EE4DA06BFF0535FAB03
        CheckMD5   : 97BB036136671E02A906430DBCC9B40A
        FixMD5     : 67365A73DF54ED51CE12C3B7A0E32C54
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Disconnect Applications and Discard SSO Credentials for Idle Users"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-UserIdleTimeout"
    $ExpectedPropertyValue = "120"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        # The value is stored in seconds, even though the number you enter into the console is in minutes. So let's divide it by 60 so it matches up with the STIG
        If ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] -ge 0) {
            $AdsiPropertyValue = ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] / 60)
        }
        Else {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
    }

    If ($AdsiPropertyValue -ne "-1" -and $AdsiPropertyValue -le $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value less than or equal to $ExpectedPropertyValue, but not -1]" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246901 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246901
        STIG ID    : HRZV-7X-000020
        Rule ID    : SV-246901r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must discard SSO credentials after 15 minutes.
        DiscussMD5 : 0ACEABED7FA3B14B4B6949625A518B52
        CheckMD5   : 3A8C91B22C3CAEBF640EC9B3DCB90859
        FixMD5     : 36091CD763F997C198C4C23B0703ED51
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Discard SSO Credentials"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-SSOCredentialCacheTimeout"
    $ExpectedPropertyValue = "15"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ($AdsiPropertyValue -ne "-1" -and $AdsiPropertyValue -le $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value less than or equal to $ExpectedPropertyValue, but not -1]" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246902 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246902
        STIG ID    : HRZV-7X-000021
        Rule ID    : SV-246902r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must not accept pass-through client credentials.
        DiscussMD5 : BD72FBB577D2CCAB68A146C6E182DE12
        CheckMD5   : BC1E1565A5D0D2A2D96A3B5F1ECEB336
        FixMD5     : B04AB2CA5BA95A0001FA1F686114D467
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Accept logon as current user"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-SendBrokerServicePrincipal"
    $ExpectedPropertyValue = "0"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value: $ExpectedPropertyValue]" | Out-String
    }

    # Check if "Smart card authentication for users" is set to required
    $SettingName = "Smart card authentication for users"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-CertAuth"
    $ExpectedPropertyValue = "3"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "'$SettingName' is set to 'Required', this STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246904 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246904
        STIG ID    : HRZV-7X-000023
        Rule ID    : SV-246904r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must backup its configuration daily.
        DiscussMD5 : 832CB529A2B39F8CE7C5562B89332C34
        CheckMD5   : 7063F35D7D9393FC2510F688C7F3ACE9
        FixMD5     : 983AE0B45CF4225F8F87876AF355FB1C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Automatic Backup Frequency"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($env:COMPUTERNAME))"
    $AdsiPropertyName = @("pae-LDAPBUFrequency", "pae-LDAPBUUnits")
    $ExpectedPropertyValue = @("1", "6", "12")
    $ExpectedPropertyValue2 = @("1", "2")

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.AddRange($AdsiPropertyName)
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    ForEach ($PropertyName in $AdsiPropertyName) {
        If ($AdsiSearchResult.Properties.Keys -notcontains "$PropertyName") {
            # Setting is not configured, add the property to the object and set the value
            $AdsiSearchResult.Properties["$PropertyName"] = "(Not Set)"
        }
    }

    If ($AdsiSearchResult.Properties["$($AdsiPropertyName[0])"] -in $ExpectedPropertyValue -and $AdsiSearchResult.Properties["$($AdsiPropertyName[1])"] -in $ExpectedPropertyValue2) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[0])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[0])"])" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[1])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[1])"])" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[0])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[0])"])" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[1])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[1])"])" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246905 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246905
        STIG ID    : HRZV-7X-000024
        Rule ID    : SV-246905r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server Instant Clone domain account must be configured with limited permissions.
        DiscussMD5 : 832CB529A2B39F8CE7C5562B89332C34
        CheckMD5   : BFEEA6A2DC2463E98B78E9425DAA2817
        FixMD5     : 2F184600681601F2F8E06A2D920881BA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Root = "LDAP://localhost:389/OU=VirtualCenter,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=*)"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($null -eq $AdsiSearchResult) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "There are no vCenter Servers configured, therefore Instant Clone is not supported. This STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246906 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246906
        STIG ID    : HRZV-7X-000025
        Rule ID    : SV-246906r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : 832CB529A2B39F8CE7C5562B89332C34
        CheckMD5   : F0B1DE92B81FBE700CF1CB4492F2813E
        FixMD5     : D30A2A74221F63C4D7A35311366369A8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RegistryPath = "HKLM:\Software\VMware, Inc.\VMware VDM\Plugins\wsnm\TunnelService\Params\"
    $RegistryValueName = "JvmOptions"
    $ExpectedValueString = "-Djdk.tls.rejectClientInitiatedRenegotiation=true"

    $JvmOptionsValue = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value

    If ($JvmOptionsValue -match $ExpectedValueString) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "This Horizon Connection Server is configured in accordance with the security configuration settings based on DoD security guidance." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
        $FindingDetails += "Value Data:`t$JvmOptionsValue" | Out-String
    }
    ElseIf ($JvmOptionsValue -eq "(NotFound)") {
        # Setting does not exist, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "This Horizon Connection Server is configured in accordance with the security configuration settings based on DoD security guidance." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName (Not Found)" | Out-String
        $FindingDetails += "Value Data:`t$JvmOptionsValue (Not Found)" | Out-String
    }
    Else {
        # Setting is not configured according to STIG, set to Open
        $Status = "Open"
        $FindingDetails += "This Horizon Connection Server is NOT configured in accordance with the security configuration settings based on DoD security guidance." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
        $FindingDetails += "Value Data:`t$JvmOptionsValue" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246907 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246907
        STIG ID    : HRZV-7X-000026
        Rule ID    : SV-246907r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must have X-Frame-Options enabled.
        DiscussMD5 : CFB9C2FEC2EA656035C930C10818C9D1
        CheckMD5   : 92F98A12C68B08304E703A7A0A92807C
        FixMD5     : 2237A4C7A4E12803DC519DBEE86E0571
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "X-Frame-Options" # Name of the setting identified in STIG
    $ExpectedValue = @("ON") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246908 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246908
        STIG ID    : HRZV-7X-000027
        Rule ID    : SV-246908r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must have Origin Checking enabled.
        DiscussMD5 : 274F67C46C4BFE44505AF353BAD5FC9E
        CheckMD5   : B30C9D17D126A1A2DB934F9611A8B14A
        FixMD5     : D7A58A4C1110E16C2D087A9EE2CE269D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "checkOrigin" # Name of the setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246909
        STIG ID    : HRZV-7X-000028
        Rule ID    : SV-246909r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must enable the Content Security Policy.
        DiscussMD5 : E369B00ACBA306A2130E484183F08000
        CheckMD5   : FB4169C6520F75019F99B4F0ABFCAC80
        FixMD5     : 4EC674A8ABCE330F4537F2CADAEFFFFF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "enableCSP" # Name of the setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246910 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246910
        STIG ID    : HRZV-7X-000029
        Rule ID    : SV-246910r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must enable the proper Content Security Policy directives.
        DiscussMD5 : 834EB6BC5AAB533FDDE0EE3F2B52995C
        CheckMD5   : A4BB003F0BE3EF7ACD1160EB1250CBA3
        FixMD5     : CBFE1CA45DD3EECB87A77A24492F4A86
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = @("content-security-policy", "content-security-policy-newadmin", "content-security-policy-portal", "content-security-policy-rest") # Name of the setting identified in STIG
    $SettingDescription = "Content Security Policy directives"
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            ForEach ($Setting in $SettingName) {
                $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
            }
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            ForEach ($Setting in $SettingName) {
                $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
            }
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath | Where-Object { $_.Keys -match "$SettingName" }
        If (-not ($ConfigurationSettings)) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                ForEach ($Setting in $SettingName) {
                    $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                ForEach ($Setting in $SettingName) {
                    $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists, set to Open
            $Status = "Open"
            $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
            ForEach ($Key in $ConfigurationSettings) {
                $FindingDetails += "Setting Name:`t$Key [This setting should not exist in $ConfigurationFileName]" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings["$Key"]) [This value should not be configured]" | Out-String
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

Function Get-V246911 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246911
        STIG ID    : HRZV-7X-000030
        Rule ID    : SV-246911r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The PCoIP Secure Gateway must be configured with a DoD-issued TLS certificate.
        DiscussMD5 : 56B3A205BDB99B62ADD2AC5F3C91D15E
        CheckMD5   : 87BB3F477415C4073D85C0B174AB96B8
        FixMD5     : AE07ADBB5B12DD5BF337259375A78812
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RegistryPath = "HKLM:\Software\Teradici\SecurityGateway\"
    $RegistryValueName = "SSLCertWinCertFriendlyName"
    $ExpectedValue = "vdm"

    $RegistryValue = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value

    $SettingName = "Use PCoIP Secure Gateway"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($Env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-BypassPCoIPSecureGateway"
    $ExpectedPropertyValue = "1"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "'$SettingName' is set to 'Disabled' for this Connection Server, this STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    ElseIf ($RegistryValue -eq $ExpectedValue) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$RegistryValueName' is set to '$ExpectedValue', this is not a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
        $FindingDetails += "Value Data:`t$RegistryValue" | Out-String
    }
    ElseIf ($RegistryValue -eq "(NotFound)") {
        # Setting does not exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$RegistryValueName' does not exist, this is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName (Not Found) [This registry value must exist]" | Out-String
        $FindingDetails += "Value Data:`t(Not Found)" | Out-String
    }
    Else {
        # Registry value differs from expected value, check to see if friendlyname certificate was issued by DoD
        $SettingName = "DoD-issued TLS Certificate"
        $CertPath = "Cert:\LocalMachine\My"
        $CertFriendlyName = $RegistryValue
        $CertExpectedIssuer = "DOD SW"

        $VdmCert = Get-ChildItem -Path "$CertPath\*" | Where-Object { $_.FriendlyName -eq "$CertFriendlyName" }

        If ($VdmCert) {
            # Certificate exists, check Issuer...
            If ($VdmCert.Issuer -match $CertExpectedIssuer) {
                # Cert was issued by DoD, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$CertFriendlyName' was issued by DoD, this is not a finding." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
                $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
                $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
            }
            Else {
                # Cert was not issued by DoD, set to Open
                $Status = "Open"
                $FindingDetails += "'$CertFriendlyName' was not issued by DoD, this is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
                $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
                $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
            }
        }
        Else {
            # Certificate does not exist, set to Open
            $Status = "Open"
            $FindingDetails += "A certificate with FriendlyName '$CertFriendlyName' does not exist, this is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
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

Function Get-V246912 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246912
        STIG ID    : HRZV-7X-000031
        Rule ID    : SV-246912r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must not allow unauthenticated access.
        DiscussMD5 : F88A3CBF38BF12AAB169CA3BA9774B4C
        CheckMD5   : B468188BA6EA21851137C9576EA88FFB
        FixMD5     : 33CA093C9FD22873F9598F33AFB20E61
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Allow Unauthenticated Access"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($Env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-AnonymousLogonEnabled"
    $ExpectedPropertyValue = "0"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    $SettingName2 = "Smart card authentication for users"
    $Root2 = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter2 = "(CN=Common)"
    $AdsiPropertyName2 = "pae-CertAuth"
    $ExpectedPropertyValue2 = "3"

    $AdsiSearcher2 = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher2.Filter = "$Filter2"
    [void]$AdsiSearcher2.PropertiesToLoad.Add("$AdsiPropertyName2")
    $AdsiSearchResult2 = $AdsiSearcher2.FindOne()

    If ($AdsiSearchResult2.Properties.Keys -notcontains "$AdsiPropertyName2" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult2.Properties["$AdsiPropertyName2"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue2 = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue2 = $AdsiSearchResult2.Properties["$AdsiPropertyName2"]
    }

    If ([string]$AdsiPropertyValue2 -eq $ExpectedPropertyValue2) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "'$SettingName2' is set to 'Required', this STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
        $FindingDetails += "LDAP Path:`t$Root2" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter2" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName2" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue2" | Out-String
    }
    ElseIf ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is set to 'Disabled', this is not a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Setting is not configured according to STIG, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is set to 'Enabled', this is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246913 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246913
        STIG ID    : HRZV-7X-000032
        Rule ID    : SV-246913r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must require CAC reauthentication after user idle timeouts.
        DiscussMD5 : DC7153A0FFFADC22D248BD71290DB04E
        CheckMD5   : 64B578EF9A9CD3A90A26FE13C21EF059
        FixMD5     : 21B7F96F66208F252059126AF3BB2A32
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Enable 2-Factor Reauthentication"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-EnableMultiFactorReAuth"
    $ExpectedPropertyValue = "1"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is set to 'Yes', this is not a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Setting is not configured according to STIG, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is set to 'No', this is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V246915 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246915
        STIG ID    : HRZV-7X-000034
        Rule ID    : SV-246915r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must prevent MIME type sniffing.
        DiscussMD5 : F0106259DEBFD6EA4A53BAF4E12CAAC1
        CheckMD5   : 749FC6DB93CEB9BD1EE0B3FDB11BC5DF
        FixMD5     : 2CF0260E882127A93174833CAE84DF2B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "x-content-type-options" # Name of the setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246916 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246916
        STIG ID    : HRZV-7X-000035
        Rule ID    : SV-246916r951010_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-AS-000266
        Rule Title : All Horizon components must be running supported versions.
        DiscussMD5 : 117ECC7EE34DF6F898C147FBFE6F17EA
        CheckMD5   : 8BA15EC8F9FC5BF438B7A8D7F330BC07
        FixMD5     : 985E09DC4521A949B0A14C40DD96245E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $HorizonSoftware = Get-InstalledSoftware | Where-Object DisplayName -match "^VMware Horizon"

    If ($HorizonSoftware | Where-Object {[Version]$_.DisplayVersion -lt [Version]"8.0"}) {
        $Status = "Open"
        ForEach ($Item in $HorizonSoftware) {
            $FindingDetails += "$($Item.DisplayName) $($Item.DisplayVersion) is installed.  [finding]" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No Horizon 7.x components are installed." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDuEjA/IA6xpdAO
# lEnw3SWY9Wv2PzblP2/+/QEzUV/WTqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCCESShK2rhCrMdgr9ar6/rxnQfDg22RPf/ENogmCIJ0ZzANBgkqhkiG9w0BAQEF
# AASCAQAuisTHUBh4WQqGwY0O/1XrzkI3RxAq28SPRp4hQXsglSC9u8zfuE16rYeP
# sGMiF1G0N+riAVe6nbgFDApw+TW9JePuWOySNLI8hPke/7MDzy3jv5WArekKPz3s
# T6BJW4GAKp71K3D7ZWd5z1TBqEyrdlnZ8IaKXWTebz/eXHFB69Pd3PEn3ifsqHU7
# YkhtPXY0Q/dqCcL/SA7HZ/dVRdAk8fGsRWClu67E+TctkQjA9wt7KAm3pAVUf4+k
# t4DmX+LCPWuVqEVf5hJdzH3DbW6RHOXJVyR1KGiZsO6DFrsDh3NI8Z1e79MuTz1B
# bl+R1ywKByMeN8iXVOh+SjTE7EekoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTkwNlowLwYJKoZIhvcNAQkEMSIEIDLuIdgqyymAKumAYZDKulxlk+nN
# mqa4ZIU6zu+yp6qUMA0GCSqGSIb3DQEBAQUABIICAB09AEGZJz+xGVzGnFRZN/12
# bgRKhI4babQsMsOSeAeM5yzXIsCzAfSS9vm0Zvm4Y6L6dv6VzkC+tmMXrLvBFsrn
# ggbTZlb52hdFFflEZmaq4jHtf5J/PZq8NN5LgDE3cNwdoxyorjJYK5l3usd2mi6g
# gMPg8Mn1W6hoJ1lpirsQouzCSq1oul8I6zVW+WmNf6JubBLgYHFpVW6i63MaipSt
# OCPvTpiyPj+15fhFCx1tYbl/zFevWALqfDt/C2pRfHvyb2rI7VDi9HoCnPEtqCH2
# XM+glUnLyOSWanjUUvlvF2aDCe0OckVjD05+AFf3D/TdQ8XcM/YaRI4OPACXYbfN
# S1d0vqAdNh0Psf5hEB5Oas72cPFAnryXIVUrNCsB0q7KDGhiVyl7tyuAPSHY8RTM
# vDcwVOFIlZlDPm5VaDwxG1oYZDZwv0XETqb9F6o1z1Tboto7R/W+nXyZd16nZEM6
# tAEqZaB3G04M/G4lAXTTqN6Mg202IUNL4CPO7IFkakKAeYYaLHdjPA01jHF0SZNL
# yqh+l68cwVf1uDr0e2lqPEHzn42ILlNKXHyeB++/gj3sZS1rGRzrWc4P8SJReoGN
# Ug3BqOmzWjmqEGnorOOtZ6euyH+bhPVMxC6UVbfEezGinI65J4CqRGb5PGovP1D8
# 9EpeQWpAmBylubDU/y7G
# SIG # End signature block
