##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     JBoss Enterprise Application Platform 6.3
# Version:  V2R6
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

If ($null -eq $env:NOPAUSE -or $env:NOPAUSE -eq ""){
$env:NOPAUSE = "true"
}

Function Get-JBossCLI {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Command, ###Comand to be run in CLI
        [Parameter(Mandatory = $True)]
        [string] $Setting, ###Define the parameter to check.
        [Parameter(Mandatory = $True)]
        [string] $ExpectedValue, ###Expected value being checked (e.g. True, False, on, off, etc.).
        [Parameter(Mandatory = $false)]
        [string] $SettingRegex, ###The value detected by STIG functions/commands.
        [Parameter(Mandatory = $True)]
        [string] $ValueRegex, ###The value detected by STIG functions/commands.
        [Parameter(Mandatory = $False)]
        [string] $CLIPath ###Optional parameter if jboss object is not already created
    )

    Process {
        if ($null -eq $CLIPath -or $CLIPath -eq "") {
            $Result = Get-JBossCliOutput -Command $Command
        }
        else {
            $Result = Get-JBossCliOutput -Command $Command -CLIPath $CLIPath
        }
        $DetectedValue = "Not Found"
        $FoundCount=0
        foreach ($line in $Result) {
            if ($line | Select-String '^CLI Error') {
                $DetectedValue = "No Output"
                break
            }
            if ($null -ne $SettingRegex -and $SettingRegex -ne "") {
                if ($line | Select-String $SettingRegex) {
                    $DetectedValue = $line
                }
            }
            if ($line | Select-String $ValueRegex) {
                $DetectedValue = $line
                $FoundCount++
            }
        }
        if ($null -eq $ServerMode -or $ServerMode -eq "") {
            $ProcDetails = (Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue)
        }
        else{
            $ProcDetails = "None"
        }
        $CLIObject = [PSCustomObject]@{
            Details = $ProcDetails
            Count = $FoundCount
            DetectedValue = $DetectedValue
        }
        return $CLIObject
    }
}

Function Get-JBossCliOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $False)]
        [string] $CLIPath ###Optional parameter if object is not yet created
    )


    if ($($JBossInstance.CLIPath -ne "Not Found")){

###Might need to set NOPAUSE env variable. Check cli.bat
        if ($JBossInstance.CLIPath -eq "" -or $null -eq $JBossInstance.CLIPath) {
            $CLIOutput =  & "$CLIPath" --connect --command=$Command
        }
        else {
            $CLIOutput =  & $($JBossInstance.CLIPath) --connect --command=$Command
        }

        if ($null -eq "$CLIOutput" -or "$CLIOutput" -eq ""){
        	$CLIOutput = "no output"
        }
        elseif ( $CLIOutput | Select-String -Pattern "Failed to fetch the list"){
            foreach ( $line in $CLIOutput ){
                $CLIError = $line | Select-String -Pattern "failure-description"
                if ($null -ne $CLIError) {
                    $CLIOutput="CLI Error:"
                    $CLIOutput += ($line -replace ',')
                    break
                }
            }
        }
        return $CLIOutput
    }
  return $null
}

Function Get-JBossFormattedOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string] $Setting, ###Define the parameter to check.
        [Parameter(Mandatory = $True)]
        [string] $ExpectedValue, ###Expected value being checked (e.g. True, False, on, off, etc.).
        [Parameter(Mandatory = $True)]
        [string] $DetectedValue, ###The value detected by STIG functions/commands.
        [Parameter(Mandatory = $False)]
        [string] $Profile, ###Optional parameter if you want to include profile names in findings
        [Parameter(Mandatory = $False)]
        [string] $Hostname ###Optional parameter if you want to include profile names in findings
    )

    Process {
        $FormattedOutput = "" # Start with a clean slate.
        foreach ($value in $DetectedValue) {
            $FormattedOutput += "Configuration:`t`t$($JBossInstance.ServerMode)" | Out-String
            if($null -ne $Profile -and $Profile -ne ""){
                $FormattedOutput += "Profile:`t`t`t$($Profile)" | Out-String
            }
            if ($null -ne $Hostname -and $Hostname -ne "") {
                $FormattedOutput += "Host:`t`t`t$($Hostname)" | Out-String
            }
            $FormattedOutput += "Setting:`t`t`t$($Setting)" | Out-String
            $FormattedOutput += "Expected Value:`t$($ExpectedValue)" | Out-String
            $FormattedOutput += "Detected Value:`t$($DetectedValue)" | Out-String
            $FormattedOutput += "" | Out-String
        }
        return $FormattedOutput
    }
}

Function Get-JBOSSInstance {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [String]$ProcessString,
        [Parameter(Mandatory = $false)]
        [String]$HostConfigFile,
        [Parameter(Mandatory = $false)]
        [String]$DomainConfigFile
    )

    $Server=$(hostname)
    $HomeDir="Not Found"
    $BaseDir="Not Found"
    $BindAddr="Not Found"
    $ManAddr = "Not Found"
    $LogDir = "Not Found"
    $ServerMode="Not Found"
    $ServerConfigPath = "Not Found"
    $ServerConfig="Not Found"
    $DomainConfig=$DomainConfigFile
    $HostConfig= $HostConfigFile
    $ConfigDir="Not Found"

    if($isLinux){
        $ProcessID = $ProcessString | awk '{print $2}'
        $ProcessUser = ps -o uname= -p $ProcessID
    }
    else{
        $ProcessID = ($ProcessString.Trim() -Split " ")[0]
        $ProcessUser = (Get-Process -Id $ProcessID -IncludeUserName).Username
    }

    if ($null -eq $ProcessUser -or $ProcessUser -eq "") {
        $ProcessUser = "Unknown"
    }

    $ModProcessString = $ProcessString.replace(' -','|')
    $ModProcessString = $ModProcessString.replace('"-',"|")
    $ModProcessString = $ModProcessString.replace('}',"")
    $ProcessArray = $ModProcessString -Split "\|"

    foreach ($i in $ProcessArray) {
        $line = $i.Replace("=","|")
        $linearray = $line -Split "\|"
        if ($null -ne $linearray[1] -and $linearray[1] -ne "") {
            $ArrayValue = $linearray[1].Trim()
            $ArrayValue = $ArrayValue.Replace('"','')
            $ArrayValue = $ArrayValue.Replace('file:','')
        }
        else {
            $ArrayValue="Not Found"
        }
        if ($line | Select-String -Pattern "D\[Server:") {
        	$Server = (($line -split ":")[1]).Replace(']','')
            continue
        }
        if ($line | Select-String -Pattern "jboss.home.dir") {
            $HomeDir = $ArrayValue
            continue
        }
        if ($line | Select-String -Pattern "jboss.server.base.dir") {
            $BaseDir = $ArrayValue
            continue
        }
        if ($line | Select-String -Pattern "jboss.server.log.dir") {
            $LogDir = $ArrayValue
            continue
        }
        if ($line | Select-String -Pattern "jboss.domain.log.dir") {
            $LogDir = $ArrayValue
            continue
        }
        if ($line | Select-String -Pattern "^jaxpmodule") {
            if ($line | Select-String -Pattern "org.jboss.as.standalone") {
                $ServerMode="standalone"
                continue
            }
        }
        if (($line | Select-String -SimpleMatch -Pattern "^b|") -or ($line | Select-String -Pattern "jboss.bind.address")) {
            $BindAddr = $ArrayValue
            continue
        }
        if (($line | Select-String -Pattern "^bmanagement") -or ($line | Select-String -Pattern "jboss.bind.address.management")) {
            $ManAddr = $ArrayValue
            continue
        }
        if (($line | Select-String -SimpleMatch -Pattern "^c|server-config") -or ($line | Select-String -SimpleMatch -Pattern "server-config")) {
            $ServerConfig = $ArrayValue
            continue
        }
        if ($line | Select-String -Pattern "server.config.dir") {
            $ConfigDir = $ArrayValue
            continue
        }

    }

    if ($ServerMode -eq "standalone") {
        if ($BaseDir -eq "Not Found") {
            $BaseDir = "$HomeDir/$($ServerMode)"
        }
        if ($ConfigDir -eq "Not Found") {
            $ConfigDir = "$BaseDir/configuration"
        }
        if ($ServerConfig -eq "Not Found") {
            $ServerConfigPath = "$ConfigDir/$($ServerMode).xml"
        }
        else {
            $ServerConfigPath = "$ConfigDir/$($ServerConfig)"
        }
    }
    else {
        $ServerMode = "domain"
        if ($BaseDir -eq "Not Found") {
            $BaseDir = "$HomeDir/$($ServerMode)"
        }
        if ($ConfigDir -eq "Not Found") {
            $ConfigDir = "$BaseDir/configuration"
        }
        if ($null -eq $DomainConfig -or $DomainConfig -eq "") {
            $DomainConfigPath = "$ConfigDir/domain.xml"
        }
        else {
            $DomainConfigPath = "$ConfigDir/$($DomainConfig)"
        }
    }
    if($IsLinux){
        $ChildPath = "/bin/jboss-cli.sh"
        $CLIPath = Join-Path -Path $HomeDir -ChildPath "$ChildPath"
    }
    else{
        $ChildPath = "/bin/jboss-cli.bat"
        $CLIPath = Join-Path -Path $HomeDir -ChildPath "$ChildPath"
    }
    if (Test-Path -Path $CLIPath){
        Try{
            $Command = 'ls /profile'
            $Profiles =  @(& $CLIPath --connect --command=$Command)
        }
        Catch {
            $Profiles = "Not Found"
        }
        Try {
            $Command = 'ls /socket-binding-group='
            $SocketBindingGroup = @(& $CLIPath --connect --command=$Command)
        }
        Catch {
            $Hosts = "Not Found"
        }
        Try {
            $Command = 'ls /host'
            $Hosts = @(& $CLIPath --connect --command=$Command)
        }
        Catch {
            $Hosts = "Not Found"
        }
    }
    else{
    	$CLIPath = "Not Found"
    }
    if ($LogDir -eq "Not Found") {
        $LogDir = "$BaseDir/log"
    }
    if ($ManAddr -eq "Not Found") {
        if ($ServerMode -eq "standalone") {
            $CLICommand = "ls /interface=management"
        }
        else {
            $CLICommand = "ls /host=$hosts/interface=management"
        }
        $Outputs =  & $CLIPath --connect --command=$CLICommand
        foreach ($line in $outputs) {
            if ( $line | Select-String -Pattern "Inet-Address=" ) {
                $line = $line -replace '[${}]',''
                $ManAddr= ($line -Split "=")[1]
                $ManAddr= ($ManAddr -Split ":")[1]
            }
        }
    }

    # CLI Output to be added as object for 213503 and other like checks
    if ($ServerMode -eq "standalone") {
        $CLICommand = "ls /core-service=management/access=audit/logger=audit-log"
    }
    else {
        $CLICommand = "ls host=$Hosts/server=$Server/core-service=management/access=audit/logger=audit-log"
    }
    $AuditLogEnabledOutputs = Get-JBossCLI -Command "$CLICommand" -Setting "audit-log" -ExpectedValue "enabled=true" -SettingRegex '"enabled"' -ValueRegex "^\s*enabled\s*=\s*false\s*$" -CLIPath $CLIPath
    $AuditLogStatus = $AuditLogEnabledOutputs.DetectedValue
    if ($BindAddr -eq "Not Found") {
        if ($ServerMode -eq "standalone") {
            $CLICommand = "ls /interface=public"
        }
        else {
            $CLICommand = "ls /host=$hosts/interface=public"
        }
        $Outputs =  & $CLIPath --connect --command=$CLICommand
        foreach ($line in $outputs) {
            if ( $line | Select-String -Pattern "Inet-Address=" ) {
                $line = $line -replace '[${}]',''
                $BindAddr= ($line -Split "=")[1]
                $BindAddr= ($BindAddr -Split ":")[1]
            }
        }
    }

    $Instance = [PSCustomObject]@{
        Server              = $Server
        ProcessID           = $ProcessID
        ProcessUser         = $ProcessUser
        HomeDir             = $HomeDir
        BaseDir             = $BaseDir
        BindAddr            = $BindAddr
        ManAddr             = $ManAddr
        LogDir              = $LogDir
        ConfigDir           = $ConfigDir
        ServerMode          = $ServerMode
        ServerConfig        = $ServerConfig
        DomainConfig        = $DomainConfig
        HostConfig          = $HostConfig
        ProcessString       = $ProcessString
        ServerConfigPath    = $ServerConfigPath
        DomainConfigPath    = $DomainConfigPath
        Profiles            = $Profiles
        Hosts               = $Hosts
        CLIPath             = $CLIPath
        SocketBindingGroup  = $SocketBindingGroup
        AuditLogStatus      = $AuditLogStatus
    }

    return $Instance
}

Function Get-JBossInstances {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param (
    )

    if ($IsLinux) {
        $ProcessStrings = ps -ef | grep jboss.home.dir | grep -v grep

    }
    else {
            if (($PsVersionTable.PSVersion).ToString() -match "5.*") {
                $ProcessStrings = Get-WmiObject Win32_Process -Filter "Name= 'java.exe'" -ErrorAction SilentlyContinue | ForEach-Object { if ($_.CommandLine | Select-String -Pattern "jboss.home.dir") {Write-Output "$($_.ProcessId) $($_.CommandLine)}" }}
            }
            else{
                $ProcessStrings = (Get-Process -Name "java" | ForEach-Object { if ($_.CommandLine | Select-String -Pattern "jboss.home.dir") {
                Write-Output "$($_.Id) $($_.CommandLine)}"
                }})
        }
    }
    foreach ($string in $ProcessStrings){
        $HostConfigline =  $string | Select-String -Pattern "--host-config=.+\.xml" | ForEach-Object {$_.Matches.Value}
        if ($HostConfigline){
            $HostConfigFile = ($HostConfigline -Split ("="))[1]
            break
        }
        $DomainConfigline =  $string | Select-String -Pattern "--domain-config=.+\.xml" | ForEach-Object {$_.Matches.Value}
        if ($DomainConfigline){
            $DomainConfigFile = ($DomainConfigline -Split ("="))[1]
            break
        }
    }

    [System.Collections.ArrayList]$Instances = @()
    foreach ($ProcessString in $ProcessStrings) {
        if($ProcessString | Select-String -Pattern 'D\[Host Controller\]' -NotMatch){
            if ($null -ne $ProcessString -and $ProcessString -ne "") {
                $Instance = Get-JBOSSInstance -ProcessString $ProcessString -HostConfigFile $HostConfigFile -DomainConfigFile $DomainConfigFile
                [void] $Instances.add($Instance)
            }
        }
    }

    return $Instances
}

Function Get-V213494 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213494
        STIG ID    : JBOS-AS-000010
        Rule ID    : SV-213494r960759_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-AS-000009
        Rule Title : HTTP management session traffic must be encrypted.
        DiscussMD5 : 1ACDC6E8E8E565744A95EC13699C6027
        CheckMD5   : 12599095E333FA5B55898AD0686A112D
        FixMD5     : 4436E637F06DF112651A88142CC7EE76
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/management-interface=http-interface"
        $Setting = "secure-socket-binding"
        $SettingRegex = 'secure-socket-binding\s*='
        $ValueRegex = 'secure-socket-binding\s*=\s*undefined'
    }
    else {
        $CLICommand = "ls /host=$($JBossInstance.Hosts)/core-service=management/management-interface=http-interface"
        $Setting = "secure-port"
        $SettingRegex = 'secure-port\s*='
        $ValueRegex = 'secure-port\s*=\s*undefined'
    }
    $ExpectedValue = "<defined>"
    $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
    if ($($Outputs.Count) -eq 0) {
        $Status = "NotAFinding"
    }
    $FindingDetails += $Outputs.Details
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213495 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213495
        STIG ID    : JBOS-AS-000015
        Rule ID    : SV-213495r960762_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : HTTPS must be enabled for JBoss web interfaces.
        DiscussMD5 : 0B8C6F5C6ED518E71AFA1E387FD385AA
        CheckMD5   : 0F02BEBAF2B0FB53350815BA54B8C63C
        FixMD5     : 5E1E33D31DE8910282C7BFDE061185D7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Status="Open"
    $Setting = "Connector"
    $ExpectedValue = "https"
    $ValueRegex = "^\s*\bhttps\b\s*$"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=web/connector="
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
        if ($($Outputs.Count) -eq 0) {
            $ErrorCount++
        }
    }
    else {
        foreach ($Profile in $($JBossInstance.Profiles)){
            $CLICommand = "ls /profile=$Profile/subsystem=web/connector="
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $($Outputs.DetectedValue) -Profile $Profile
            if ($($Outputs.Count) -eq 0) {
                $ErrorCount++
            }
        }
    }


    if ($ErrorCount -eq 0) {
        $Status="NotAFinding"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213496 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213496
        STIG ID    : JBOS-AS-000025
        Rule ID    : SV-213496r1069472_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Java permissions must be set for hosted applications.
        DiscussMD5 : C6E8FF3F1E0218721D077DFDF5408CB8
        CheckMD5   : EA82831B3563ECAC59D990823F630DA6
        FixMD5     : 8B486532737F15E7D1907DCD6E1C49DB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # Need logic to determine JDK version.  Per STIG, if JDK 24 is used, it's an automatic NF.
    $VariableName = "java.security.policy"
    $ServerConfig = Join-Path -Path $(Join-Path -Path $JBossInstance.HomeDir -ChildPath "bin") -ChildPath "$($JBossInstance.ServerMode).conf"
    $EnvironmentString = ($JBossInstance.ProcessString | Select-String -Pattern "$VariableName\=\S*" -AllMatches).Matches.Value

    if ( $null -eq $EnvironmentString) {
        $EnvironmentValue = "Not Defined"
    }
    else {
        $EnvironmentValue = ($EnvironmentString -Split "=")[1]
    }

    $FindingDetails += "Server Mode: $($JBossInstance.ServerMode)" | Out-String
    $FindingDetails += "Server Config: $($ServerConfig)" | Out-String
    $FindingDetails += "Variable Name: $($VariableName)" | Out-String
    $FindingDetails += "Variable Value: $($EnvironmentValue)" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213497 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213497
        STIG ID    : JBOS-AS-000030
        Rule ID    : SV-213497r1069475_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : The Java Security Manager must be enabled for the JBoss application server.
        DiscussMD5 : 31A3C6EB57601A1BA107ACE52B299750
        CheckMD5   : 54CA9A60A5A96F2E8DB16D0AAC499B43
        FixMD5     : B8B07A81B8773050A45AD6A0F43D3DD4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # Need logic to determine JDK version.  Per STIG, if JDK 24 is used, it's an automatic NF.
    $ErrorCount = 0
    $VariableName = "java.security.manager"
    $ServerConfig = Join-Path -Path $(Join-Path -Path $JBossInstance.HomeDir -ChildPath "bin") -ChildPath "$($JBossInstance.ServerMode).conf"
    $EnvironmentString = ($JBossInstance.ProcessString | Select-String -Pattern "$VariableName" -AllMatches).Matches.Value

    if ( -Not $isLinux ) {
        $ServerConfig = ($ServerConfig + ".bat")
    }

    if ( $null -eq $EnvironmentString) {
        $EnvironmentValue = "False"
        $ErrorCount++
    }
    else {
        $EnvironmentValue = "True"
    }

    $FindingDetails += "Server Mode: $($JBossInstance.ServerMode)" | Out-String
    $FindingDetails += "Server Config: $($ServerConfig)" | Out-String
    $FindingDetails += " " | Out-String
    $FindingDetails += "Java Option: $($VariableName)" | Out-String
    $FindingDetails += "Set: $($EnvironmentValue)" | Out-String
    $FindingDetails += " " | Out-String

    $VariableName = "java.security.policy"
    $EnvironmentString = ($JBossInstance.ProcessString | Select-String -Pattern "$VariableName=\S*\b" -AllMatches).Matches.Value

    if ( $null -eq $EnvironmentString) {
        $EnvironmentValue = "Not Defined"
        $ErrorCount++
    }
    else {
        $EnvironmentValue = $EnvironmentString
    }

    $FindingDetails += "Java Option: $($VariableName)" | Out-String
    $FindingDetails += "Value: $($EnvironmentValue)" | Out-String

    if ( $ErrorCount -gt 0 ) {
        # $Status="Open"  # Commenting out until JDK version logic can be worked in.
        $FindingDetails += " " | Out-String
        $JavaOptions = ($JBossInstance.ProcessString | Select-String -Pattern "-D\S*\b" -AllMatches).Matches.Value
        $FindingDetails += "Process String: $($JBossInstance.ProcessString)" | Out-String
        $FindingDetails += " " | Out-String
    }
    else {
        $Status="NotAFinding"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213498 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213498
        STIG ID    : JBOS-AS-000035
        Rule ID    : SV-213498r1028281_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : The JBoss server must be configured with Role Based Access Controls.
        DiscussMD5 : 1C8FE016507B6448D6DC92A7BF162335
        CheckMD5   : 85DD086779E1EFC2BA145E2F5D7430DF
        FixMD5     : 52E5681D77BE1078AF9B8B4E9F4C5DB8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status="Open"
    $Setting = "Access-Control"
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/access=authorization/"
    }
    else {
        $CLICommand = "ls /core-service=management/access=authorization/"
    }
    $ExpectedValue = "provider=rbac"
    $SettingRegex = 'provider\s*='
    $ValueRegex = 'provider\s*=\s*rbac'
    $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
    if ($($Outputs.Count) -gt 0) {
        $Status="NotAFinding"
    }
    $FindingDetails += $Outputs.Details
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213499 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213499
        STIG ID    : JBOS-AS-000040
        Rule ID    : SV-213499r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Users in JBoss Management Security Realms must be in the appropriate role.
        DiscussMD5 : ECFDF26B6E037BD138717183CBF005FC
        CheckMD5   : 7736871E9512873619995B4BB1353DDD
        FixMD5     : 298254D9466E548AD9E4C5D41B18E09D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ChildPath = "mgmt-users.properties"
    $FilePath = Join-Path -Path $($JBossInstance.ConfigDir) -ChildPath $ChildPath
    $MgmtUsers = (Get-Content $FilePath) | Select-String -Pattern '^\s{0,}#' -NotMatch
    $FindingDetails += "Configuration:`t$($JBossInstance.ServerMode)" | Out-String
    $FindingDetails += "File:`t`t`t$($FilePath)" | Out-String
    $FindingDetails += "Users:" | Out-String

    if ($null -eq $MgmtUsers -or $MgmtUsers -eq ""){
        $FindingDetails += "`t`t`tNone Found"  | Out-String
    }
    else{
        foreach ($line in $MgmtUsers){

            if ($line | Select-String -Pattern '\\=' -NotMatch){
                $user = $(($line.ToString() -Split '=')[0]  | Out-String).Trim()
                $FindingDetails += "`t`t`t$user" | Out-String
            }
            else{
                $BadString = ($line.ToString() -Split "=")[-1]
                $user = $($line -Split("\=$BadString")  | Out-String).Trim()
                    $FindingDetails += "`t`t`t$user" | Out-String
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

Function Get-V213500 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213500
        STIG ID    : JBOS-AS-000045
        Rule ID    : SV-213500r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Silent Authentication must be removed from the Default Application Security Realm.
        DiscussMD5 : 9DFBE189A73375B5F9CBD32FA2BEDD90
        CheckMD5   : E65380C09FE35D8CA128341595C6A0BC
        FixMD5     : 7CA1A182E21BE883786D52991B70469B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Setting = "Security-Realm"
    $ExpectedValue = "Not 'local'"
    $BadValue = "local"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $DetectedValue = $ExpectedValue
        $CLICommand = "ls /core-service=management/security-realm=ApplicationRealm/authentication"
        $Result = Get-JBossCliOutput -Command $CLICommand

        foreach ($line in $Result) {
            if ($line | Select-String $BadValue) {
                $DetectedValue = $BadValue
                $ErrorCount++
                break
            }
        }

        $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $DetectedValue = $ExpectedValue
        $CLICommand = "ls /host=$($JBossInstance.Hosts)/core-service=management/security-realm=ApplicationRealm/authentication"
        $Result = Get-JBossCliOutput -Command $CLICommand

        foreach ($line in $Result) {
            if ($line | Select-String $BadValue) {
                $DetectedValue = $BadValue
                $ErrorCount++
                break
            }
        }

        $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }

    if ($ErrorCount -eq 0) {
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

Function Get-V213501 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213501
        STIG ID    : JBOS-AS-000050
        Rule ID    : SV-213501r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : Silent Authentication must be removed from the Default Management Security Realm.
        DiscussMD5 : 9DFBE189A73375B5F9CBD32FA2BEDD90
        CheckMD5   : 95B0838A1976357D9867EA452FF125B7
        FixMD5     : D952C91E9184CDC4C1D6693803E92876
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Status = "Open"
    $Setting = "Authentication"
    $ExpectedValue = "Not 'local'"
    $ValueRegex = "^\s*local\s*$"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/security-realm=ManagementRealm/authentication"
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
        if ($($Outputs.DetectedValue) -eq "Local") {
            $ErrorCount++
        }
    }
    else {
        foreach ($JBHost in $($JBossInstance.Hosts)) {
            $CLICommand = "ls /host=$JBHost/core-service=management/security-realm=ManagementRealm/authentication"
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $($Outputs.DetectedValue) -Hostname $JBHost
            if ($($Outputs.DetectedValue) -eq "Local") {
                $ErrorCount++
            }
        }
    }
    if ($ErrorCount -eq 0) {
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

Function Get-V213502 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213502
        STIG ID    : JBOS-AS-000075
        Rule ID    : SV-213502r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-AS-000024
        Rule Title : JBoss management interfaces must be secured.
        DiscussMD5 : 0CEE7164C13081560C2A0E732BAF8FA8
        CheckMD5   : 48544CDDF58D2EE9E44EF5128C33B8FB
        FixMD5     : 9600F9FC475E987D9458D3EA33299EF8
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $ErrorCount = 0
    $SettingRegex = 'security-realm\s*='
    $ValueRegex = 'security-realm\s*=\s*ManagementRealm\b'
    $ExpectedValue = "<defined>"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $Interfaces =  Get-JBossCliOutput -Command  "ls /core-service=management/management-interface="
        foreach ($interface in $Interfaces){
            $Setting = "Interface $($interface): security-realm"
            $CLICommand = "ls /core-service=management/management-interface=$($interface)"
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex

            $FindingDetails += $Outputs.Details
            if ($($Outputs.Count) -eq 0) {
                $ErrorCount++
            }
        }
    }
    else {
        $Interfaces =  Get-JBossCliOutput -Command  "ls /host=$($JBossInstance.Hosts)/core-service=management/management-interface="
        foreach ($interface in $Interfaces){
            $Setting = "Interface $($interface): security-realm"
            $CLICommand = "ls /host=$($JBossInstance.Hosts)/core-service=management/management-interface=$($interface)"
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex

            $FindingDetails += $Outputs.Details
            if ($($Outputs.Count) -eq 0) {
                $ErrorCount++
            }
        }
    }

    if ($ErrorCount -eq 0) {
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

Function Get-V213503 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213503
        STIG ID    : JBOS-AS-000080
        Rule ID    : SV-213503r1028283_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-AS-000050
        Rule Title : The JBoss server must generate log records for access and authentication events to the management interface.
        DiscussMD5 : 1570C60B5C7C060D795FB9F242F17850
        CheckMD5   : EB9F335D8E4E18983EECD12CF4D42041
        FixMD5     : 4DF285F9823295FFC9D8DB6A9F9E8BC1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213504 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213504
        STIG ID    : JBOS-AS-000085
        Rule ID    : SV-213504r960882_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-AS-000051
        Rule Title : JBoss must be configured to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which loggable events are to be logged.
        DiscussMD5 : 93CABA1C8C9AB631A51855CD323EAB8F
        CheckMD5   : BD9F1467EA52B2B6DCDBD5B86D102C38
        FixMD5     : 3DBC4031EBEF0AD0A1117BD12A9C10B9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "auditor"
    $ExpectedValue = "all auditors are approved"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/access=authorization/role-mapping=Auditor/include="
    }
    else {
        $CLICommand = "ls host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/core-service=management/access=authorization/role-mapping=Auditor/include="
    }
    $Results += Get-JBossCliOutput -Command $CLICommand
    $FindingDetails += "Configuration:`t`t$($JBossInstance.ServerMode)" | Out-String
    $FindingDetails += "Setting:`t`t`t$($Setting)" | Out-String
    $FindingDetails += "Expected Users:`t$($ExpectedValue)" | Out-String
    $FindingDetails += "Detected Users:"
    if ($null -eq $results -or $Results -eq "" -or $Results -eq "no output") {
        $FindingDetails += "`tNo group members" | Out-String
    }
    else {
        foreach ($result in $Results) {
            $FindingDetails += "`n`t`t`t`t$($result)" | Out-String
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

Function Get-V213505 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213505
        STIG ID    : JBOS-AS-000095
        Rule ID    : SV-213505r960888_rule
        CCI ID     : CCI-001464
        Rule Name  : SRG-APP-000092-AS-000053
        Rule Title : JBoss must be configured to initiate session logging upon startup.
        DiscussMD5 : 6936D6D178CE394CB0E7045E2615507E
        CheckMD5   : EB9F335D8E4E18983EECD12CF4D42041
        FixMD5     : 563C7BE7D433B00A8805C5AFC9D44AF3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213506 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213506
        STIG ID    : JBOS-AS-000105
        Rule ID    : SV-213506r960891_rule
        CCI ID     : CCI-000130
        Rule Name  : SRG-APP-000095-AS-000056
        Rule Title : JBoss must be configured to log the IP address of the remote system connecting to the JBoss system/cluster.
        DiscussMD5 : 101B6A48B422B1B0AF47A5DF7FDE8969
        CheckMD5   : 63CED2F69FC41B20AD13308DB640DEBD
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213507 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213507
        STIG ID    : JBOS-AS-000110
        Rule ID    : SV-213507r960891_rule
        CCI ID     : CCI-000130
        Rule Name  : SRG-APP-000095-AS-000056
        Rule Title : JBoss must be configured to produce log records containing information to establish what type of events occurred.
        DiscussMD5 : 796D227C49F1AA276E2C8276384FC731
        CheckMD5   : 63CED2F69FC41B20AD13308DB640DEBD
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213508 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213508
        STIG ID    : JBOS-AS-000115
        Rule ID    : SV-213508r960894_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-AS-000059
        Rule Title : JBoss Log Formatter must be configured to produce log records that establish the date and time the events occurred.
        DiscussMD5 : 69E9F2CD9CA09C24542C4214FD072409
        CheckMD5   : 63CED2F69FC41B20AD13308DB640DEBD
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213510 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213510
        STIG ID    : JBOS-AS-000125
        Rule ID    : SV-213510r960900_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098-AS-000061
        Rule Title : JBoss must be configured to record the IP address and port information used by management interface network traffic.
        DiscussMD5 : ECE615EAA239B25DD288DAE39012EDC9
        CheckMD5   : 63CED2F69FC41B20AD13308DB640DEBD
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213511 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213511
        STIG ID    : JBOS-AS-000130
        Rule ID    : SV-213511r960903_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-AS-000062
        Rule Title : The application server must produce log records that contain sufficient information to establish the outcome of events.
        DiscussMD5 : 81340391BCEBA2B296EED7C65339C657
        CheckMD5   : 63CED2F69FC41B20AD13308DB640DEBD
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213512 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213512
        STIG ID    : JBOS-AS-000135
        Rule ID    : SV-213512r960906_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-AS-000063
        Rule Title : JBoss ROOT logger must be configured to utilize the appropriate logging level.
        DiscussMD5 : 300D3CEDB0400D99FF655E6D3AF92EDF
        CheckMD5   : 872DFBE68FF6CA6808FC264E92AD537C
        FixMD5     : 6550B5F9C36004737418108E5CD8C54C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Status="Open"
    $Setting = "Log Level"
    $SettingRegex = 'level\s*='
    $ExpectedValue = "INFO, DEBUG, or TRACE"
    $ValueRegex = "(DEBUG|INFO|TRACE)"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=logging/root-logger=ROOT"
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
        if ($($Outputs.Count) -eq 0) {
            $ErrorCount++
        }
    }
    else {
        foreach ($Profile in $($JBossInstance.Profiles)){
            $CLICommand = "ls /profile=$Profile/subsystem=logging/root-logger=ROOT"
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $($Outputs.DetectedValue) -Profile $Profile
            if ($($Outputs.Count) -eq 0) {
                $ErrorCount++
            }
        }
    }

    if ($ErrorCount -eq 0) {
        $Status="NotAFinding"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213513 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213513
        STIG ID    : JBOS-AS-000165
        Rule ID    : SV-213513r960930_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-AS-000078
        Rule Title : File permissions must be configured to protect log information from any type of unauthorized read access.
        DiscussMD5 : 8F3F6C0620EF1A5270F49E0AA2526AED
        CheckMD5   : AA184958385B5D46681ADB67B4CAF4A9
        FixMD5     : 455A498BBE2A176C8492F48AF62B6DC3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Listing of $($JBossInstance.LogDir)" | out-string
        $DirListing += ls -la $JBossInstance.LogDir
        foreach ($listing in $DirListing) {
            $FindingDetails += $listing | Out-String
        }
    }
    else {
        $FindingDetails += Get-Acl -Path "$($JBossInstance.LogDir)"  | Format-Table -Wrap | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213514 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213514
        STIG ID    : JBOS-AS-000170
        Rule ID    : SV-213514r960933_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-APP-000119-AS-000079
        Rule Title : File permissions must be configured to protect log information from unauthorized modification.
        DiscussMD5 : CC5DF2A60B9BC62A1F5BDD9AE0297F17
        CheckMD5   : 90DD2B889DB6101A3C10C00B71345B7A
        FixMD5     : F0AD253A64C3FF9B8BB3F58DEAB83DFE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Listing of $($JBossInstance.LogDir)" | Out-String
        $DirListing += ls -la $JBossInstance.LogDir
        foreach ($listing in $DirListing) {
            $FindingDetails += $listing | Out-String
        }
    }
    else {
        $FindingDetails += Get-Acl -Path "$($JBossInstance.LogDir)" | Format-Table -Wrap | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213515 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213515
        STIG ID    : JBOS-AS-000175
        Rule ID    : SV-213515r960936_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-AS-000080
        Rule Title : File permissions must be configured to protect log information from unauthorized deletion.
        DiscussMD5 : 3F4A03D0BAA3E640A06C9A8E1CA6BE08
        CheckMD5   : ADE1DFC3836DFEC16C72A34B98AE459D
        FixMD5     : FF2A22623170AA8DB1621B05E07665A2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $FindingDetails += "Listing of $($JBossInstance.LogDir)" | Out-String
        $DirListing += ls -la $JBossInstance.LogDir
        foreach ($listing in $DirListing) {
            $FindingDetails += $listing | Out-String
        }
    }
    else {
        $FindingDetails += Get-Acl -Path "$($JBossInstance.LogDir)" | Format-Table -Wrap | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213517 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213517
        STIG ID    : JBOS-AS-000210
        Rule ID    : SV-213517r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-AS-000092
        Rule Title : mgmt-users.properties file permissions must be set to allow access to authorized users only.
        DiscussMD5 : 67BA81288B1D6634C230692393ADC271
        CheckMD5   : 9AC0E66AC8724A6305CB154ED4FE833C
        FixMD5     : 4A04A3AE7CCC80237527EFD93C9623DC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Mgmtfile = "mgmt-users.properties"
    $Mgmtpath = Join-Path -Path $JBossInstance.ConfigDir -ChildPath $Mgmtfile
    if (Test-Path -Path $Mgmtpath -PathType Leaf) {
        if ($IsLinux) {
            $Status="Open"
            $Dir_Listing = ls -ld $Mgmtpath
            $FindingDetails += "Permissions:`t$Dir_Listing" | Out-String
            $Perms = ls -ld $Mgmtpath | awk '{print $1}'
            $hasWorldRead = ($Perms.substring(7, 1) -eq "r")
            $hasWorldWrite = ($Perms.substring(8, 1) -eq "w")
            if ($hasWorldRead -eq $false -and $hasWorldWrite -eq $false) {
                $Status="Not_Reviewed"
            }

        }
        else {
            $FindingDetails += Get-Acl -Path "$Mgmtpath" | Format-Table -Wrap | Out-String
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

Function Get-V213518 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213518
        STIG ID    : JBOS-AS-000220
        Rule ID    : SV-213518r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : JBoss process owner interactive access must be restricted.
        DiscussMD5 : C0BD5AE4059B12EAA41CF629C61D97D6
        CheckMD5   : 8C093D9208002B57B92601A5877927ED
        FixMD5     : 27B0A2A75A53C753315FB8BE829CE4A0
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        $JBossUserShell = grep -E "^$($JBossInstance.ProcessUser)" /etc/passwd | awk -F: '{print $7}'
        $FindingDetails += "Configuration:`t`t$($JBossInstance.ServerMode)" | Out-String
        $FindingDetails += "User:`t`t`t$($JBossInstance.ProcessUser)" | Out-String
        $FindingDetails += "Attribute:`t`t`tUser Shell" | Out-String
        $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`t$JBossUserShell" | Out-String
        if ($JBossUserShell -in $ExpectedValues) {
            $Status = "NotAFinding"
        }
        else {
            $Status = "Open"
        }
    }
    else {
        $ExpectedValue = "JBoss user account cannot logon interactively"
        $ErrorCount = 0
        $UserRight = "SeInteractiveLogonRight"
        $SecPolIni = Get-IniContent $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_SecPol.ini
        $ProcessUser = $($JBossInstance.ProcessUser)
        $FindingDetails += "Configuration:`t`t$($JBossInstance.ServerMode)" | Out-String
        $FindingDetails += "JBoss User:`t`t$($JBossInstance.ProcessUser)" | Out-String
        $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String

        If ($SecPolIni.'Privilege Rights'.$UserRight) {
            $AssignedRights = ($SecPolIni.'Privilege Rights'.$UserRight).Replace("*", "") -split ","
            ForEach ($Object in $AssignedRights) {
                If ($Object -match "S-1-") {
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($Object)
                    Try {
                        $ResolvedItem = $objSID.Translate([System.Security.Principal.NTAccount]).Value
                        If ("$ResolvedItem" -eq "$ProcessUser") {
                            $ErrorCount++
                            break
                        }
                    }
                    Catch {
                        Continue
                    }
                }
            }
        }

        If ($ErrorCount -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "Detected Value:`tInteractive logon not allowed for $($JBossInstance.ProcessUser)" | Out-String
        }
        Else{
            $Status = "Open"
            $FindingDetails += "Detected Value:`tInteractive logon is allowed for $($JBossInstance.ProcessUser)" | Out-String
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

Function Get-V213520 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213520
        STIG ID    : JBOS-AS-000230
        Rule ID    : SV-213520r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : JBoss process owner execution permissions must be limited.
        DiscussMD5 : 9D3E7CD1337749CB81124C54A0E79B40
        CheckMD5   : 24D793E5C922C02562636EBFF1DDC099
        FixMD5     : DB024C2E259D4F2262C08E0D6EC88D3C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValue = "JBoss process user does not have admin permissions on the system."

    if ($isLinux) {
        $AdminPerms = sudo -l -U ($JBossInstance.ProcessUser) | grep -i "may run the following commands"
        if($null -eq $AdminPerms -or $AdminPerms -eq ""){
            $AdminPerms = "false"
        }
        else{
            $AdminPerms = "true"
            $ErrorCount++
        }
    }
    else {
        $AdminAccounts = @("NT AUTHORITY\\", "BUILTIN\\Administrator")
        $AdminRegex = ($AdminAccounts | ForEach-Object { "(" + ($_) + ")" }) -join "|"
        if ($JBossInstance.ProcessUser -match $AdminRegex) {
            $ErrorCount++
        }
    }

    $FindingDetails += "Configuration:`t`t$($JBossInstance.ServerMode)" | Out-String
    $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
    $FindingDetails += "Process User:`t`t$($JBossInstance.ProcessUser)" | Out-String
    if ($isLinux) {
        $FindingDetails += "Admin Permissions:`t$AdminPerms" | Out-String
    }

    If ($ErrorCount -eq 0) {
        if ($isLinux) {
            $Status = "NotAFinding"
        }
    }
    Else{
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

Function Get-V213521 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213521
        STIG ID    : JBOS-AS-000235
        Rule ID    : SV-213521r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : JBoss QuickStarts must be removed.
        DiscussMD5 : 60EE12AA2107AAB5FB0618ADD7239238
        CheckMD5   : 8350E589657556486664C2AECC899816
        FixMD5     : 1202E59CE086A671A55ED542BACE9E57
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Setting = "Quickstarts"
    $ExpectedValue = "Quickstarts folder should not exist"
    $Pattern = "jboss-eap-[0-9]\.[0-9]\.[0-9]-GA-quickstart"
    $Folder = "jboss-eap-#.#.#-GA-quickstarts"
    $Directories = (Get-ChildItem -Path $($JBossInstance.HomeDir) -Directory -Recurse -Force).FullName | Select-String -Pattern $Pattern
    if ($Directories.count -ge 1){
        $Status = "Open"
        $DetectedValue = $Directories
    }
    else{
        $Status = "NotAFinding"
        $DetectedValue = "Quickstarts folder does not exist"
    }

    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213522 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213522
        STIG ID    : JBOS-AS-000240
        Rule ID    : SV-213522r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Remote access to JMX subsystem must be disabled.
        DiscussMD5 : 875DE967718B7561BC8D508C5999B6F2
        CheckMD5   : FA5F4319766660FD558D410D97BD8DC5
        FixMD5     : ABC6907CD18C2C7ACCDD6D5D11B9FA15
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Status = "Open"
    $Setting = "remoting-connector"
    $ExpectedValue = "Not 'jmx'"
    $ValueRegex = "^\s*jmx\s*$"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=jmx/remoting-connector"
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex
        if ($($Outputs.DetectedValue) -eq "Not Found") {
            $($Outputs.DetectedValue = "No Output")
        }
        $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $($Outputs.DetectedValue)
        if ($($Outputs.Count) -gt 0) {
            $ErrorCount++
        }
    }
    else {
        foreach ($Profile in $($JBossInstance.Profiles)) {
            $CLICommand = "ls /profile=$Profile/subsystem=jmx/remoting-connector"
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex
            if ($($Outputs.DetectedValue) -eq "Not Found") {
                $($Outputs.DetectedValue = "No Output")
            }
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $($Outputs.DetectedValue) -Profile $Profile
            if ($($Outputs.Count) -gt 0) {
                $ErrorCount++
            }
        }
    }

    if ($ErrorCount -eq 0) {
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

Function Get-V213523 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213523
        STIG ID    : JBOS-AS-000245
        Rule ID    : SV-213523r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Welcome Web Application must be disabled.
        DiscussMD5 : 92548915962F47A0E8D079017A17CD98
        CheckMD5   : 0BCBC5FDC18CF0D24AD42A9F0146BDBC
        FixMD5     : 4125CDCB1FCC9F7794AD24A8A69D88AC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Status="Open"
    $Setting = "JBoss Welcome Page"
    $ExpectedValue = "enable-welcome-root=false"
    $SettingRegex = 'enable-welcome-root\s*='
    $ValueRegex = 'enable-welcome-root\s*=\s*false'

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=web/virtual-server=default-host"
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
        if ($($Outputs.Count) -eq 0) {
            $ErrorCount++
        }
    }
    else {
        foreach ($Profile in $($JBossInstance.Profiles)){
            $CLICommand = "ls /profile=$Profile/subsystem=web/virtual-server=default-host"
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $($Outputs.DetectedValue) -Profile $Profile
            if ($($Outputs.Count) -eq 0) {
                $ErrorCount++
            }
        }
    }


    if ($ErrorCount -eq 0) {
        $Status="NotAFinding"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213524 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213524
        STIG ID    : JBOS-AS-000250
        Rule ID    : SV-213524r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-AS-000095
        Rule Title : Any unapproved applications must be removed.
        DiscussMD5 : 2F64BE5971FC378837CE49B929E1AC3B
        CheckMD5   : 8693D359B5BB2FFB794E9F55CF5CC239
        FixMD5     : AF7003EED0CA2649831A11FE77A58663
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $CLICommand = "ls /deployment"

    $Deployments = Get-JBossCliOutput -Command $CLICommand
	if ($Deployments -eq "no output"){
		$Status = "NotAFinding"
		$FindingDetails = "No deployments found"
	}
    elseif ($null -ne $Deployments -and $Deployments -ne "") {
        $FindingDetails += "The following deployments must be documented and approved:" | Out-String
        foreach ($Deployment in $Deployments) {
            $FindingDetails += "`t$Deployment" | Out-String
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

Function Get-V213525 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213525
        STIG ID    : JBOS-AS-000255
        Rule ID    : SV-213525r1043177_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-AS-000014
        Rule Title : JBoss application and management ports must be approved by the PPSM CAL.
        DiscussMD5 : 03B7C0240DEC1926C1A35C473438738F
        CheckMD5   : 34BBF01C5E89C7FFA812FD77CB52D9FD
        FixMD5     : 3936EAAE94EAD7F6BCD8781D12B9280B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Configuration:`t`t$($JBossInstance.ServerMode)" | Out-String
    if ($($JBossInstance.SocketBindingGroup -eq "Not Found")){
        $FindingDetails = "No Socket-Binding-Groups found" | Out-String
    }
    else{
        foreach ($SocketBindingGroup in $($JBossInstance.SocketBindingGroup)){
            $CLICommand = "/socket-binding-group=$SocketBindingGroup/socket-binding=*:read-resource"
            $Output = Get-JBossCliOutput -Command $CLICommand
            foreach ($line in $Output){

                if($line | Select-String -Pattern '"socket-binding-group"'){
                    $FindingDetails += ($line -Replace '[()">,]', '').ToString().Trim()  | Out-String
                }
                elseif($line | Select-String -Pattern '"Socket-Binding"'){
                    $FindingDetails += ($line -Replace '[()">,]', '').ToString().Trim()  | Out-String
                }
                elseif($line | Select-String -Pattern '"port"'){
                    $FindingDetails += ($line -Replace '[()">,]', '').ToString().Trim()  | Out-String
                    $FindingDetails += "" | Out-String
                }
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

Function Get-V213526 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213526
        STIG ID    : JBOS-AS-000260
        Rule ID    : SV-213526r1051118_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-APP-000148-AS-000101
        Rule Title : The JBoss Server must be configured to utilize a centralized authentication mechanism such as AD or LDAP.
        DiscussMD5 : 48ABF7BBA76E16449480FADBF4FCBD35
        CheckMD5   : 337B14821C9BE5EA831BFACCA7D91E6E
        FixMD5     : 7DD520B3ADE4274D5F0D8BA4F50C4B11
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $LDAPCount = 0
    $Status = "Open"
    $Setting = "authentication"
    $ExpectedValue = "At least one LDAP security realm must exist"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/security-realm="
    }
    else {
        $CLICommand = "ls host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/core-service=management/security-realm="
    }
    $SecurityRealms = Get-JBossCliOutput -Command $CLICommand
    if ($null -ne $SecurityRealms -and $SecurityRealms -ne "") {
        foreach ($SR in $SecurityRealms) {
            if ($($JBossInstance.ServerMode) -eq "standalone") {
                $CLICommand = "ls /core-service=management/security-realm=$SR/authentication"
            }
            else {
                $CLICommand = "ls host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/core-service=management/security-realm=$SR/authentication"
            }
            $AuthenticationMethods = Get-JBossCliOutput -Command $CLICommand
            if ($null -ne $AuthenticationMethods -and $AuthenticationMethods -ne "") {
                $DetectedValue = ($AuthenticationMethods -split " ")[0]
                $FindingDetails += "Realm:`t`t`t$SR" | Out-String
                $FindingDetails += "Setting:`t`t`t$Setting" | Out-String
                $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
                $FindingDetails += "Detected Value:`t$DetectedValue" | Out-String
                $FindingDetails += "" | Out-String
                if ($AuthenticationMethods | Select-String -Pattern "LDAP") {
                    $LDAPCount++
                }
            }
        }
    }
    if ($LDAPCount -gt 0) {
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

Function Get-V213527 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213527
        STIG ID    : JBOS-AS-000265
        Rule ID    : SV-213527r960972_rule
        CCI ID     : CCI-000765
        Rule Name  : SRG-APP-000149-AS-000102
        Rule Title : The JBoss Server must be configured to use certificates to authenticate admins.
        DiscussMD5 : 7BEB0A014D61559AD876796077BF71A7
        CheckMD5   : 2B4ED72FABF5CA175898486FE0D1ADDE
        FixMD5     : 3FF58B6348D53141FF10E74547632BE6
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Setting = "authentication"
    $ExpectedValue = "ldap"


    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/management-interface="
    }
    else {
        $CLICommand = "ls host=$($JBossInstance.Hosts)/core-service=management/management-interface="
    }

    $ManagementInterfaces = Get-JBossCliOutput -Command $CLICommand

    if ($null -ne $ManagementInterfaces -and $ManagementInterfaces -ne "") {
        foreach ($interface in $ManagementInterfaces) {
            if ($($JBossInstance.ServerMode) -eq "standalone") {
                $CLICommand = "ls /core-service=management/management-interface=$interface"
            }
            else {
                $CLICommand = "ls host=$($JBossInstance.Hosts)/core-service=management/management-interface=$interface"
            }

            $SecurityRealms = Get-JBossCliOutput -Command $CLICommand

            if ($null -ne $SecurityRealms -and $SecurityRealms -ne "") {
                foreach ($line in $SecurityRealms) {
                 if ($line | Select-String -Pattern "security-realm") {
                        $securityRealm = ($line -split "=")[1]
                        if ($($JBossInstance.ServerMode) -eq "standalone") {
                            $CLICommand = "ls /core-service=management/security-realm=$securityRealm/authentication"
                        }
                        else {
                            $CLICommand = "ls host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/core-service=management/security-realm=$securityRealm/authentication"
                        }

                        $AuthenticationMethods = Get-JBossCliOutput -Command $CLICommand

                        if ($null -ne $AuthenticationMethods -and $AuthenticationMethods -ne "") {
                            $DetectedValue = ($AuthenticationMethods -split " ")[0]
                            $FindingDetails += "Interface:`t`t`t$interface" | Out-String
                            $FindingDetails += "Realm:`t`t`t$securityRealm" | Out-String
                            $FindingDetails += "Setting:`t`t`t$Setting" | Out-String
                            $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
                            $FindingDetails += "Detected Value:`t$DetectedValue" | Out-String


                            $FindingDetails += "" | Out-String
                            $ldapAuth = $AuthenticationMethods | Select-String -Pattern "ldap"
                            if ($null -eq $ldapAuth -or $ldapAuth -eq "") {
                                $ErrorCount++
                            }
                        }
                    }
                }
            }
        }
    }

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

Function Get-V213528 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213528
        STIG ID    : JBOS-AS-000275
        Rule ID    : SV-213528r981680_rule
        CCI ID     : CCI-000770
        Rule Name  : SRG-APP-000153-AS-000104
        Rule Title : The JBoss server must be configured to use individual accounts and not generic or shared accounts.
        DiscussMD5 : 0B0BC6B7D800824F193511D9E4FA686A
        CheckMD5   : BEA7025586FD6EA55487D7D07FFFCEF4
        FixMD5     : C368223E364292C354CA0A09C8772512
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $LDAPCount = 0
    $Setting = "authentication"
    $ExpectedValue = "At least one LDAP security realm must exist"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/security-realm="
    }
    else {
        $CLICommand = "ls host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/core-service=management/security-realm="
    }
    $SecurityRealms = Get-JBossCliOutput -Command $CLICommand
    if ($null -ne $SecurityRealms -and $SecurityRealms -ne "") {
        foreach ($SR in $SecurityRealms) {
            if ($($JBossInstance.ServerMode) -eq "standalone") {
                $CLICommand = "ls /core-service=management/security-realm=$SR/authentication"
            }
            else {
                $CLICommand = "ls host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/core-service=management/security-realm=$SR/authentication"
            }
            $AuthenticationMethods = Get-JBossCliOutput -Command $CLICommand
            if ($null -ne $AuthenticationMethods -and $AuthenticationMethods -ne "") {
                if ($AuthenticationMethods | Select-String -Pattern "LDAP") {
                    $LDAPCount++
                }
            }
        }
    }
    if ($LDAPCount -gt 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "LDAP Authentication in use" | Out-String
    }
    else {
        if ($($JBossInstance.ServerMode) -eq "standalone") {
            $FileToCheck = $JBossInstance.ServerConfigPath
        }
        else {
            $FileToCheck = $JBossInstance.DomainConfigPath
        }
        $FindingDetails += "Filename: $FileToCheck" | Out-String
        if (Test-Path -path $FileToCheck) {
            foreach ($line in Get-Content $FileToCheck) {
                if ($line | Select-String -pattern "User name|Role name") {
                    $FindingDetails += "$line" | Out-String
                }
            }
        }
        else {
            $FindingDetails += "File $FileToCheck not found" | Out-String
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

Function Get-V213529 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213529
        STIG ID    : JBOS-AS-000290
        Rule ID    : SV-213529r981681_rule
        CCI ID     : CCI-000795
        Rule Name  : SRG-APP-000163-AS-000111
        Rule Title : JBoss management Interfaces must be integrated with a centralized authentication mechanism that is configured to manage accounts according to DoD policy.
        DiscussMD5 : 7DFD0AAB37CEACBBB0CFBB2DC8803CB3
        CheckMD5   : C17F3627E81E91C4F5DE598C13B65469
        FixMD5     : 7DD520B3ADE4274D5F0D8BA4F50C4B11
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Status = "Open"
    $Setting = "authentication"
    $ExpectedValue = "LDAP"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/management-interface="
    }
    else {
        $CLICommand = "ls host=$($JBossInstance.Hosts)/core-service=management/management-interface="
    }
    $ManagementInterfaces = Get-JBossCliOutput -Command $CLICommand
    if ($null -ne $ManagementInterfaces -and $ManagementInterfaces -ne "") {
        foreach ($MI in $ManagementInterfaces) {
            if ($($JBossInstance.ServerMode) -eq "standalone") {
                $CLICommand = "ls /core-service=management/management-interface=$MI"
            }
            else {
                $CLICommand = "ls host=$($JBossInstance.Hosts)/core-service=management/management-interface=$MI"
            }
            $SecurityRealms = Get-JBossCliOutput -Command $CLICommand
            if ($null -ne $SecurityRealms -and $SecurityRealms -ne "") {
                foreach ($line in $SecurityRealms) {
                    if ($line | Select-String -Pattern "security-realm") {
                        $SR = ($line -split "=")[1]
                        if ($($JBossInstance.ServerMode) -eq "standalone") {
                            $CLICommand = "ls /core-service=management/security-realm=$SR/authentication"
                        }
                        else {
                            $CLICommand = "ls host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/core-service=management/security-realm=$SR/authentication"
                        }
                        $AuthenticationMethods = Get-JBossCliOutput -Command $CLICommand
                        if ($null -ne $AuthenticationMethods -and $AuthenticationMethods -ne "") {
                            $DetectedValue = ($AuthenticationMethods -split " ")[0]
                            $FindingDetails += "Interface:`t`t`t$MI" | Out-String
                            $FindingDetails += "Realm:`t`t`t$SR" | Out-String
                            $FindingDetails += "Setting:`t`t`t$Setting" | Out-String
                            $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
                            $FindingDetails += "Detected Value:`t$DetectedValue" | Out-String
                            $FindingDetails += "" | Out-String
                            if ($AuthenticationMethods | Select-String -Pattern "LDAP" -NotMatch) {
                                $ErrorCount++
                            }
                        }
                    }
                }
            }
        }
    }
    if ($ErrorCount -eq 0) {
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

Function Get-V213530 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213530
        STIG ID    : JBOS-AS-000295
        Rule ID    : SV-213530r981682_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-APP-000171-AS-000119
        Rule Title : The JBoss Password Vault must be used for storing passwords or other sensitive configuration information.
        DiscussMD5 : 261E3BD27AB0FD0B0BBA7C045E25F70B
        CheckMD5   : E180935CD68D341F6C11EDFDD214064B
        FixMD5     : 8F2F2B8DC393C361AE021132897CE17D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Outcome2 = "False"
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=vault"
    }
    else {
        $CLICommand = "ls /host=master/core-service=vault"
    }
    $DetectedValue = Get-JBossCliOutput -Command $CLICommand
    if($null -eq $DetectedValue -or $DetectedValue -eq "no output" -or $DetectedValue  -match "CLI Error"){
        $ErrorCount++
        $Outcome1 += "False"
    }
    else{
        $Outcome1 = "True"
        $VaultOptions =  $DetectedValue | Select-String -Pattern "vault-options" | Out-String
        $VaultOptions =  $VaultOptions.Split(",") -SPlit('vault-options=')
        foreach ($line in $VaultOptions){
            $match = $line | Select-String -Pattern '=>\s\"[a-zA-Z]'
            if($null -ne $match -and $match -ne ""){
                $Outcome2 = "True"
                break
            }
        }

        if($Outcome2 -eq "False"){
            $ErrorCount++
        }
    }

    $Setting = "<vault>"
    $FindingDetails += "Setting:`n`t$Setting" | Out-String
    $FindingDetails += "$Setting exists:`n`t$Outcome1" | Out-String
    $FindingDetails += "" | Out-String
    $Setting2 = "<vault-options>"
    $FindingDetails += "Setting:`n`t$Setting2" | Out-String
    $FindingDetails += "$Setting2 configured:`n`t$Outcome2" | Out-String

    if($ErrorCount -eq 0){
        $Status = "NotAFinding"
    }
    else{
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

Function Get-V213532 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213532
        STIG ID    : JBOS-AS-000305
        Rule ID    : SV-213532r961029_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-APP-000172-AS-000120
        Rule Title : LDAP enabled security realm value allow-empty-passwords must be set to false.
        DiscussMD5 : 1CF2CEF9C4C87867D163464FF487C599
        CheckMD5   : DAFAC0B307281CAFEF47E658D93CED7F
        FixMD5     : FB9BCD80D91E1CFBC02F5AC8ADD42F65
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/security-realm=ldap_security_realm/authentication=ldap"
        $Setting = "allow-empty-passwords"
        $SettingRegex = 'allow-empty-passwords\s*='
        $ValueRegex = 'allow-empty-passwords\s*=\s*false'
    }
    else {
        $CLICommand = "ls /host=$($JBossInstance.Hosts)/core-service=management/security-realm=ldap_security_realm/authentication=ldap"
        $Setting = "allow-empty-passwords"
        $SettingRegex = 'allow-empty-passwords\s*='
        $ValueRegex = 'allow-empty-passwords\s*=\s*false'
    }

    $ExpectedValue = "allow-empty-passwords=false"
    $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex

    if ($($Outputs.Count) -gt 0 -or $($Outputs.DetectedValue) -eq "No Output") {
        $Status = "NotAFinding"
    }
    $FindingDetails += $Outputs.Details
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213533 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213533
        STIG ID    : JBOS-AS-000310
        Rule ID    : SV-213533r961029_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-APP-000172-AS-000121
        Rule Title : JBoss must utilize encryption when using LDAP for authentication.
        DiscussMD5 : 9877347395B137561035B0E3D1F2D946
        CheckMD5   : 03C99197A2E63939A8D691BD052418D7
        FixMD5     : 7DD520B3ADE4274D5F0D8BA4F50C4B11
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Status="Open"
    $Setting = "port"
    $SettingRegex = '^port\s*='
    $ValueRegex = '^port\s*=\s*636'
    $ExpectedValue = "port=636"

    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /socket-binding-group=standard-sockets/remote-destination-outbound-socket-binding=ldap_connection"
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
        if ($($Outputs.Count) -eq 0) {
            $ErrorCount++
        }
    }
    else {
        foreach ($SocketBindingGroup in $($JBossInstance.SocketBindingGroup)){
        $CLICommand = "ls /socket-binding-group=$SocketBindingGroup/remote-destination-outbound-socket-binding=ldap_connection"
            $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $($Outputs.DetectedValue) -Profile $SocketBindingGroup
            if ($($Outputs.Count) -eq 0) {
                $ErrorCount++
            }
        }
    }

    if ($ErrorCount -eq 0) {
        $Status="NotAFinding"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213534 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213534
        STIG ID    : JBOS-AS-000320
        Rule ID    : SV-213534r961041_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-AS-000125
        Rule Title : The JBoss server must be configured to restrict access to the web servers private key to authenticated system administrators.
        DiscussMD5 : 1497639DD9718C237DBA063C8CD123AF
        CheckMD5   : 0834FA395D681265C358F776A03EDB67
        FixMD5     : 70A82671FEDDD4CF9D8FD77971BF2D19
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Path = Join-Path -Path $JBossInstance.HomeDir -ChildPath "vault"

    if (Test-Path $Path) {
        if ($IsLinux) {
            $Status="Open"
            $Dir_Listing = ls -ld $($Path)
            $FindingDetails += "Permissions:`n`t$Dir_Listing" | Out-String
            $Perms = $Dir_Listing | awk '{print $1}'
            $hasWorldRead = ($Perms.substring(7, 1) -eq "r")
            $hasWorldWrite = ($Perms.substring(8, 1) -eq "w")
            if ($hasWorldRead -eq $false -and $hasWorldWrite -eq $false) {
                $Status="NotAFinding"
            }
        }
        else {
                $FindingDetails += Get-Acl -Path "$($Path)" | Format-Table -Wrap | Out-String
        }
    }
    else {
        $FindingDetails += "$($Path) does not exist." | Out-String
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

Function Get-V213535 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213535
        STIG ID    : JBOS-AS-000355
        Rule ID    : SV-213535r961095_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-AS-000146
        Rule Title : The JBoss server must separate hosted application functionality from application server management functionality.
        DiscussMD5 : 323470A8FBDC177B0CEC7A96318F603F
        CheckMD5   : 9F8AA56799357E478365D1BA6E0814E2
        FixMD5     : 55AC85746989A6345F0D75D92CB8F99F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if ($($JBossInstance.BindAddr) -ne $($JBossInstance.ManAddr) -and $($JBossInstance.ManAddr) -ne "Not Found" -and $($JBossInstance.BindAddr) -ne "Not Found") {
        $Status = "NotAFinding"
    }
    if ($($JBossInstance.BindAddr) -eq $($JBossInstance.ManAddr) -and $($JBossInstance.ManAddr) -ne "Not Found") {
        $Status = "Open"
    }
    $FindingDetails += "Management Address:`t$($JBossInstance.ManAddr)" | Out-String
    $FindingDetails += "Public Address:`t`t$($JBossInstance.BindAddr)" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213536 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213536
        STIG ID    : JBOS-AS-000400
        Rule ID    : SV-213536r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-AS-000133
        Rule Title : JBoss file permissions must be configured to protect the confidentiality and integrity of application files.
        DiscussMD5 : B05FC916E6874121B2761A64FEE402AE
        CheckMD5   : E45C1F7B20583C8A60D7199503E21612
        FixMD5     : 96C537F181B2C9F50CB3500CD799DB03
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Test-Path -Path $($JBossInstance.HomeDir)) {
        if ($IsLinux) {
            $Status="Open"
            $Dir_Listing = ls -ld $($JBossInstance.HomeDir)
            $FindingDetails += "Permissions:`t$Dir_Listing" | Out-String
            $Perms = $Dir_Listing | awk '{print $1}'
            $hasWorldRead = ($Perms.substring(7, 1) -eq "r")
            $hasWorldWrite = ($Perms.substring(8, 1) -eq "w")
            if ($hasWorldRead -eq $false -and $hasWorldWrite -eq $false) {
                $Status="NotAFinding"
            }

        }
        else {
            $FindingDetails += Get-Acl -Path "$($JBossInstance.HomeDir)" | Format-Table -Wrap | Out-String
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

Function Get-V213537 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213537
        STIG ID    : JBOS-AS-000425
        Rule ID    : SV-213537r961170_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-AS-000170
        Rule Title : Access to JBoss log files must be restricted to authorized users.
        DiscussMD5 : 59856D6D416CA844468088746A4AB478
        CheckMD5   : 7612FA135415C91CDB8DF8E05DA64230
        FixMD5     : 477E6EC2362805A193D10B612D547026
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if (Test-Path -Path $($JBossInstance.HomeDir)) {
        if ($IsLinux) {
            $Status = "Open"
            $Dir_Listing = ls -ld $($JBossInstance.LogDir)
            $FindingDetails += "Permissions:`t$Dir_Listing" | Out-String
            $Perms = $Dir_Listing | awk '{print $1}'
            $hasWorldRead = ($Perms.substring(7, 1) -eq "r")
            $hasWorldWrite = ($Perms.substring(8, 1) -eq "w")
            if ($hasWorldRead -eq $false -and $hasWorldWrite -eq $false) {
                $Status = "NotAFinding"
            }

        }
        else {
            $FindingDetails += Get-Acl -Path "$($JBossInstance.LogDir)" | Format-Table -Wrap | Out-String
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

Function Get-V213538 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213538
        STIG ID    : JBOS-AS-000470
        Rule ID    : SV-213538r961281_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-AS-000199
        Rule Title : Network access to HTTP management must be disabled on domain-enabled application servers not designated as the domain controller.
        DiscussMD5 : 13E3F1B393585FDC2FE85C7A2E1A030A
        CheckMD5   : 2A5AF9AA570164C8458A229EA99279C2
        FixMD5     : 6B5AD62B3C672D79FDE70802DCB1B10B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "console-enabled"
    $SettingRegex = 'console-enabled\s*='
    $ValueRegex = 'console-enabled\s*=\s*true'
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/management-interface=http-interface"
    }
    else {
        $CLICommand = "ls /host=$($JBossInstance.Hosts)/core-service=management/management-interface=http-interface"
    }
    $ExpectedValue = "not console-enabled=true"
    $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
    if ($($Outputs.Count) -eq 0) {
        $Status = "NotAFinding"
    }
    $FindingDetails += $Outputs.Details
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213539 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213539
        STIG ID    : JBOS-AS-000475
        Rule ID    : SV-213539r961353_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-APP-000340-AS-000185
        Rule Title : The application server must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
        DiscussMD5 : 4C781B6B4A8F1EC2CBE9DAFFAC3CF63E
        CheckMD5   : 874F9E546E50C19BCCCA3D91DF14B4C0
        FixMD5     : 0814EEBBE72FCBB359F641E218080E77
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status="Open"
    $Setting = "Access-Control"
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /core-service=management/access=authorization/"
    }
    else {
        $CLICommand = "ls /core-service=management/access=authorization/"
    }
    $ExpectedValue = "provider=rbac"
    $SettingRegex = 'provider\s*='
    $ValueRegex = 'provider\s*=\s*rbac'
    $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
    if ($($Outputs.Count) -gt 0) {
        $Status="NotAFinding"
    }
    $FindingDetails += $Outputs.Details
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213540 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213540
        STIG ID    : JBOS-AS-000480
        Rule ID    : SV-213540r961362_rule
        CCI ID     : CCI-002234
        Rule Name  : SRG-APP-000343-AS-000030
        Rule Title : The JBoss server must be configured to log all admin activity.
        DiscussMD5 : 41B8D14DAD0EB5E37E065EA5614C186A
        CheckMD5   : 0A72A5D98CD9906980320B46C31F016A
        FixMD5     : F9811519556441E51674F90212E42FC1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213541 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213541
        STIG ID    : JBOS-AS-000505
        Rule ID    : SV-213541r961395_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000358-AS-000064
        Rule Title : The JBoss server must be configured to utilize syslog logging.
        DiscussMD5 : 082EC8C8F43C991120C5F8A81790DAA3
        CheckMD5   : 5C021AA2A5B9636F10D0FA76ACFC20E2
        FixMD5     : A22EB025783EB7E47A832ADE5B4F18C2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "syslog-handler"
    $ExpectedValue = "a syslog handler name"
    $FindingCount = 0
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=logging/syslog-handler="
        $Outputs = Get-JBossCliOutput -Command $CLICommand
        foreach ($output in $Outputs) {
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $Output
        }
        if ($($Outputs -eq "no output")) {
            $FindingCount++
        }
    }
    else {
        foreach ($profile in $($JBossInstance.Profiles)) {
            $CLICommand = "ls /profile=$profile/subsystem=logging/syslog-handler="
            $Outputs = Get-JBossCliOutput -Command $CLICommand
            foreach ($output in $Outputs) {
                $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $Output -Profile $profile
            }
            if ($($Outputs -eq "no output")) {
                $FindingCount++
            }
        }
    }

    if ($FindingCount -eq 0) {
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

Function Get-V213542 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213542
        STIG ID    : JBOS-AS-000545
        Rule ID    : SV-213542r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-AS-000088
        Rule Title : Production JBoss servers must not allow automatic application deployment.
        DiscussMD5 : 847522640D4F9077D47DF90CF3713DC7
        CheckMD5   : ED36CF0536A02A045EA7898BB52149DF
        FixMD5     : AB2D77D8A6FDF04F9BF60A2DFC5C3C74
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "scan-enabled"
    $SettingRegex = 'scan-enabled\s*='
    $ValueRegex = 'scan-enabled\s*=\s*true'
    $ExpectedValue = "scan-enabled not set to true"
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=deployment-scanner/scanner=default"
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
        $FindingCount = $outputs.count
    }
    else {
        $FindingCount = 0
        foreach ($profile in $($JBossInstance.Profiles)) {
            $CLICommand = "ls /profile=$profile/subsystem=deployment-scanner/scanner=default"
            $DetectedValue = Get-JBossCliOutput -Command $CLICommand
            if ($DetectedValue | Select-String '^CLI Error') {
                $DetectedValue = "No Output"
            }
            $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue -Profile $profile
            if ($DetectedValue | Select-String -Pattern "true") {
                $FindingCount++
            }
        }
    }
    if ($FindingCount -eq 0) {
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

Function Get-V213543 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213543
        STIG ID    : JBOS-AS-000550
        Rule ID    : SV-213543r981687_rule
        CCI ID     : CCI-001814
        Rule Name  : SRG-APP-000381-AS-000089
        Rule Title : Production JBoss servers must log when failed application deployments occur.
        DiscussMD5 : AE9F4A4BE64CC0D1CC4235CD308C4383
        CheckMD5   : FD80CDB3ACFE12B0AC9C422083DD522F
        FixMD5     : F9811519556441E51674F90212E42FC1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213544 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213544
        STIG ID    : JBOS-AS-000555
        Rule ID    : SV-213544r981687_rule
        CCI ID     : CCI-001814
        Rule Name  : SRG-APP-000381-AS-000089
        Rule Title : Production JBoss servers must log when successful application deployments occur.
        DiscussMD5 : AE9F4A4BE64CC0D1CC4235CD308C4383
        CheckMD5   : BC9138ECC0E76A789FC654E8489488DB
        FixMD5     : F9811519556441E51674F90212E42FC1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213547 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213547
        STIG ID    : JBOS-AS-000650
        Rule ID    : SV-213547r961632_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-AS-000155
        Rule Title : JBoss must be configured to use an approved TLS version.
        DiscussMD5 : 38EC43E516B896B5AA6F4DED428222E0
        CheckMD5   : 37482E8D71F58BE12F9A8769E29D94B8
        FixMD5     : 7F53C0D38E64B274CD3538B8AD14FE74
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "protocol"
    $ValueRegex = 'TLSv1.[2-9]'
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=web/connector=https/ssl=configuration"
    }
    else {
        $CLICommand = "ls /host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/subsystem=web/connector=https/ssl=configuration"
    }

    $ExpectedValue = "TLS V1.2 or higher"
    $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex

    if ($($Outputs.Count) -gt 0) {
        $Status = "NotAFinding"
    }
    $FindingDetails += $Outputs.Details
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V213548 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213548
        STIG ID    : JBOS-AS-000655
        Rule ID    : SV-213548r961635_rule
        CCI ID     : CCI-002421
        Rule Name  : SRG-APP-000440-AS-000167
        Rule Title : JBoss must be configured to use an approved cryptographic algorithm in conjunction with TLS.
        DiscussMD5 : E9300304AE988FD33424D16E036E607F
        CheckMD5   : 72786716EC22E035391FF9170C6973F3
        FixMD5     : 4790547143029312A858BD1E036C1E76
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Not_Reviewed"
    $Setting = "cipher-suite"
    $ValueRegex = 'cipher-suite='
    $CLICommand = "ls /subsystem=web/connector=https/ssl=configuration"
    $ExpectedValue = "approved by NIST as per 800-52r1"
    $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex

    $FindingDetails += $Outputs.Details

    if ($Outputs.Count -eq 0) {
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

Function Get-V213551 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213551
        STIG ID    : JBOS-AS-000690
        Rule ID    : SV-213551r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-AS-000220
        Rule Title : JBoss must be configured to generate log records when successful/unsuccessful attempts to modify privileges occur.
        DiscussMD5 : FCAA21CFF432AA5DF02DF546BA1424EA
        CheckMD5   : 63CED2F69FC41B20AD13308DB640DEBD
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213552 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213552
        STIG ID    : JBOS-AS-000695
        Rule ID    : SV-213552r961812_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-AS-000224
        Rule Title : JBoss must be configured to generate log records when successful/unsuccessful attempts to delete privileges occur.
        DiscussMD5 : 9F1A1FCA17CDD6CE0F0C4A892DB6848A
        CheckMD5   : 63CED2F69FC41B20AD13308DB640DEBD
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213553 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213553
        STIG ID    : JBOS-AS-000700
        Rule ID    : SV-213553r961824_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-AS-000228
        Rule Title : JBoss must be configured to generate log records when successful/unsuccessful logon attempts occur.
        DiscussMD5 : E6562687CF46418DDEA49EDDE0115BF5
        CheckMD5   : 161E6546B072939F7191EFA5594404F6
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213554 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213554
        STIG ID    : JBOS-AS-000705
        Rule ID    : SV-213554r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-AS-000229
        Rule Title : JBoss must be configured to generate log records for privileged activities.
        DiscussMD5 : 18C1D417494FC185E4A491385301B9DC
        CheckMD5   : 161E6546B072939F7191EFA5594404F6
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213555
        STIG ID    : JBOS-AS-000710
        Rule ID    : SV-213555r961830_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000505-AS-000230
        Rule Title : JBoss must be configured to generate log records that show starting and ending times for access to the application server management interface.
        DiscussMD5 : 1A9A15219F968EE67F35C207FDBCC718
        CheckMD5   : 161E6546B072939F7191EFA5594404F6
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213556 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213556
        STIG ID    : JBOS-AS-000715
        Rule ID    : SV-213556r961833_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000506-AS-000231
        Rule Title : JBoss must be configured to generate log records when concurrent logons from different workstations occur to the application server management interface.
        DiscussMD5 : E20E743FD6DDD1E8AFC4D8342DE3F41D
        CheckMD5   : 161E6546B072939F7191EFA5594404F6
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213557
        STIG ID    : JBOS-AS-000720
        Rule ID    : SV-213557r961842_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000509-AS-000234
        Rule Title : JBoss must be configured to generate log records for all account creations, modifications, disabling, and termination events.
        DiscussMD5 : C76A5508AAB33CEF6B7BB9E14FD247A3
        CheckMD5   : 161E6546B072939F7191EFA5594404F6
        FixMD5     : 460989E60BDCE270571C0BB0F0CACB0C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Open"
    $Setting = "audit-log"
    $ExpectedValue = "enabled=true"
    $FindingDetails += Get-JBossFormattedOutput -Setting $Setting -ExpectedValue $ExpectedValue -DetectedValue $JBossInstance.AuditLogStatus

    if ($($JBossInstance.AuditLogStatus) -match "true") {
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

Function Get-V213559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213559
        STIG ID    : JBOS-AS-000735
        Rule ID    : SV-213559r961860_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000515-AS-000203
        Rule Title : JBoss servers must be configured to roll over and transfer logs on a minimum weekly basis.
        DiscussMD5 : 72FA37BB37F8280A27777AF0F3313B1D
        CheckMD5   : AE291A24519C03691C282AEA5FE0CC8E
        FixMD5     : 61D92FF7C6508CC5436C498C47A67028
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "periodic-rotating-file-handler"
    $ValueRegex = '\bFILE\b'
    $ExpectedValue = "FILE"
    $ErrorCount = 0
    if ($($JBossInstance.ServerMode) -eq "standalone") {
        $CLICommand = "ls /subsystem=logging/periodic-rotating-file-handler="
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -SettingRegex $SettingRegex -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
    }
    else {
        $CLICommand = "ls /host=$($JBossInstance.Hosts)/server=$($JBossInstance.Server)/subsystem=logging/periodic-rotating-file-handler="
        $Outputs = Get-JBossCLI -Command $CLICommand -Setting $Setting -ExpectedValue $ExpectedValue -ValueRegex $ValueRegex
        $FindingDetails += $Outputs.Details
    }

    if ($($Outputs.DetectedValue) -ne "$ExpectedValue") {
        $ErrorCount++
    }

    if ($ErrorCount -ge 1) {
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

Function Get-V217099 {
    <#
    .DESCRIPTION
        Vuln ID    : V-217099
        STIG ID    : JBOS-AS-000285
        Rule ID    : SV-217099r961863_rule
        CCI ID     : CCI-000366, CCI-000778
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The JBoss server must be configured to bind the management interfaces to only management networks.
        DiscussMD5 : CD1261093AFD06FDB54F88DDE6C67470
        CheckMD5   : DEC5EF53E9DA66DD966E4AE43529E1CD
        FixMD5     : 357FAF44C2D15CE4CF2AA6E3431C6133
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Server Address:  $($JBossInstance.BindAddr)" | Out-String
    $FindingDetails += "Management Address:  $($JBossInstance.ManAddr)" | Out-String
    $FindingDetails += "" | Out-String

    if (($JBossInstance.BindAddr -eq $JBossInstance.ManAddr) -and ($JBossInstance.ManAddr -notmatch "localhost|127.0.0.1")) {
        $Status = "Open"
    }
    else {
        $Status="NotAFinding"
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAcTLNDOMAdWZXx
# cFys7ZUvfSvzHwkfX2JI3hWEiqcxLqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDRvrJAMazm5eb7XLEbWkQynf/JtKmpu57HmhOJAsEb0jANBgkqhkiG9w0BAQEF
# AASCAQBX6WnnRyNwvdDES4NUVMWNu71xtbmDZBiIyVciRvTS87DKOZvAOoZzWiEF
# EtWEBQx2MGp7YdFRl32caTA7mKaexn4gbeht+YG0IxRjC/M5roG3s1fj7QKS3H5X
# HTPbDfqFKSPxaWQNzMyQEJf2K9tnEViZ1I1SYVYlAHv2RtmDIWyjTHk40x6IQW7a
# BEzKGlg86srjrJUWypa9BBqRHwLQyto7geF8oqToVNHnbtudTsD4dxoE36qXWhib
# fSCylQVoMr12ncGmawKkr7jKl7VA/kLFeys2Q65UWWNDM6V49507z6cbIhzk0K3U
# LivPt4A31wdTAEIBLvonvL82PA5joYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTU0MVowLwYJKoZIhvcNAQkEMSIEIJdVBRRQSu14KZXTi3fsi/F6MiKa
# kM8G/7wwon28vXxPMA0GCSqGSIb3DQEBAQUABIICALYnK0wILP1wP5isb6Qac/8n
# fZdBhurdiGZfGZfC1hwGSzFNYeFLb7+ZG/DXZCq/x4xfjYWI1mK0FdjMmVe54dnJ
# kzSIxrYy3Bcpi52WuMVetJanP3CoRZCcCoHnIXbucyGhSaB/LS609mOgk/M+6H5R
# djdedwl2m0tRggQ3ZMSUzj0PRpaR3rRbovcoouvbW4mXauoLs4HDrC4GLkUuAwQI
# h38xoEixCWS//y4T23X+1NdRDJcTbbfT0NCx2GHIV/MtUzMaLd3XC1VEGVxThuh+
# Jl03UFxadFC6GsbDXle4y9oESo1b+17q75lUEARHRUW2n03Xc6rFLkrIylnaasst
# 7MmpA93OEFShX3BG7Hcwqj9ihc5LCnclheegdzyHTjmG1WrX2qww+XFao5FSi3JY
# SSIkj48Ips+ZIsnUTpUXI2vxBivJuuFjhySEDC2L/K6FGVU3yxsAy8HMqpbE/mNj
# 2t//BOgybJ2eqhGEXangvWZmtVYwrAgv52sBWj2h9jcsr1WkaeG3cn2+9RIWG79k
# NTU7wkR5e0yu3DsDCRcBS1DhXSrIZSMyadMQ2iwpXEwD4fPlE78L6Bi3pdZxKI6s
# GrI667PVysnOT54iWeSx9kDb4kjbka85SbSNAXl5Dyo8QbtP41nv1M3ZSwbglrpj
# HAKXHSY1fKRuWtXvS9+M
# SIG # End signature block
