##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MongoDB Enterprise Advanced 3.x
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-MongoConfig {
    param (
        [Parameter(Mandatory = $true)]
        [int] $ProcessId
    )

    $ConfigFile = ""

    try {
        $ConfigFile = (((Get-ProcessString -ProcessId $ProcessId) -split " -f | --config ")[1] -split " -")[0]
    }
    catch {
        $ConfigFile = "Not Defined"
    }

    return $ConfigFile
}

Function Get-MongoDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$MongoShell
    )

    if ($null -ne $MongoShell -and ($MongoShell -notmatch "Unavailable")) {
        $MongoDatabase = (& $MongoShell --quiet -eval 'db')
    }

    if ($null -eq $MongoDatabase -or $MongoDatabase -eq "") {
        $MongoDatabase = "Unknown"
    }

    return $MongoDatabase
}

Function Get-MongoDBInstance {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessId,
        [Parameter(Mandatory = $True)]
        [int]$Index
    )

    $ProcessString = Get-ProcessString -ProcessId $ProcessId
    $ConfigFile = Get-MongoConfig -ProcessId $ProcessId
    $ProcessUser = Get-ProcessUser -ProcessId $ProcessId
    $BindIP = Get-ProcessIPBinding -ProcessId $ProcessId
    $BindPort = Get-ProcessPortBinding -ProcessId $ProcessId
    $MongoShell = Get-MongoShell -ProcessId $ProcessId
    $Database = Get-MongoDatabase -MongoShell $MongoShell

    $Instance = [PSCustomObject]@{
        Index         = $Index
        ProcessID     = $ProcessID
        ConfigFile    = $ConfigFile
        ProcessUser   = $ProcessUser
        BindIP        = $BindIP
        BindPort      = $BindPort
        Database      = $Database
        ProcessString = $ProcessString
        MongoShell    = $MongoShell
    }

    return $Instance
}

Function Get-MongoDBInstances {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param ()

    $mongoPids = Get-ProcessIds -ProcessName "mongod"

    $Index = 0
    [System.Collections.ArrayList]$Instances = @()
    foreach ($mongoPid in $mongoPids) {
        $Instance = Get-MongoDBInstance -ProcessId $mongoPid -Index $Index
        [void] $Instances.add($Instance)
        $Index++
    }

    return $Instances
}

Function Get-MongoSetting {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Object[]]$YAMLObject,
        [Parameter(Mandatory = $True)]
        [string]$Setting
    )

    $LineIndent = 0
    $SettingIndent = 0
    $SettingFound = $false
    $SelectionArray = @()

    Foreach ($line in $YAMLObject) {
        if ($line -match '(^\s+)') {
            $LineIndent = $Matches[1].Length
        }

        $settingLine = $line | Select-String -Pattern "\s*$Setting"

        if ($null -ne $settingLine) {
            if ($settingLine -match '(^\s+)') {
                $SettingIndent = $Matches[1].Length
            }
        }

        if ($SettingIndent -gt 0) {
            if ($LineIndent -le $SettingIndent) {
                if ($SettingFound) {
                    break
                }
                else {
                    $SelectionArray += $line
                }
                $SettingFound = $true
            }
            else {
                $SelectionArray += $line
            }
        }
    }

    return $SelectionArray
}

Function Get-MongoShell {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessId
    )

    if ($IsLinux) {
        $MongoShell = (which mongo)
    }
    else {
        try {
            $MongoShell = (Get-Command -Name "mongo" -ErrorAction SilentlyContinue).Source
            if ($null -eq $MongoShell -or $MongoShell -eq "") {
                $MongoDBPath = (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue).Path
                $MongoDBBinDir = $MongoDBPath | Split-Path -Parent
                $MongoShell = (Get-ChildItem -Recurse -Path $MongoDBBinDir -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "mongo.exe"} | Select-Object -First 1).FullName
            }
        }
        catch {
        }
    }

    if ($null -eq $MongoShell -or $MongoShell -eq "") {
        $MongoShell = "Unavailable"
    }

    return $MongoShell
}

Function Get-MongoShellOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $false)]
        [string]$Database
    )


    if ($($MongoInstance.MongoShell -ne "Unavailable")) {

        $ShellOutput = & $($MongoInstance.MongoShell) $Database --quiet --eval "printjson($Command)"

        if ($null -eq "$ShellOutput" -or "$ShellOutput" -eq "") {
            $ShellOutput = "no output"
        }
        else {
            if ($ShellOutput.Count -gt 1) {
                $arrayOutput = ""
                foreach ($line in $ShellOutput) {
                    $arrayOutput += "$line" | Out-String
                }
                $ShellOutput = $arrayOutput
            }
        }
        return $ShellOutput
    }
    return $null
}

Function Get-ProcessIPBinding {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessId
    )

    if ($IsLinux) {
        $netstatString = netstat -pant | grep $ProcessId
        $processIP = ((($netstatString -replace '\s+', ' ') -split " ")[3] -split ":")[0]
    }
    else {
        $processIP = (((netstat -ano | findstr $ProcessId | findstr "LISTENING" | Select-Object -First 1) -split ":")[0] -replace '.*\s', '')
    }

    return $processIP
}

Function Get-ProcessPortBinding {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessId
    )

    if ($IsLinux) {
        $netstatString = (& netstat -pant | grep $ProcessId)
        $processPort = (((($netstatString -replace '\s+', ' ') -split " ")[3]) -split ":")[1]
    }
    else {
        $processPort = ((((netstat -ano | findstr $ProcessId | findstr "LISTENING" | Select-Object -First 1) -split ":")[1]) -split " ")[0]
    }

    return $processPort
}

Function Get-YAMLObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$Section,
        [Parameter(Mandatory = $True)]
        [string]$FilePath
    )

    $CommentRegex = '^\s*#'
    $HeaderRegex = '^[a-zA-Z]'
    $SelectionArray = @()
    $FilePath = $FilePath -replace '"',''
    if (Test-Path -Path $FilePath) {
        $ArrayFromFile = Get-Content -Path $FilePath
        if ($ArrayFromFile.Count -gt 0) {
            $InSelection = $False
            foreach ($line in $ArrayFromFile) {
                if ($line -notmatch $CommentRegex) {
                    if ($InSelection) {
                        if ($line -notmatch $HeaderRegex) {
                            if ($line -ne "") {
                                $SelectionArray += $line
                            }
                        }
                        else {
                            return $SelectionArray
                        }
                    }
                    else {
                        if ($line -match $HeaderRegex) {
                            if ($line | Select-String -Pattern $Section) {
                                $InSelection = $True
                                $SelectionArray += $line
                            }
                        }

                    }
                }
            }
            if ($InSelection) {
                return $SelectionArray
            }
        }
        else {
            return "File is empty"
        }
    }
    else {
        return "File not found"
    }
}

Function Get-V221158 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221158
        STIG ID    : MD3X-00-000010
        Rule ID    : SV-221158r960768_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : MongoDB must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.
        DiscussMD5 : E5836CFE2FCFF65FAB0692690B6866D4
        CheckMD5   : 0CFF603F5579E8478AA52C33A2C8C987
        FixMD5     : 74318C94E28A36735E231F8BCE95762B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "authorization"
    $ExpectedValue = "enabled"
    $SecurityConfig = ""
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $Status = "Open"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$ExpectedValue") {
                $Status = "NotAFinding"
                $FindingDetails += "Detected:`n`tenabled" | Out-String
            }
            else {
                $Status = "Open"
                $FindingDetails += "Detected:`n`tdisabled" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221159 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221159
        STIG ID    : MD3X-00-000020
        Rule ID    : SV-221159r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-DB-000084
        Rule Title : MongoDB must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
        DiscussMD5 : 3552ACF611D41222F595AABF41FB2B65
        CheckMD5   : 7D0FD226A8962562D247E4DDF9371A71
        FixMD5     : 686633CBBF197A3271C1BDDF35C2ED96
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Command = "db.getRoles({rolesInfo:1, showPrivileges:true, showBuiltinRoles:true})"
    $FindingDetails += Get-MongoShellOutput -Command $Command
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221160 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221160
        STIG ID    : MD3X-00-000040
        Rule ID    : SV-221160r960879_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000140, CCI-000166, CCI-000171, CCI-000172, CCI-001462, CCI-001464, CCI-001487, CCI-001814, CCI-001844, CCI-001851, CCI-001858
        Rule Name  : SRG-APP-000089-DB-000064
        Rule Title : MongoDB must provide audit record generation for DoD-defined auditable events within all DBMS/database components.
        DiscussMD5 : 867525AE45519485EE5599254B283340
        CheckMD5   : F8981A67512EF45718D36FC282329246
        FixMD5     : 9DE2327A36F4F7877CCA4C626DE40BB3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Key = "auditLog"
    $SubKey = "filter"
    $ExpectedValue = "$SubKey or Value String Not Present"
    $DetectedValue = ""
    $Config = ""

    if (-not $IsLinux) {
        $ExpectedValue = "$($ExpectedValue) (Not supported in Windows)"
    }

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $Config = Get-YAMLObject -Section $Key -FilePath $($MongoInstance.ConfigFile)

        if ($Config.Count -eq 0) {
            $ErrorCount++
            $FindingDetails += "$($Key) key not found in file $($MongoInstance.ConfigFile)" | Out-String
        }
        else {
            $FindingDetails += "Key:`n`t$Key" + ":" + "$SubKey" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String

            try {
                $KeySection = ($Config | Select-String -Pattern "$SubKey\b")

                if ($null -ne $KeySection) {
                    $DetectedValue = ($KeySection -split ":", 2)[1]
                    if (($null -ne $DetectedValue) -and ($DetectedValue -ne "")) {
                        $DetectedValue = $DetectedValue.Trim()
                        $ErrorCount = -1
                    }
                    else {
                        $DetectedValue = "Value String Not Present"
                    }
                }
                else {
                    $DetectedValue = "$SubKey Not Present"
                }
            }
            catch {
            }

            $FindingDetails += "Detected:`n`t$($DetectedValue)" | Out-String
        }

        if ($ErrorCount -ge 0) {
            if ($ErrorCount -eq 0) {
                $Status = "NotAFinding"
            }
            else {
                $Status = "Open"
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221161 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221161
        STIG ID    : MD3X-00-000190
        Rule ID    : SV-221161r960930_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-APP-000118-DB-000059
        Rule Title : The audit information produced by MongoDB must be protected from unauthorized read access.
        DiscussMD5 : A21DB0428AEBD2DF6AFD9D27B36D95BD
        CheckMD5   : 26F8392ECD0BCCFBDBF8861557A0AFC0
        FixMD5     : 95DEAD40E2D2A94B720B60A747C70A10
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Key = "auditLog"
    $SubKey = "path"
    $OwnerCheck = "mongod"
    $GroupCheck = "mongod"
    $Config = ""

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $Config = Get-YAMLObject -Section $Key -FilePath $($MongoInstance.ConfigFile -replace '"')

        if ($Config.Count -eq 0) {
            $ErrorCount++
            $FindingDetails += "$($Key) key not found in file $($MongoInstance.ConfigFile)." | Out-String
        }
        else {
            try {
                $Path = (($Config | Select-String -Pattern "$SubKey\b") -split ":", 2)[1].Trim() | Out-NormalizedPath
                $Dir = Split-Path -Parent $Path

                if (Test-Path -Path $Dir) {
                    if ($IsLinux) {
                        $Listing = (& ls -ald $Dir)
                        $Listing = $Listing.Trim() -replace "\s+", " "
                        $Perms = (& stat -c '%a' $Dir)
                        $GroupPerm = $Perms[1]
                        $OtherPerm = $Perms[2]
                        $Owner = ($Listing -split " ")[2]
                        $Group = ($Listing -split " ")[3]
                        $FindingDetails += "Directory: $($Dir)`n" | Out-String
                        $FindingDetails += "`tOwner: $Owner" | Out-String
                        $FindingDetails += "`tGroup: $Group" | Out-String
                        $FindingDetails += "`tPerms: $Perms" | Out-String

                        if ($Owner -ne $OwnerCheck) {
                            $ErrorCount++
                        }

                        if ($Group -ne $GroupCheck) {
                            $ErrorCount++
                        }

                        if ($GroupPerm -gt "0") {
                            $ErrorCount++
                        }

                        if ($OtherPerm -gt "0") {
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
                        $Acl = Get-Acl $Dir | Format-Table -Wrap | Out-String
                        $FindingDetails += $Acl
                    }
                }
                else {
                    $FindingDetails += "Directory $($Dir) does not exist" | Out-String
                }
            }
            catch {
                $FindingDetails += "$($_.Exception.Message)" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "Mongo configuration file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221162 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221162
        STIG ID    : MD3X-00-000220
        Rule ID    : SV-221162r960939_rule
        CCI ID     : CCI-001493, CCI-001494, CCI-001495
        Rule Name  : SRG-APP-000121-DB-000202
        Rule Title : MongoDB must protect its audit features from unauthorized access.
        DiscussMD5 : 054C0C83B50D9D91ADF3AFE30300F6AE
        CheckMD5   : 3E0925DA0B6BE48E3A1789848136CBA9
        FixMD5     : AF5EB5B860C45CD01D4FE97216CF96EC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OwnerCheck = "mongod"
    $GroupCheck = "mongod"
    $Config = ""

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        try {
            $File = $MongoInstance.ConfigFile -replace '"'
            if (Test-Path -Path $File) {
                if ($IsLinux) {
                    $Listing = (& ls -ald $File)
                    $Listing = $Listing.Trim() -replace "\s+", " "
                    $Perms = (& stat -c '%a' $File)
                    $GroupPerm = $Perms[1]
                    $OtherPerm = $Perms[2]
                    $Owner = ($Listing -split " ")[2]
                    $Group = ($Listing -split " ")[3]
                    $FindingDetails += "File: $($File)`n" | Out-String
                    $FindingDetails += "`tOwner: $Owner" | Out-String
                    $FindingDetails += "`tGroup: $Group" | Out-String
                    $FindingDetails += "`tPerms: $Perms" | Out-String

                    if ($Owner -ne $OwnerCheck) {
                        $ErrorCount++
                    }

                    if ($Group -ne $GroupCheck) {
                        $ErrorCount++
                    }

                    if ($GroupPerm -gt "0") {
                        $ErrorCount++
                    }

                    if ($OtherPerm -gt "0") {
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
                    $Acl = Get-Acl $File | Format-Table -Wrap | Out-String
                    $FindingDetails += $Acl
                }
            }
            else {
                $FindingDetails += "File $($File) does not exist" | Out-String
            }
        }
        catch {
            $FindingDetails += "$($_.Exception.Message)" | Out-String
        }
    }
    else {
        $FindingDetails += "Mongo configuration file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221165 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221165
        STIG ID    : MD3X-00-000270
        Rule ID    : SV-221165r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000362
        Rule Title : The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to MongoDB, etc.) must be restricted to authorized users.
        DiscussMD5 : 74D92BA5EACEE4C80BAA5B8602EA8736
        CheckMD5   : 36F91FF0C01E99C4A588211AD502E4A3
        FixMD5     : 40FAB87481522917FDE9CD1BF462D67D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Database = "admin"
    $Continued = $false
    $FindingDetails += "Roles assigned to users:" | Out-String
    $UserLines = (& $MongoInstance.MongoShell $database --quiet --eval "db.system.users.find()")
    foreach ($Userline in $UserLines) {
        $UserArray = $Userline -split ', '
        foreach ($user in $UserArray) {
            if ($Continued) {
                $FindingDetails += "`t`t$user" | Out-String
                if ($user | Select-String '\} \]') {
                    $Continued = $false
                    $FindingDetails += "" | Out-String
                }
                continue
            }
            if ($user | Select-String '"_id"') {
                $Username = $user -replace '{'
                $FindingDetails += "`t$username" | Out-String
            }
            if ($user | Select-String '"roles"') {
                $UserRole = $user -replace '}'
                $FindingDetails += "`t$UserRole" | Out-String
                if ($user | Select-String '\[ \{') {
                    $Continued = $true
                }
                else {
                    $FindingDetails += "" | Out-String
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

Function Get-V221166 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221166
        STIG ID    : MD3X-00-000280
        Rule ID    : SV-221166r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : Unused database components, DBMS software, and database objects must be removed.
        DiscussMD5 : 89B408D0D101A1E7D5689ED4C7354403
        CheckMD5   : 612EAC94A7022D809312865BD650AB64
        FixMD5     : 2E8A1497E8393175EA90ADE168C2AF89
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Version = (& "$($MongoInstance.MongoShell)" --version)[0] | Out-String
    if ($IsLinux) {
        $RpmVersion = $(rpm -qa | grep MongoDB)
        $HeaderName = "RPMs"
    }
    else {
        $RpmVersion += Get-ItemProperty "HKLM:\Software\MongoDB\Server\*" -EA SilentlyContinue | Select-Object -ExpandProperty "Edition" -EA SilentlyContinue
        $HeaderName = "Registry list of Installed Versions"
    }
    if ($null -ne $Version -and $Version -ne "") {
        $FindingDetails += "Version:`n$($Version)" | Out-String
        $FindingDetails += "" | Out-String

    }
    if ($null -ne $RpmVersion -and $RpmVersion -ne "") {
        $FindingDetails += "$($HeaderName):" | Out-String
        foreach ($rpm in $RpmVersion) {
            $FindingDetails += "$($rpm)" | Out-String
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

Function Get-V221167 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221167
        STIG ID    : MD3X-00-000290
        Rule ID    : SV-221167r960963_rule
        CCI ID     : CCI-000381, CCI-000382
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : Unused database components that are integrated in MongoDB and cannot be uninstalled must be disabled.
        DiscussMD5 : 5AC42C76E4083ACC3D6A1694D1D1C22F
        CheckMD5   : 384B3AAE308DD987A3BC8070A0194058
        FixMD5     : 9D0F73DE154A841047A432EEAF4F5ADE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "http"
    $ExpectedValue = "false or disabled"
    $BadValueRegex = "true"
    $BadValues = 0
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $HttpConfig = Get-MongoSetting -YAMLObject $NetConfig -Setting $SubHeader
            if ($Null -ne $HttpConfig -and $HttpConfig -ne "") {

                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "Enabled" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $HttpEnabled = $HttpConfig | Select-String '\senabled:' | Select-String $BadValueRegex
                if ($HttpEnabled) {
                    $BadValues++
                    $FindingDetails += "Detected:`n`ttrue" | Out-String
                }
                else {
                    $nullCheck = $HttpConfig | Select-String '\senabled:'
                    if ($nullCheck) {
                        $FindingDetails += "Detected:`n`tfalse" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "JSONPEnabled" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $HttpEnabled = $HttpConfig | Select-String '\sjsonpenabled:' | Select-String $BadValueRegex
                if ($HttpEnabled) {
                    $BadValues++
                    $FindingDetails += "Detected:`n`ttrue" | Out-String
                }
                else {
                    $nullCheck = $HttpConfig | Select-String '\sjsonpenabled:'
                    if ($nullCheck) {
                        $FindingDetails += "Detected:`n`tfalse" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "RESTInterfaceEnabled" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $HttpEnabled = $HttpConfig | Select-String '\srestinterfaceenabled:' | Select-String $BadValueRegex
                if ($HttpEnabled) {
                    $BadValues++
                    $FindingDetails += "Detected:`n`ttrue" | Out-String
                }
                else {
                    $nullCheck = $HttpConfig | Select-String '\sRESTInterfaceEnabled:'
                    if ($nullCheck) {
                        $FindingDetails += "Detected:`n`tfalse" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }

                if ($BadValues -gt 0) {
                    $Status = "Open"
                }
                else {
                    $Status = "NotAFinding"
                }
            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
                $Status = "NotAFinding"
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221168 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221168
        STIG ID    : MD3X-00-000310
        Rule ID    : SV-221168r960969_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-APP-000148-DB-000103
        Rule Title : MongoDB must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).
        DiscussMD5 : 7FA437E21FA15045B0E2720F58ECDA90
        CheckMD5   : 2FF3FE1B9BD70D2041FC569A1EB80C48
        FixMD5     : B6972AE5462E9FFA7ED49BEA01ECAC5A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "authorization"
    $ExpectedValue = "enabled"
    $SecurityConfig = ""
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $Status = "Open"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$ExpectedValue") {
                $FindingDetails += "Detected:`n`tenabled" | Out-String
            }
            else {
                $Status = "Open"
                $FindingDetails += "Detected:`n`tdisabled" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }

    $Databases = (& $MongoInstance.MongoShell --quiet --eval "printjson(db.adminCommand('listDatabases'))" | ConvertFrom-Json).databases.name
    foreach ($Database in $Databases) {
        $FindingDetails += '' | Out-String
        $FindingDetails += '----------' | Out-String
        $FindingDetails += '' | Out-String
        $Users = ((& $MongoInstance.MongoShell $database --quiet --eval "printjson(db.getUsers())") | Select-String -NotMatch '"userId"' | ConvertFrom-Json).User
        $FindingDetails += "Database:" | Out-String
        $FindingDetails += "`t$Database" | Out-String
        $FindingDetails += '' | Out-String
        $FindingDetails += "Users:" | Out-String
        if ($null -eq $Users -or $Users -eq "") {
            $FindingDetails += "`tNo Users" | Out-String
        }
        else {
            $UserArray = $Users -split ' '
            foreach ($user in $UserArray) {
                $FindingDetails += "`t$user" | Out-String
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

Function Get-V221169 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221169
        STIG ID    : MD3X-00-000320
        Rule ID    : SV-221169r981946_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-APP-000164-DB-000401
        Rule Title : If DBMS authentication using passwords is employed, MongoDB must enforce the DoD standards for password complexity and lifetime.
        DiscussMD5 : C281B672564E5152088CD0CDD6A4BB57
        CheckMD5   : 403E6A6DCFFD50AB4DDBC1752B30AC91
        FixMD5     : 22B32920E3ABFA64F56F83AD8733AF0B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "authenticationMechanisms"
    $ExpectedValue = "Not SCRAM-SHA-1, MONGODB-CR, or PLAIN"
    $Command = "db.adminCommand( {getParameter: 1, 'authenticationMechanisms' :1})"
    $AuthMech = Get-MongoShellOutput -Command $Command
    if ($AuthMech -match "SCRAM-SHA-1|MONGODB-CR|PLAIN") {
        $Status = "Open"
    }
    else {
        if ($AuthMech -match "MONGODB-X509") {
            $Status = "NotAFinding"
        }
    }
    $AuthMech = (($AuthMech -split ':')[1] -split ']')[0] -replace "\["
    $FindingDetails += "Setting:`t`t`t$Setting" | Out-String
    $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
    $FindingDetails += "Detected Value:`t$AuthMech" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221170 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221170
        STIG ID    : MD3X-00-000330
        Rule ID    : SV-221170r981949_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-APP-000171-DB-000074
        Rule Title : If passwords are used for authentication, MongoDB must store only hashed, salted representations of passwords.
        DiscussMD5 : 3AED519C41721CDF328771EC0CC7020E
        CheckMD5   : 96B26804951B477943C346B7854146A5
        FixMD5     : 4336C67C4D3BECB855554E94C2432B84
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "authenticationMechanisms"
    $ExpectedValue = "MONGODB-X509"
    $Command = "db.adminCommand( {getParameter: 1, 'authenticationMechanisms' :1})"
    $AuthMech = Get-MongoShellOutput -Command $Command

    if ($AuthMech -match "MONGODB-X509") {
        $Status = "NotAFinding"
    }

    $AuthMech = (($AuthMech -split ':')[1] -split ']')[0] -replace "\["
    $FindingDetails += "Setting:`t`t`t$Setting" | Out-String
    $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
    $FindingDetails += "Detected Value:`t $AuthMech" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221171 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221171
        STIG ID    : MD3X-00-000340
        Rule ID    : SV-221171r961029_rule
        CCI ID     : CCI-000185, CCI-000197
        Rule Name  : SRG-APP-000172-DB-000075
        Rule Title : If passwords are used for authentication, MongoDB must transmit only encrypted representations of passwords.
        DiscussMD5 : 926FD46B4A25287EC11301B3C799D298
        CheckMD5   : F4A58D98DB423EFB4A989BD46FD095EA
        FixMD5     : 5C33A95CEF87DCAE0750643532E751B1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "ssl"
    $BadValues = 0
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $SslConfig = Get-MongoSetting -YAMLObject $NetConfig -Setting "$SubHeader\:"
            if ($null -ne $SslConfig -and $SslConfig -ne "") {
                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "CAFile" | Out-String
                $FindingDetails += "Expected:`n`tpresent" | Out-String
                $SSlCA = $SslConfig | Select-String '\sCAFile:'
                if ("$SSlCA" -ne "") {
                    $FindingDetails += "Detected:`n`tpresent" | Out-String
                }
                else {
                    $BadValues++
                    $FindingDetails += "Detected:`n`tnot present" | Out-String
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "allowInvalidCertificates" | Out-String
                $FindingDetails += "Expected:`n`tfalse or not present" | Out-String
                $AllowInvalid = $SslConfig | Select-String '\sallowInvalidCertificates:' | Select-String "true"
                if ("$AllowInvalid" -ne "") {
                    $BadValues++
                    $FindingDetails += "Detected:`n`ttrue" | Out-String
                }
                else {
                    if ($SslConfig | Select-String '\sallowInvalidCertificates:') {
                        $FindingDetails += "Detected:`n`tfalse" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tnot present" | Out-String
                    }
                }
            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
                $BadValues++
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
        $BadValues++
    }

    if ($BadValues -gt 0) {
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

Function Get-V221172 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221172
        STIG ID    : MD3X-00-000360
        Rule ID    : SV-221172r961041_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DB-000068
        Rule Title : MongoDB must enforce authorized access to all PKI private keys stored/utilized by MongoDB.
        DiscussMD5 : 979C8FEEC958D1A7F3A26DC190E6DFAA
        CheckMD5   : D48E8D2375AD89C134B15A786CFCD85A
        FixMD5     : 07C7EC7F90EB16CB096B258536E42639
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "ssl"
    $ErrorCount = 0
    $OwnerCheck = "mongod"
    $GroupCheck = "mongod"
    $NetConfig = ""
    $FilesToCheck = @()
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $FilesToCheck += $($MongoInstance.ConfigFile)
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            if ($NetConfig | Select-String "ssl:") {
                $PEMKeyFileLine = $netConfig | Select-String "PEMKeyFile:"
                if ($null -eq $PEMKeyFileLine -or $PEMKeyFileLine -eq "") {
                    $FindingDetails += "PEMKeyFile not found." | Out-String
                }
                else {
                    $FilesToCheck += (($PEMKeyFileLine -split 'File:')[1]).Trim()
                }
                $CAFileLine = $netConfig | Select-String "CAFile:"
                if ($null -eq $CAFileLine -or $CAFileLine -eq "") {
                    $FindingDetails += "CAFile not found." | Out-String
                }
                else {
                    $FilesToCheck += (($CAFileLine -split 'File:')[1]).Trim()
                }
            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
                $Status = "Open"
            }
        }
        foreach ($file in $FilesToCheck) {
            if (Test-Path $file) {
                if ($IsLinux) {
                    $Listing = (& ls -ald $file)
                    $Listing = $Listing.Trim() -replace "\s+", " "
                    $Perms = (& stat -c '%a' $file)
                    $UserPerm = $Perms[0]
                    $GroupPerm = $Perms[1]
                    $OtherPerm = $Perms[2]
                    $Owner = ($Listing -split " ")[2]
                    $Group = ($Listing -split " ")[3]
                    $FindingDetails += "File: $($file)`n" | Out-String
                    $FindingDetails += "`tOwner: $Owner" | Out-String
                    $FindingDetails += "`tGroup: $Group" | Out-String
                    $FindingDetails += "`tPerms: $Perms" | Out-String
                    $FindingDetails += "" | Out-String

                    if ($Owner -ne $OwnerCheck) {
                        $ErrorCount++
                    }

                    if ($Group -ne $GroupCheck) {
                        $ErrorCount++
                    }

                    if ($UserPerm -gt "6") {
                        $ErrorCount++
                    }

                    if ($GroupPerm -gt "0") {
                        $ErrorCount++
                    }

                    if ($OtherPerm -gt "0") {
                        $ErrorCount++
                    }

                }
                else {
                    $FindingDetails += "File: $($file)`n"
                    $Acl = Get-Acl $File
                    $FindingDetails += $Acl.Access | Select-Object IdentityReference, AccessControlType, FileSystemRights | Format-List | Out-String
                }

            }
            else {
                $FindingDetails += "$file not found" | Out-String
            }
            if ($Islinux) {
                if ($ErrorCount -eq 0) {
                    $Status = "NotAFinding"
                }
                else {
                    $Status = "Open"
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221173 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221173
        STIG ID    : MD3X-00-000370
        Rule ID    : SV-221173r961044_rule
        CCI ID     : CCI-000187
        Rule Name  : SRG-APP-000177-DB-000069
        Rule Title : MongoDB must map the PKI-authenticated identity to an associated user account.
        DiscussMD5 : 79B1436F69077498ECB0F15F3D48299B
        CheckMD5   : 6A3EDD6BE2BB48D7C4ECD1E3D9D9D891
        FixMD5     : 568FE941D9F3E46662EE0F9E93A49181
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Database = "admin"
    $UserLines = (& $MongoInstance.MongoShell $database --quiet --eval "db.system.users.find({db: `"'$external'`"})")
    if ($UserLines.count -gt 0) {
        $FindingDetails += "Users:" | Out-String
        foreach ($Userline in $UserLines) {
            $UserArray = $Userline -split ', '
            foreach ($field in $UserArray) {
                $FindingDetails += "$field" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    else {
        $FindingDetails += 'No users in $external database' | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221174 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221174
        STIG ID    : MD3X-00-000380
        Rule ID    : SV-221174r961050_rule
        CCI ID     : CCI-000803, CCI-002450
        Rule Name  : SRG-APP-000179-DB-000114
        Rule Title : MongoDB must use NIST FIPS 140-2-validated cryptographic modules for cryptographic operations.
        DiscussMD5 : 801DBF9F7CE5597ED8416A48D971BF57
        CheckMD5   : 11357335A0522E61D7924BC4B6E54D0B
        FixMD5     : 25DE2A149B49D1B536C20786D7CD3287
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "ssl"
    $ExpectedValue = "true"
    $BadValues = 0
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $SslConfig = Get-MongoSetting -YAMLObject $NetConfig -Setting "$SubHeader\:"
            if ($Null -ne $SslConfig -and $SslConfig -ne "") {

                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "FIPSMode" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $SslFips = $SslConfig | Select-String '\sFIPSMode:' | Select-String $ExpectedValue
                if ($SslFips) {
                    $FindingDetails += "Detected:`n`ttrue" | Out-String
                }
                else {
                    $BadValues++
                    $nullCheck = $SslConfig | Select-String '\sFIPSMode:'
                    if ($nullCheck) {
                        $FindingDetails += "Detected:`n`tfalse" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }

                if ($BadValues -gt 0) {
                    $Status = "Open"
                }
                else {
                    $Status = "NotAFinding"
                }
            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
                $Status = "NotAFinding"
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221175 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221175
        STIG ID    : MD3X-00-000390
        Rule ID    : SV-221175r961053_rule
        CCI ID     : CCI-000804, CCI-001082, CCI-001084
        Rule Name  : SRG-APP-000180-DB-000115
        Rule Title : MongoDB must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).
        DiscussMD5 : BE621613840AE1386BA6ECC42136FF0E
        CheckMD5   : 90D11ED8E4F28E2B8842965831ED19EC
        FixMD5     : 966C0EC5328A7CC05BE9D740CAD63BDA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Role Privileges:" | Out-String
    $FindingDetails += "================" | Out-String
    $FindingDetails += (& $MongoInstance.MongoShell --quiet -eval "db.getRoles({rolesInfo: 1, showPrivileges: true, showBuiltinRoles: true}).forEach(function(aRow) {print ('  Role: ' + aRow.role) + print ('    Privileges: ') + aRow.privileges.forEach(function(item) {print ('      ' + item.actions)}) + print()})") | Get-Unique | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "User Roles:" | Out-String
    $FindingDetails += "===========" | Out-String
    $Databases = (& $MongoInstance.MongoShell --quiet --eval "db.getMongo().getDBNames().forEach(function(db) {print(db)})")
    foreach ($database in $Databases) {
        $FindingDetails += "  Database: $database" | Out-String
        $FindingDetails += (& $MongoInstance.MongoShell $database --quiet -eval "db.getUsers().forEach(function (aRow) {print ('    User: ' + aRow.user) + aRow.roles.forEach(function(item) {print ('      Role: ' + item.role)}) + print ()})") | Out-String
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

Function Get-V221176 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221176
        STIG ID    : MD3X-00-000410
        Rule ID    : SV-221176r961119_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-DB-000384
        Rule Title : MongoDB must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.
        DiscussMD5 : B9DB2F4C06240981769EF38EC0E9D166
        CheckMD5   : F18FD59ACF8D39E0EC4521F2C0784F54
        FixMD5     : D8D202D6FE6542BE4D9BCFC839CEF6F1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "ssl"
    $ExpectedValue = "requireSSL"
    $BadValues = 0
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $SslConfig = Get-MongoSetting -YAMLObject $NetConfig -Setting "$SubHeader\:"
            if ($Null -ne $SslConfig -and $SslConfig -ne "") {

                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "Mode" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $SslMode = $SslConfig | Select-String "mode:" | Select-String "requireSSL"
                if ($SslMode) {
                    $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
                }
                else {
                    $BadValues++
                    $nullCheck = $SslConfig | Select-String '\smode:'
                    if ($nullCheck) {
                        $DetectedValue = ($nullCheck -split ':')[1].trim()
                        $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }

            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
                $BadValues++
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
        $BadValues++
    }

    if ($BadValues -gt 0) {
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

Function Get-V221177 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221177
        STIG ID    : MD3X-00-000420
        Rule ID    : SV-221177r961122_rule
        CCI ID     : CCI-001190, CCI-001665
        Rule Name  : SRG-APP-000225-DB-000153
        Rule Title : MongoDB must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.
        DiscussMD5 : 901936BE96BD4A7172D8EC09127A8213
        CheckMD5   : D8612223E237927CC6F7A31268F19D4B
        FixMD5     : 4845DBB26C5AB57CB55F8582E5F6A370
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $BadResult = 0
    $NoJournal = $($MongoInstance.ProcessString) | Select-String "--nojournal"
    $FindingDetails += "Setting:`t`t`tProcess String" | Out-String
    $FindingDetails += "Expected Value:`tdoes not contain --nojournal" | Out-String
    $FindingDetails += "Detected Value:`t$($MongoInstance.ProcessString)" | Out-String
    if ($null -ne $NoJournal -and $NoJournal -ne "") {
        $BadResult++
    }

    $FindingDetails += "" | Out-String
    $Header = "storage"
    $SubHeader = "journal"
    $ExpectedValue = "true"
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$Header context not found in $($MongoInstance.ConfigFile)" | Out-String
        }
        else {
            $JournalConfig = Get-MongoSetting -YAMLObject $NetConfig -Setting "$SubHeader\:"
            if ($Null -ne $JournalConfig -and $JournalConfig -ne "") {

                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "enabled" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $JournalEnabled = $JournalConfig | Select-String '\senabled:' | Select-String 'false'
                if ($JournalEnabled) {
                    $FindingDetails += "Detected:`n`tfalse" | Out-String
                    $BadResult++
                }
                else {
                    $nullCheck = $JournalConfig | Select-String '\senabled:'
                    if ($nullCheck) {
                        $FindingDetails += "Detected:`n`ttrue" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }
            }
            else {
                $FindingDetails += "$Subheader context not found in $($MongoInstance.ConfigFile)" | Out-String
                $Status = "NotAFinding"
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }

    if ($BadResult -eq 0) {
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

Function Get-V221178 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221178
        STIG ID    : MD3X-00-000440
        Rule ID    : SV-221178r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : MongoDB must protect the confidentiality and integrity of all information at rest.
        DiscussMD5 : 23E4733106178EA985014EF4A32170FD
        CheckMD5   : 9614A3E94A8ED12924C7C01478FDA783
        FixMD5     : 57B45B493F9333B9669FB8C6993B92B3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "enableEncryption"
    $ExpectedValue = "true"
    $ErrorCount = 0

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $ErrorCount++
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$ExpectedValue") {
                $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
            }
            else {
                $ErrorCount++
                $EELine = $SecurityConfig | Select-String -Pattern "$Parameter\:"
                if ($null -ne $EELine -and $EELine -ne "") {
                    $DetectedValue = ($EELine -split ':')[1].trim()
                    $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                }
                else {
                    $FindingDetails += "Detected:`n`tNot found" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
        $ErrorCount++
    }

    $FindingDetails += '' | Out-String
    $FindingDetails += "Setting:`n`tProcessString" | Out-String
    $FindingDetails += "Expected Value:`n`t" + 'Does not contain "--enableEncryption false"' | Out-String
    $FindingDetails += "Detected Value:`n`t$($MongoInstance.ProcessString)" | Out-String
    $CheckValue = $($MongoInstance.ProcessString) | Select-String "--enableEncryption false"
    if ($null -ne $CheckValue -and $CheckValue -ne "") {
        $ErrorCount++
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

Function Get-V221180 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221180
        STIG ID    : MD3X-00-000470
        Rule ID    : SV-221180r961149_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-APP-000243-DB-000373
        Rule Title : MongoDB must prevent unauthorized and unintended information transfer via shared system resources.
        DiscussMD5 : B601A0A89E81A8A686E9663F1D1CDFFF
        CheckMD5   : BE62F3C826160E62A84C6B5F50B062FA
        FixMD5     : 7B0C95FFD6252D9266E3400D8A4B4281
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OwnerCheck = "mongod"
    $GroupCheck = "mongod"
    $FileArray = @()
    $ProcessArray = @()

    if ($IsLinux) {
        $DefaultDataDir = "/var/lib/mongo"
    }
    else {
        $DefaultDataDir = "c:\data\db"
    }

    if ($($MongoInstance.ProcessString) | Select-String '--dbpath') {
        $ProcessArray = ($($MongoInstance.ProcessString) -split '--')
        foreach ($line in $ProcessArray) {
            if ($line | Select-String "dbpath") {
                $DataDir = (($line -split '--dbpath')[1]).trim()
            }
        }
    }

    if ($null -eq $DataDir -or $DataDir -eq "") {
        $DataDir = $DefaultDataDir
    }

    $FileArray += $DataDir

    if ($($MongoInstance.ConfigFile) -EQ "Not Defined" ) {
        if ($IsLinux) {
            $FileArray += "/etc/mongod.conf"
        }
    }
    else {
        $FileArray += $($MongoInstance.ConfigFile)
    }

    foreach ($item in $FileArray) {
        try {
            $item = $Item | Out-NormalizedPath

            if (Test-Path -Path $Item) {
                if ($IsLinux) {
                    $Listing = (& ls -ald $item)
                    $Listing = $Listing.Trim() -replace "\s+", " "
                    $Perms = (& stat -c '%a' $item)
                    $GroupPerm = $Perms[1]
                    $OtherPerm = $Perms[2]
                    $Owner = ($Listing -split " ")[2]
                    $Group = ($Listing -split " ")[3]
                    $FindingDetails += "Item: $($Item)" | Out-String
                    $FindingDetails += "`tOwner: $Owner" | Out-String
                    $FindingDetails += "`tGroup: $Group" | Out-String
                    $FindingDetails += "`tPerms: $Perms`n" | Out-String

                    if ($Owner -ne $OwnerCheck) {
                        $ErrorCount++
                    }

                    if ($Group -ne $GroupCheck) {
                        $ErrorCount++
                    }

                    if ($GroupPerm -gt "5") {
                        $ErrorCount++
                    }

                    if ($OtherPerm -gt "5") {
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
                    $Acl = Get-Acl $Item | Format-Table -Wrap | Out-String
                    $FindingDetails += $Acl
                }
            }
            else {
                $FindingDetails += "Item $($Item) does not exist" | Out-String
            }
        }
        catch {
            $FindingDetails += "$($_.Exception.Message)" | Out-String
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

Function Get-V221181 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221181
        STIG ID    : MD3X-00-000490
        Rule ID    : SV-221181r961158_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-DB-000160
        Rule Title : MongoDB must check the validity of all data inputs except those specifically identified by the organization.
        DiscussMD5 : 107AEE599D525E7CFD76FC7A2B2681F6
        CheckMD5   : 10D6248C5E2AF51599D114453DA732E2
        FixMD5     : ACF6188E9D8BF9A0FB37EE494B868B3E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "javascriptEnabled"
    $ExpectedValue = "false or not found"
    $BadValue = "true"
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$BadValue") {
                $FindingDetails += "Detected:`n`ttrue" | Out-String
            }
            else {
                $Status = "NotAFinding"
                $JSLine = $SecurityConfig | Select-String -Pattern "$Parameter\:"
                if ($null -ne $JSLine -and $JSLine -ne "") {
                    $DetectedValue = ($JSLine -split ':')[1].trim()
                    $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                }
                else {
                    $FindingDetails += "Detected:`n`tNot found" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221182 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221182
        STIG ID    : MD3X-00-000500
        Rule ID    : SV-221182r961158_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-DB-000391
        Rule Title : MongoDB and associated applications must reserve the use of dynamic code execution for situations that require it.
        DiscussMD5 : 28FCBB17531EF1CBE0AE9540498908B3
        CheckMD5   : 6B9DD6765638E653A35F76ED81BECC3F
        FixMD5     : 78FEABD949ACA5E549FD5FAA34D391DF
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "javascriptEnabled"
    $ExpectedValue = "false"
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $Status = "Open"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$ExpectedValue") {
                $Status = "NotAFinding"
                $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
            }
            else {
                $Status = "Open"
                $JSLine = $SecurityConfig | Select-String -Pattern "$Parameter\:"
                if ($null -ne $JSLine -and $JSLine -ne "") {
                    $DetectedValue = ($JSLine -split ':')[1].trim()
                    $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                }
                else {
                    $FindingDetails += "Detected:`n`tNot found" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221184 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221184
        STIG ID    : MD3X-00-000530
        Rule ID    : SV-221184r961170_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-DB-000163
        Rule Title : MongoDB must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA.
        DiscussMD5 : DD8A284E415A45FA8FC418A9CC898AEF
        CheckMD5   : A8A17C65EC8C137DCF5E1632837B7708
        FixMD5     : 971E59C76BC63BBB1B3F7DF346336380
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "redactClientLogData"
    $ExpectedValue = "true"
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $Status = "Open"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$ExpectedValue") {
                $Status = "NotAFinding"
                $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
            }
            else {
                $Status = "Open"
                $Line = $SecurityConfig | Select-String -Pattern "$Parameter\:"
                if ($null -ne $Line -and $Line -ne "") {
                    $DetectedValue = ($Line -split ':')[1].trim()
                    $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                }
                else {
                    $FindingDetails += "Detected:`n`tNot found" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221185 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221185
        STIG ID    : MD3X-00-000540
        Rule ID    : SV-221185r961269_rule
        CCI ID     : CCI-002262, CCI-002263, CCI-002264
        Rule Name  : SRG-APP-000311-DB-000308
        Rule Title : MongoDB must associate organization-defined types of security labels having organization-defined security label values with information in storage.
        DiscussMD5 : 2059994FA1CECC1058D3920D1127CF22
        CheckMD5   : DE51DA8652B459B8302C51E8C0D0C615
        FixMD5     : 848853F600558D583ADEE0846311C408
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "authorization"
    $ExpectedValue = "enabled"

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$ExpectedValue") {
                $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
            }
            else {
                $Line = $SecurityConfig | Select-String -Pattern "$Parameter\:"
                if ($null -ne $Line -and $Line -ne "") {
                    $DetectedValue = ($Line -split ':')[1].trim()
                    $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                }
                else {
                    $FindingDetails += "Detected:`n`tNot found" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }

    $FindingDetails += '' | Out-String
    $FindingDetails += "Setting:`n`tProcessString" | Out-String
    $FindingDetails += "Expected Value:`n`t" + 'Contains appropriate "--auth" setting' | Out-String
    $FindingDetails += "Detected Value:`n`t$($MongoInstance.ProcessString)" | Out-String

    $FindingDetails += "" | Out-String
    $FindingDetails += "db.getCollectionInfos() Output:" | Out-String
    $Command = "db.getCollectionInfos()"
    $QueryResults += & $($MongoInstance.MongoShell) admin --quiet --eval $Command
    $QueryArray = $QueryResults -split ','
    foreach ($line in $QueryArray) {
        $blankline = $line.trim()
        if ($blankline -ne "") {
            $FindingDetails += "$line" + "," | Out-String
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

Function Get-V221188 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221188
        STIG ID    : MD3X-00-000600
        Rule ID    : SV-221188r981952_rule
        CCI ID     : CCI-001844
        Rule Name  : SRG-APP-000356-DB-000314
        Rule Title : MongoDB must utilize centralized management of the content captured in audit records generated by all components of MongoDB.
        DiscussMD5 : 2DA77123BC0EFB36C37F6202E660ED58
        CheckMD5   : 0BE779A2E9855AC42379260DB6485678
        FixMD5     : F855028E339AD976C44C028FFA96F5F1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "auditLog"
    $Parameter = "destination"
    $ExpectedValue = "syslog or file"
    $HasSyslog = 0

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "syslog") {
                $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
                $HasSyslog++
            }
            else {
                $Line = $SecurityConfig | Select-String -Pattern "$Parameter\:"
                if ($null -ne $Line -and $Line -ne "") {
                    $DetectedValue = ($Line -split ':')[1].trim()
                    $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                    if ($DetectedValue -eq "file") {
                        $FindingDetails += '' | Out-String
                        $FindingDetails += "Parameter:`n`t$Header" + ":format" | Out-String
                        $FindingDetails += "Expected:`n`tJSON or BSON" | Out-String
                        $Line = $SecurityConfig | Select-String -Pattern "format\:"
                        if ($null -ne $Line -and $Line -ne "") {
                            $DetectedValue = ($Line -split ':')[1].trim()
                            $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                        }
                        else {
                            $FindingDetails += "Detected:`n`tNot found" | Out-String
                        }
                    }
                }
                else {
                    $FindingDetails += "Detected:`n`tNot found" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }

    $FindingDetails += '' | Out-String
    $FindingDetails += "Setting:`n`tProcessString" | Out-String
    $FindingDetails += "Expected Value:`n`tAudit log set to syslog or file and pushed to a centralized logging system.." | Out-String
    $FindingDetails += "Detected Value:`n`t$($MongoInstance.ProcessString)" | Out-String
    $auditCheck = $($MongoInstance.ProcessString) | Select-String "--auditDestination syslog"
    if ($null -ne $auditCheck -and $auditCheck -ne "") {
        $HasSyslog++
    }

    if ($HasSyslog -gt 0) {
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

Function Get-V221189 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221189
        STIG ID    : MD3X-00-000620
        Rule ID    : SV-221189r961392_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-DB-000316
        Rule Title : MongoDB must allocate audit record storage capacity in accordance with site audit record storage requirements.
        DiscussMD5 : 7BB33FFD3FD01BEF637B8DCBD1BE5DBE
        CheckMD5   : 85FE9AD3F27B73287A9D3D50023328E6
        FixMD5     : 05C17D95F027E534A10B672EBF0B9FFB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $Key = "auditLog"
    $SubKey = "Destination"
    $ExpectedValue = "Not file"
    $DetectedValue = ""
    $Config = ""

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $Config = Get-YAMLObject -Section $Key -FilePath $($MongoInstance.ConfigFile)

        if ($Config.Count -eq 0) {
            $ErrorCount++
            $FindingDetails += "$($Key) key not found in file $($MongoInstance.ConfigFile)" | Out-String
        }
        else {
            $FindingDetails += "Key:`n`t$Key" + ":" + "$SubKey" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String

            try {
                $KeySection = ($Config | Select-String "destination:")

                if ($null -ne $KeySection) {
                    $DetectedValue = ($KeySection -split ":", 2)[1]
                    if (($null -ne $DetectedValue) -and ($DetectedValue -ne "")) {
                        $DetectedValue = $DetectedValue.Trim()
                        if ($DetectedValue | Select-String "file") {
                            $ErrorCount = -1
                        }
                    }
                    else {
                        $DetectedValue = "Value String Not Present"
                    }
                }
                else {
                    $DetectedValue = "$SubKey Not Present"
                }
            }
            catch {
            }

            $FindingDetails += "Detected:`n`t$($DetectedValue)" | Out-String
            $FindingDetails += "" | Out-String
        }



        if ($ErrorCount -lt 0) {
            $Status = "Open"
            $SubKey = "path"
            $DetectedValue = ""
            $FindingDetails += "Key:`n`t$Key" + ":" + "$SubKey" | Out-String

            try {
                $KeySection = ($Config | Select-String -Pattern "path:")

                if ($null -ne $KeySection) {
                    $DetectedValue = ($KeySection -split ":", 2)[1]
                    if (($null -ne $DetectedValue) -and ($DetectedValue -ne "")) {
                        $DetectedValue = $DetectedValue.Trim()
                    }
                    else {
                        $DetectedValue = "Value String Not Present"
                    }
                }
                else {
                    $DetectedValue = "$SubKey Not Present"
                }
            }
            catch {
            }

            $FindingDetails += "Detected:`n`t$($DetectedValue)" | Out-String

        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221190 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221190
        STIG ID    : MD3X-00-000630
        Rule ID    : SV-221190r961398_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-APP-000359-DB-000319
        Rule Title : MongoDB must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity.
        DiscussMD5 : E32000EF9C497CEB78E70D0D51CB6C30
        CheckMD5   : E0002D984371094ED00976E72FB550E2
        FixMD5     : 74E095546290F2EEC1F74E6779FB2851
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "auditLog"
    $Parameter = "destination"
    $ExpectedValue = "Not file"
    $ErrorCount = 0

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            $Line = $SecurityConfig | Select-String -Pattern "$Parameter\:"
            if ($null -ne $Line -and $Line -ne "") {
                $DetectedValue = ($Line -split ':')[1].trim()
                $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                if ($DetectedValue | Select-String -Pattern "file") {
                    $ErrorCount++
                }
            }
            else {
                $FindingDetails += "Detected:`n`tNot found" | Out-String
                $ErrorCount = -1
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }

    if ($ErrorCount -ge 0) {
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

Function Get-V221191 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221191
        STIG ID    : MD3X-00-000650
        Rule ID    : SV-221191r981956_rule
        CCI ID     : CCI-001812
        Rule Name  : SRG-APP-000378-DB-000365
        Rule Title : MongoDB must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.
        DiscussMD5 : 288BFAEC07E54CE1E5618EE16FDCD862
        CheckMD5   : 5C5BEAD644CC37B5C974171ADA166114
        FixMD5     : 2C56F6890888CF80C11912E6C875A7DC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Command = "db.getRoles({rolesInfo:1, showPrivileges:true, showBuiltinRoles:true})"
    $FindingDetails += Get-MongoShellOutput -Command $Command
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221192 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221192
        STIG ID    : MD3X-00-000670
        Rule ID    : SV-221192r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : MongoDB must enforce access restrictions associated with changes to the configuration of MongoDB or database(s).
        DiscussMD5 : 841236AE36286B8E29EE7B91507764A7
        CheckMD5   : 43A3499B488369652D1A296F6C462DCA
        FixMD5     : 82FDAC57CF5CD24E1B90D23F2A9088FB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $OwnerCheck = "mongod"
    $GroupCheck = "mongod"
    $Config = ""

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        try {
            $File = $MongoInstance.ConfigFile
            if (Test-Path -Path $File) {
                if ($IsLinux) {
                    $Listing = (& ls -ald $File)
                    $Listing = $Listing.Trim() -replace "\s+", " "
                    $Perms = (& stat -c '%a' $File)
                    $GroupPerm = $Perms[1]
                    $OtherPerm = $Perms[2]
                    $Owner = ($Listing -split " ")[2]
                    $Group = ($Listing -split " ")[3]
                    $FindingDetails += "File: $($File)`n" | Out-String
                    $FindingDetails += "`tOwner: $Owner" | Out-String
                    $FindingDetails += "`tGroup: $Group" | Out-String
                    $FindingDetails += "`tPerms: $Perms" | Out-String

                    if ($Owner -ne $OwnerCheck) {
                        $ErrorCount++
                    }

                    if ($Group -ne $GroupCheck) {
                        $ErrorCount++
                    }

                    if ($GroupPerm -gt "0") {
                        $ErrorCount++
                    }

                    if ($OtherPerm -gt "0") {
                        $ErrorCount++
                    }

                    if ($ErrorCount -gt 0) {
                        $Status = "Open"
                    }
                }
                else {
                    $Acl = Get-Acl $File | Format-Table -Wrap | Out-String
                    $FindingDetails += $Acl
                }
            }
            else {
                $FindingDetails += "File $($File) does not exist" | Out-String
            }
        }
        catch {
            $FindingDetails += "$($_.Exception.Message)" | Out-String
        }
    }
    else {
        $FindingDetails += "Mongo configuration file could not be found." | Out-String
    }

    $Command = "db.getRoles({rolesInfo:1, showPrivileges:true, showBuiltinRoles:true})"
    $FindingDetails += Get-MongoShellOutput -Command $Command
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221193 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221193
        STIG ID    : MD3X-00-000700
        Rule ID    : SV-221193r987687_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-APP-000389-DB-000372
        Rule Title : MongoDB must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.
        DiscussMD5 : 5584ED5BD25A661A9E0BC38F02660E85
        CheckMD5   : 9E79B14CB9DC019113FBB02FD417FC02
        FixMD5     : 08C1183A17ABBFA03402A1ED70189FCB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "security"
    $Parameter = "authorization"
    $ExpectedValue = "enabled"
    $ErrorCount = 0

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $SecurityConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($SecurityConfig.Count -eq 0) {
            $ErrorCount++
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $FindingDetails += "Parameter:`n`t$Header" + ":" + "$Parameter" | Out-String
            $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
            if ($SecurityConfig | Select-String -Pattern "$Parameter\:" | Select-String -Pattern "$ExpectedValue") {
                $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
            }
            else {
                $ErrorCount++
                $EELine = $SecurityConfig | Select-String -Pattern "$Parameter\:"
                if ($null -ne $EELine -and $EELine -ne "") {
                    $DetectedValue = ($EELine -split ':')[1].trim()
                    $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                }
                else {
                    $FindingDetails += "Detected:`n`tNot found" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
        $ErrorCount++
    }

    $FindingDetails += '' | Out-String
    $FindingDetails += "Setting:`n`tProcessString" | Out-String
    $FindingDetails += "Detected Value:`n`t$($MongoInstance.ProcessString)" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221194 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221194
        STIG ID    : MD3X-00-000710
        Rule ID    : SV-221194r961521_rule
        CCI ID     : CCI-002007
        Rule Name  : SRG-APP-000400-DB-000367
        Rule Title : MongoDB must prohibit the use of cached authenticators after an organization-defined time period.
        DiscussMD5 : CC1503EB4AC6C661B16A41A973BC66E1
        CheckMD5   : B362B21AAD058919CED93E40486F8832
        FixMD5     : A52424C933F4FAB3DBAFD03AB6A73504
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $TimeoutSet = $false
    $Header = "setParameter"
    $SubHeader = "userCacheInvalidationIntervalSecs"
    $ExpectedValue = "Has value"

    $ProcessIds = Get-ProcessIds -ProcessName "saslauthd"

    if ($ProcessIds.Count -eq 0) {
        $FindingDetails += "saslauthd is not running" | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        foreach ($pId in $ProcessIds) {
            $SASLCacheIntervalsSet = $false
            $processString = Get-ProcessString -ProcessId $pId
            $saslTimeoutFlag = $processString | Select-String -Pattern "-t"

            if ($null -eq $saslTimeoutFlag -or $saslTimeoutFlag -eq "") {
                $ErrorCount++
            }
            else {
                $SASLCacheIntervalsSet = $true
                $TimeoutSet = $true
            }

            $FindingDetails += "saslauthd Process:`n`t$processString" | Out-String
            $FindingDetails += "Flag:`n`t'-t' present:" | Out-String
            $FindingDetails += "Expected:`n`tTrue" | Out-String
            $FindingDetails += "Detected:`n`t$SASLCacheIntervalsSet" | Out-String
            $FindingDetails += "" | Out-String

        }
    }

    $ProcessIds = Get-ProcessIds -ProcessName "mongos"

    if ($ProcessIds.Count -eq 0) {
        $FindingDetails += "mongos is not running" | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        foreach ($pId in $ProcessIds) {
            $ConfigFile = Get-MongoConfig -ProcessId $pId

            if ($ConfigFile -ne "Not Defined" ) {
                $Config = Get-YAMLObject -Section $Header -FilePath $ConfigFile

                if ($Config.Count -eq 0) {
                    $Status = "NotAFinding"
                    $FindingDetails += "$Header context not found." | Out-String
                }
                else {
                    $SubConfig = Get-MongoSetting -YAMLObject $Config -Setting "$SubHeader\:"
                    if ($null -ne $SubConfig -and $SubConfig -ne "") {
                        $FindingDetails += "Mongos Config File:`n`t$ConfigFile" | Out-String
                        $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" | Out-String
                        $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                        $DetectedValue = ($SubConfig -split ':')[1].trim()
                        $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                        $TimeoutSet = $true
                    }
                    else {
                        $FindingDetails += "$Subheader context not found" | Out-String
                        $ErrorCount++
                    }
                }
            }
            else {
                $FindingDetails += "Conf file could not be found." | Out-String
            }
        }
    }

    if ($ErrorCount -gt 0) {
        if ($TimeoutSet -eq $false) {
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

Function Get-V221195 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221195
        STIG ID    : MD3X-00-000730
        Rule ID    : SV-221195r961596_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-DB-000385
        Rule Title : MongoDB must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.
        DiscussMD5 : 92A211A9F7C690479628633321AD2DD3
        CheckMD5   : 38BF7571322D72310E6830F7605914DB
        FixMD5     : F40F81973BDCAB37921AAFE34C2EA7BC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "ssl"
    $NetConfig = ""
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            if ($NetConfig | Select-String "ssl:") {
                $PEMKeyFileLine = $netConfig | Select-String "PEMKeyFile:"
                if ($null -eq $PEMKeyFileLine -or $PEMKeyFileLine -eq "") {
                    $FindingDetails += "PEMKeyFile not found." | Out-String
                }
                else {
                    $PEMKeyFile += (($PEMKeyFileLine -split 'File:')[1]).Trim()
                    Try {
                        if($isLinux) {
                            $PEMOutput = & openssl x509 -in $PEMKeyFile -text 2>$null| select-string "issuer" | Out-String
                        }
                        else {
                            $PEMOutput = cmd /c openssl x509 -in $PEMKeyFile -text '2>nul'| select-string "issuer" | Out-String
                        }
                    }
                    Catch {
                        $PEMOutput = "openssl not found" | Out-String
                    }

                    $FindingDetails += "PEMKeyFile:`t$PEMKeyFile" | Out-String
                    $FindingDetails += "`n$PEMOutput" | Out-String
                }
            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221196 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221196
        STIG ID    : MD3X-00-000740
        Rule ID    : SV-221196r961599_rule
        CCI ID     : CCI-002475
        Rule Name  : SRG-APP-000428-DB-000386
        Rule Title : MongoDB must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.
        DiscussMD5 : 5DE682536645A6319A471B4EA56D9B70
        CheckMD5   : 4DD9A0A6A860E66CD3343920BBF03477
        FixMD5     : 17264D37BCB393D0F68693027ABF33C1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Process String:`n`t$($MongoInstance.ProcessString)" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221197 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221197
        STIG ID    : MD3X-00-000760
        Rule ID    : SV-221197r961638_rule
        CCI ID     : CCI-002420
        Rule Name  : SRG-APP-000441-DB-000378
        Rule Title : MongoDB must maintain the confidentiality and integrity of information during preparation for transmission.
        DiscussMD5 : 14007C5FC5D60FB27961A7EA762443E1
        CheckMD5   : 569B81FA0D18B56ECD0D29768E2E479B
        FixMD5     : 3083CDBA0EB96BECA3B81D39E2CEEA9F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "ssl"
    $ExpectedValue = "requireSSL"

    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $SslConfig = Get-MongoSetting -YAMLObject $NetConfig -Setting "$SubHeader\:"
            if ($Null -ne $SslConfig -and $SslConfig -ne "") {

                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "Mode" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $SslMode = $SslConfig | Select-String "mode:" | Select-String "requireSSL"
                if ($SslMode) {
                    $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
                }
                else {
                    $nullCheck = $SslConfig | Select-String '\smode:'
                    if ($nullCheck) {
                        $DetectedValue = ($nullCheck -split ':')[1].trim()
                        $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }
            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221198 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221198
        STIG ID    : MD3X-00-000770
        Rule ID    : SV-221198r961641_rule
        CCI ID     : CCI-002422
        Rule Name  : SRG-APP-000442-DB-000379
        Rule Title : MongoDB must maintain the confidentiality and integrity of information during reception.
        DiscussMD5 : 0C799B34BCEF436C79D08392950423B9
        CheckMD5   : F99BF3361DC35CEB90F5092CEC1A2852
        FixMD5     : BDB998AEFA40653EA39D7A5CFE6BC65F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Header = "net"
    $SubHeader = "ssl"
    $ExpectedValue = "requireSSL"
    if ($($MongoInstance.ConfigFile) -ne "Not Defined" ) {
        $NetConfig = Get-YAMLObject -Section $Header -FilePath $($MongoInstance.ConfigFile)
        if ($NetConfig.Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$Header context not found." | Out-String
        }
        else {
            $SslConfig = Get-MongoSetting -YAMLObject $NetConfig -Setting "$SubHeader\:"
            if ($Null -ne $SslConfig -and $SslConfig -ne "") {

                $FindingDetails += "Parameter:`n`t$Header" + ":" + "$SubHeader" + ":" + "Mode" | Out-String
                $FindingDetails += "Expected:`n`t$ExpectedValue" | Out-String
                $SslMode = $SslConfig | Select-String "mode:" | Select-String "requireSSL"
                if ($SslMode) {
                    $FindingDetails += "Detected:`n`t$ExpectedValue" | Out-String
                }
                else {
                    $nullCheck = $SslConfig | Select-String '\smode:'
                    if ($nullCheck) {
                        $DetectedValue = ($nullCheck -split ':')[1].trim()
                        $FindingDetails += "Detected:`n`t$DetectedValue" | Out-String
                    }
                    else {
                        $FindingDetails += "Detected:`n`tDoes not exist in file" | Out-String
                    }
                }
            }
            else {
                $FindingDetails += "$Subheader context not found" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "Conf file could not be found." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V221199 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221199
        STIG ID    : MD3X-00-000780
        Rule ID    : SV-221199r961656_rule
        CCI ID     : CCI-002754
        Rule Name  : SRG-APP-000447-DB-000393
        Rule Title : When invalid inputs are received, MongoDB must behave in a predictable and documented manner that reflects organizational and system objectives.
        DiscussMD5 : C6410FFD25E4E798F499A9AB9F7DEEC2
        CheckMD5   : BBD43E8E7A96F1759F890DF63FEF80EB
        FixMD5     : 5D75FB9E3A32CBFE6F49118F10024ED5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $Databases = (& $MongoInstance.MongoShell --quiet --eval "db.getMongo().getDBNames().forEach(function(db) {print(db)})")
    foreach ($database in $Databases) {
        $OptionError = $false
        $FindingDetails += "Database: $database" | Out-String
        $FindingDetails += (& $MongoInstance.MongoShell $database --quiet -eval "db.getCollectionInfos().forEach(function(row) {print('name: ' + row.name); print('options:'); printjson(row.options); print()})") | Out-String

        $Options = (& $MongoInstance.MongoShell $database --quiet -eval "db.getCollectionInfos().forEach(function(row) {printjson(row.options)})")
        foreach ($option in $Options) {
            $Validator = $option | Select-String -Pattern "validator"
            if ($null -eq $Validator) {
                if (-not $OptionError) {
                    $FindingDetails += "$database database is missing a validator option" | Out-String
                    $OptionError = $true
                }
                $ErrorCount++
            }
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "=================================================================" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V265875 {
    <#
    .DESCRIPTION
        Vuln ID    : V-265875
        STIG ID    : MD3X-00-001200
        Rule ID    : SV-265875r999531_rule
        CCI ID     : CCI-003376
        Rule Name  : SRG-APP-000456-DB-000400
        Rule Title : MongoDB products must be a version supported by the vendor.
        DiscussMD5 : A62B17501780D92ECF5A0F54F0183A13
        CheckMD5   : 2CE28D5D54C5364AD0394E8309E02491
        FixMD5     : 6D17FD185C51ACC4BC979D3F9D3BBD3C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-IsMongoDB3Installed) {
        $Status = "Open"
        $FindingDetails += "MongoDB 3 is installed.  [finding]" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "MongoDB 3 is not installed." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA38P3+Skvsh1BH
# rB3PH8fNm+DeCOp24q3FkQHT8NtPd6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCAmoaVfc5YXEYdRmT+JHUFARYm9ggaJuPj50dAlYoD+IDANBgkqhkiG9w0BAQEF
# AASCAQCqzvmMbTIbsdYuUtI9xX4cx4sc88RaVMG06dIkfh0lWrBvQjkr5rm1Je/I
# Vw11tAHqooEXb6rsxL42Hn9eCW/TRZuvGn0nFsRNnUMcu92s9513qvIQW5hie9hh
# XFTGrtp58FHoFZdGlPXwDgA6ZxHE+RCMa9YRsf/xmNqYIXrm0Qmj6xImKi+H5/qC
# mYsUGQavuBdEJxGJcRhYYc3IiFWSqbgcO6yJSfGPCgIJN/7O7nDF8AqFRDsLdBA8
# S9iTGzkBQmv5kZ9eSR/kbNldVLNLyKC3N+3heJBEpxTl7sewNTZFB6WS/KgzliA2
# W4pDPbokvx//k1RzcFC/1Q9osrOvoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTYwMlowLwYJKoZIhvcNAQkEMSIEIA/aQPBOsgdO4JbVQp79gHzxBNEJ
# e8zclTFQF98Jq0siMA0GCSqGSIb3DQEBAQUABIICAJ08vq5TG19hWrrQ9PuBrOT+
# T7jOQEvo1SLe7obI2EOm4QvdaBPn1jZ03ISKHYRCcYCBQbGdKoFVqhEwYwuSXnai
# pw2IpC9+nwQT4g9OBE52kjRWnvx6MQfufvsZ/chU/46svQ/2iPHz1clIMay0Vc2S
# k2lASJy2cshpbCv1lo/YDvv8p23ycRQb3oy6Ji8iql+7WLNu89yIp90fUSLkzM/9
# oV9PJ5Rq8kJFRcr8wgZW8GBD6D1cXVSyFYdEsLje7lSt5941aXymrRZaAjeCMSo5
# bHBe0Zv2wmWXVsvYg0bHwlzHWuKlp5T1h31ZO5J5iGXZJVuQA9W+Ov+KglB9HkV0
# cR3vSsUAzJms71SFQM2ZzDSGbJaqJem8AGnEcxN2DMNgLYqi/1fNDcYmu8yOW8g5
# WZdY5/LNKlv5YBXhNB+JvHuUkzIuJIITbAwq/KNpoGLzqV9+jRNZ5l11kNp6NcNH
# 70N3XiPbDof5h3f4ZVZxXg4pavjehiJRIa1Y3yo4VS/ey95n3oR1cwQnI0Dr1Rvf
# 5sco6PfGi9B6vsFmoublq23+pyqw9c4vz6geNZ/OpSMCgO8AhVLFk//Z+h1ZR6gm
# QYOM1H7gvz3R9NuNrtZAf+dglfEFhojebGzT7sn3iLjMxG0+YLwJIqxL4nkMzT4F
# 5QCt/Cj5WN8sSoHpUADP
# SIG # End signature block
