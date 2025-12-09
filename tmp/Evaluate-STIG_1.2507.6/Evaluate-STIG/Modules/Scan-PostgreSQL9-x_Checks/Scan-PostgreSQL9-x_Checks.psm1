##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     PostgreSQL 9.x
# Version:  V2R5
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-ContainerIPBinding {
    param (
        [Parameter(Mandatory = $True)]
        [string]$Engine,
        [Parameter(Mandatory = $True)]
        [string]$Container
    )

    $server = ""

    try {
        $server = & $Engine inspect -f '{{.NetworkSettings.IPAddress}}' $Container
    }
    catch {
        $server = "0.0.0.0"
    }

    return $server
}

Function Get-ContainerLogPath {
    param (
        [Parameter(Mandatory = $True)]
        [string]$Engine,
        [Parameter(Mandatory = $True)]
        [string]$Container
    )

    $LogPath = ""

    try {
        $LogPath = switch ($Engine) {
            'docker' {
                & $Engine inspect -f '{{.LogPath}}' $Container
            }
            'podman' {
                & $Engine inspect -f '{{.HostConfig.LogConfig.Path}}' $Container
            }
        }
    }
    catch {
        $LogPath = ""
    }

    return $LogPath
}

Function Get-ContainerPortBinding {
    param (
        [Parameter(Mandatory = $True)]
        [string]$Engine,
        [Parameter(Mandatory = $True)]
        [string]$Container
    )

    $port = ""

    try {
        $port = (& $Engine inspect -f '{{.NetworkSettings.Ports}}' $Container | Select-String -Pattern "\d+").Matches[0].Value
    }
    catch {
        $port = "5432"
    }

    return $port
}

Function Get-ErrorToCheck {
    param (
        [Parameter(Mandatory = $True)]
        [Array]$ExpectedErrors,
        [Parameter(Mandatory = $True)]
        [String]$QueryResult
    )

    $ErrorToCheck = $null
    foreach ($Error in $ExpectedErrors ) {
        if ($QueryResult -match "$Error") {
            $ErrorToCheck = "$Error"
            break
        }
    }

    return $ErrorToCheck
}

Function Get-FileACLs {
    param (
        [Parameter(Mandatory = $True)]
        [string[]] $path
    )

    $AllPerms = New-Object System.Collections.Generic.List[System.Object]

    foreach ($line in $path) {
        [System.Collections.ArrayList]$Accounts = @()

        if (-not (Test-Path $line)) {
            continue
        }

        $acls = Get-Acl -Path $line -ErrorAction SilentlyContinue

        $acls | ForEach-Object {
            $_.Access | ForEach-Object {
                if ($_.AccessControlType -match "Allow") {
                    $AcctObj = @{
                        Name       = $_.IdentityReference
                        Permission = $_.FileSystemRights -replace ", Synchronize"
                    }

                    [void]$Accounts.Add($AcctObj)
                }
            }
        }

        $PermsObj = @{
            Path     = ($acls.Path -split '::')[1]
            Owner    = $acls.Owner
            Accounts = $Accounts
        }

        [void]$AllPerms.Add($PermsObj)
    }

    return $AllPerms
}

Function Get-FileOwner {
    param (
        [Parameter(Mandatory = $True)]
        [string[]] $path
    )

    [System.Collections.ArrayList]$ListingOwner = @()

    foreach ($line in $path) {
        if ($IsLinux) {
            $ListFileOwner = ($($line -replace '\s+', ' ') -split " ")[2]
        }
        else {
            $ListFileOwner = Get-Acl -Path "$line" | ForEach-Object {$_.Owner}
        }
        [void]$ListingOwner.Add($ListFileOwner)
    }

    return $ListingOwner
}

Function Get-FormattedFileListing {
    param (
        [Parameter(Mandatory = $True)]
        [string[]] $listing,
        [Parameter(Mandatory = $False)]
        [int] $limit
    )

    $OutBuffer = ""
    $limitCount = 0

    foreach ($line in $listing) {
        $FileListing = Get-FileACLs -path $line

        foreach ($file in $FileListing) {
            $limitCount++
            $OutBuffer += "File:" | Out-String
            $OutBuffer += "  $($file.Path)" | Out-String
            $OutBuffer += "Owner:" | Out-String
            $OutBuffer += "  $($file.Owner)" | Out-String
            $OutBuffer += "Access:" | Out-String
            foreach ($account in $file.Accounts) {
                $OutBuffer += "  Name: $($account.Name)  |  Permission: $($account.Permission) " | Out-String
            }
        }

        $OutBuffer += "" | Out-String

        if ($null -ne $limit -and $limitCount -ge $limit) {
            $OutBuffer += "Output truncated at $($limit) file listings" | Out-String
            $OutBuffer += "" | Out-String
            break
        }
    }

    return $OutBuffer
}

Function Get-NumOfRows {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]$QueryOutput
    )

    $numOfRows = $QueryOutput | Select-String -Pattern "(\d+ rows{0,1})" | ForEach-Object {(($_.matches).Value -split ' ')[0]}

    if ( $null -eq $numOfRows -or $numOfRows -eq "" ) {
        $numOfRows = 0
    }
    return $numOfRows
}

Function Get-ODBCData {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [string]$PgData
    )

    $HbaData = Get-ODBCDataFromHBA -PgData $PgData

    $ODBCData = [PSCustomObject]@{
        User     = $HbaData.User
        Database = $HbaData.Database
    }

    return $ODBCData
}

Function Get-ODBCDataFromHBA {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [string]$PgData
    )

    $DefaultDatabase = "postgres"
    $DefaultUserName = "postgres"

    $HbaFilePath = Join-Path -Path $PgData -ChildPath pg_hba.conf

    if (Test-Path -Path $HbaFilePath) {
        $HbaRawLine = Select-String -Path $HbaFilePath -Pattern "^(local|host)\s*(\S*\s*){2}(|127\.\S*\s*)trust" | Select-Object -ExpandProperty Line

        if ($null -ne $HbaRawLine) {
            foreach ($line in $HbaRawLine -split "`n" ) {
                $HbaLine = $line -replace "\s+", " "
                $Database = ($HbaLine -split ' ')[1]

                if ($Database -eq "all" -or $Database -eq "postgres" ) {
                    $Database = "postgres"

                    $UserName = ($HbaLine -split ' ')[2]
                    if ($UserName -eq "all") {
                        $UserName = "postgres"
                    }
                    break
                }
            }
        }
    }

    if ($null -eq $UserName -or $UserName -eq "") {
        $UserName = $DefaultUserName
    }

    if ($null -eq $Database -or $Database -eq "") {
        $Database = $DefaultDatabase
    }

    $ODBCData = [PSCustomObject]@{
        Database = $Database
        User     = $UserName
    }

    return $ODBCData
}

Function Get-ODBCDataFromString {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [string]$HbaLines
    )

    $DefaultDatabase = "postgres"
    $DefaultUserName = "postgres"

    $HbaRawLine = $HbaLines | Select-String -Pattern "^(local|host)\s*(\S*\s*){2}(|127\.\S*\s*)trust" | Select-Object -ExpandProperty Line

    if ($null -ne $HbaRawLine) {
        foreach ($line in $HbaRawLine -split "`n" ) {
            $HbaLine = $line -replace "\s+", " "
            $Database = ($HbaLine -split ' ')[1]

            if ($Database -eq "all" -or $Database -eq "postgres" ) {
                $Database = "postgres"

                $UserName = ($HbaLine -split ' ')[2]
                if ($UserName -eq "all") {
                    $UserName = "postgres"
                }
                break
            }
        }
    }

    if ($null -eq $UserName -or $UserName -eq "") {
        $UserName = $DefaultUserName
    }

    if ($null -eq $Database -or $Database -eq "") {
        $Database = $DefaultDatabase
    }

    $ODBCData = [PSCustomObject]@{
        Database = $Database
        User     = $UserName
    }

    return $ODBCData
}

Function Get-PGDatabase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [psobject]$ODBCData
    )

    If ($IsLinux) {
        $PGDatabase = $ODBCData.Database
    }
    else {
        $PGDatabase = $Env:PGDATABASE
        if ($null -eq $PGDatabase -or $PGDatabase -eq "") {
            $PGDatabase = $ODBCData.Database
        }
    }

    if ($null -eq $PGDatabase -or $PGDatabase -eq "") {
        $PGDatabase = "postgres"
    }
    return $PGDatabase
}

Function Get-PgErrorFromLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string] $LogPath,
        [Parameter(Mandatory = $True)]
        [string] $ErrorPattern
    )

    if (-not (Test-Path $LogPath)) {
        return "$($LogPath) does not exist."
    }

    $RegexErrorPattern = $ErrorPattern.Replace("\", "\S*")
    If ($PowerShellVersion -ge [Version]"7.0") {
        $Content = Select-String -Path $LogPath -Pattern "$RegexErrorPattern" -Raw -ErrorAction SilentlyContinue | Out-String
    }
    else {
        $Content = Select-String -Path $LogPath -Pattern "$RegexErrorPattern" -ErrorAction SilentlyContinue | Out-String
    }

    return "$Content"
}

Function Get-PgErrorFromLogWithContext {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [AllowEmptyString()]
        [string] $LogPath,
        [Parameter(Mandatory = $True)]
        [string] $StatementPattern,
        [Parameter(Mandatory = $True)]
        [string] $ErrorPattern
    )

    if (-not (Test-Path $LogPath)) {
        return "$($LogPath) does not exist."
    }
    $Content = @()
    $Context = Select-String -Path $LogPath -Pattern "$StatementPattern" -Context 10, 10 -ErrorAction SilentlyContinue | Out-String -Stream

    foreach ( $line in $Context ) {
        $Content += $line | Select-String -Pattern "$ErrorPattern" | Out-String
    }

    return "$Content"
}

Function Get-PgLatestLogFile {
    [CmdletBinding()]
    param(
    )

    $LogFilePath = $null

    # Assume the file last written to is the log file we want.
    $LogFile = Get-ChildItem -Path $PgInstance.LogDir -Recurse -ErrorAction SilentlyContinue -File `
    | Sort-Object {$_.LastWriteTime} `
    | Select-Object -Last 1
    $LogFilePath = $LogFile.Fullname

    return $LogFilePath
}

Function Get-PgLogDestination {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$PSQL,
        [Parameter(Mandatory = $True)]
        [bool]$PSQLAccess,
        [Parameter(Mandatory = $True)]
        [string]$Database,
        [Parameter(Mandatory = $True)]
        [string]$UserName,
        [Parameter(Mandatory = $True)]
        [string]$Port,
        [Parameter(Mandatory = $False)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ContainerEngine,
        [Parameter(Mandatory = $False)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ContainerName
    )

    $LogDest = ""

    if ($PSQLAccess) {
        if ($null -eq $ContainerEngine -or $ContainerEngine -eq "") {
            $Result = Invoke-PSQL -PSQL $PSQL -UserName $UserName -Database $Database -Port $Port -Query "show log_destination;"
            $LogDest = Get-QueryOutputValue -QueryOutput ($Result.Output | Out-String)
        }
        else {
            $Result = Invoke-ContainerCommand -Engine $ContainerEngine -Container $ContainerName -Command "$PSQL -U $PGUser -p $Port -c 'show log_destination;'"
            $LogDest = Get-QueryOutputValue -QueryOutput ($Result | Out-String)
        }
    }

    return $LogDest
}

Function Get-PgLogDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$PSQL,
        [Parameter(Mandatory = $True)]
        [bool]$PSQLAccess,
        [Parameter(Mandatory = $True)]
        [string]$PG_DATA,
        [Parameter(Mandatory = $True)]
        [string]$Database,
        [Parameter(Mandatory = $True)]
        [string]$UserName,
        [Parameter(Mandatory = $True)]
        [string]$Port,
        [Parameter(Mandatory = $False)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ContainerEngine,
        [Parameter(Mandatory = $False)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ContainerName
    )

    $LogPath = "$PG_DATA/log" #Default Log Path

    if ($null -eq $ContainerEngine -or $ContainerEngine -eq "") {
        $LogDest = Get-PgLogDestination -PSQL $PSQL -PSQLAccess $PSQLAccess -Database $Database -UserName $UserName -Port $Port
    }
    else {
        $LogDest = Get-PgLogDestination -PSQL $PSQL -PSQLAccess $PSQLAccess -Database $Database -UserName $UserName -Port $Port -ContainerEngine $ContainerEngine -ContainerName $ContainerName
    }

    if ($PSQLAccess) {
        if ($IsLinux) {
            $IsValid = $LogDest | grep -e 'stderr\|csvlog'
        }
        else {
            $IsValid = $LogDest | Select-String -Pattern 'stderr|csvlog'
        }

        if ($null -ne $IsValid -and $IsValid -ne "") {
            # Grab the log_directory

            if ($null -eq $ContainerEngine -or $ContainerEngine -eq "") {
                $Result = Invoke-PSQL -PSQL $PSQL -UserName $UserName -Database $Database -Port $Port -Query "show log_directory;"
                $LogDir = Get-QueryOutputValue -QueryOutput ($Result.Output | Out-String)
            }
            else {
                $Result = Invoke-ContainerCommand -Engine $ContainerEngine -Container $ContainerName -Command "$PSQL -U $PGUser -p $Port -c 'show log_directory;'"
                $LogDir = Get-QueryOutputValue -QueryOutput ($Result | Out-String)
            }

            if (Test-Path -Path $LogDir) {
                # This is an absolute path to some directory.
                $LogPath = $LogDir
            }
            else {
                $ConcatPath = "$PG_DATA/$($LogDir)"
                if (Test-Path -Path $ConcatPath) {
                    # The concatenated path is the one we want.
                    $LogPath = $ConcatPath
                }
            }
        } else {
            if ($LogDest -eq 'syslog') {
                # Logging is managed by syslog, not PSQL
                $LogPath = $null
            }
        }
    }

    if ($null -ne $LogPath) {
        return $LogPath | Out-NormalizedPath
    }
    else {
        return $LogPath
    }
}

Function Get-PgLogEntryFromSyntaxError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string] $LogPath, #Path to Log File
        [Parameter(Mandatory = $True)]
        [string] $Command, #Meta command to run
        [Parameter(Mandatory = $True)]
        [string] $LogQuery, #Start of log entry to search for
        [Parameter(Mandatory = $True)]
        [int] $NumLines  #Number of lines to extract from log entry, set this to 1 if it is not multiline.
    )

    try {
        $DummyQuery1TableName = Get-RandomTableName
        $DummyQuery1 = $("SELECT NOW" + $($DummyQuery1TableName) + "()")
        $DummyVar1 = Invoke-PSQLQuery -Query $DummyQuery1 2> /dev/null

        $DummyResult = Invoke-PSQLQuery -Query $Command

        $DummyQuery2TableName = Get-RandomTableName
        $DummyQuery2 = $("SELECT NOW" + $($DummyQuery2TableName) + "()")
        $DummyVar2 = Invoke-PSQLQuery -Query $DummyQuery2 2> /dev/null
    }
    catch {
        # We don't care what the exception is.
    }

    # Find log from start to end times, grep to find log query and number of lines
    return (Get-Content $LogPath -ErrorAction SilentlyContinue | Select-String -Pattern "(?sm)\b$DummyQuery1TableName\b.*\b$DummyQuery2TableName\b" | Select-String -Pattern $LogQuery -Context 0, $NumLines)
}

Function Get-PgRecordFromMeta {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string] $command,
        [Parameter(Mandatory = $True)]
        [string] $SearchPattern
    )

    $PreviousRecord = ""
    $DBArray = Invoke-PSQLQuery -ExpandTable -Query $command -DisableRecordLimit
    foreach ($line in $DBArray) {

        if ($IsLinux) {
            $IsNewLine = $line | grep "^\-\[ RECORD"
        }
        else {
            $IsNewLine = $line | Select-String -Pattern "^\-\[ RECORD"
        }

        if ( $null -ne $IsNewLine -and $IsNewLine -ne "") {
            if ( $null -ne $PreviousRecord -and $PreviousRecord -ne "") {
                if ($IsLinux) {
                    $SURecord = $PreviousRecord | grep -e $SearchPattern
                }
                else {
                    $SURecord = $PreviousRecord | Select-String -Pattern $SearchPattern
                }
                if ( $null -ne $SURecord -and $SURecord -ne "") {
                    $ReturnValue += $PreviousRecord | Out-String
                }
            }
            $PreviousRecord = $line | Out-String
        }
        else {
            $PreviousRecord += $line | Out-String
        }
    }

    if ( $null -ne $PreviousRecord -and $PreviousRecord -ne "") {
        if ($IsLinux) {
            $SURecord = $PreviousRecord | grep -e $SearchPattern
        }
        else {
            $SURecord = $PreviousRecord | Select-String -Pattern $SearchPattern
        }
        if ( $null -ne $SURecord -and $SURecord -ne "") {
            $ReturnValue += $PreviousRecord | Out-String
        }
    }

    if ( $null -eq $ReturnValue -or $ReturnValue -eq "") {
        $ReturnValue = "No Records Found" | Out-String
    }
    $ReturnValue += "" | Out-String

    return $ReturnValue
}

Function Get-PGUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [psobject]$ODBCData
    )

    If ($IsLinux) {
        $PGUser = $ODBCData.User
        if ($null -eq $PGUser -or $PGUser -eq "") {
            $PGUser = $ProcessUser
        }
    }
    else {
        $PGUser = $Env:PGUSER
        if ($null -eq $PgUser -or $PgUser -eq "") {
            $PGUser = $ODBCData.User
        }
        if ($null -eq $PgUser -or $PgUser -eq "") {
            $RegPaths = Get-ChildItem -Path HKLM:\SOFTWARE\PostgreSQL\installations
            $Installation = @()
            foreach ($Path in $RegPaths) {
                $SearchPath = "Registry::$($PATH)"
                $Installation = Get-ItemPropertyValue -Path $SearchPath -Name "Data Directory"

                If ($Installation -eq $PG_DATA) {
                    $CorrectInstall = $SearchPath
                    break
                }
            }
            if ($null -ne $CorrectInstall) {
                $PGUser = Get-ItemPropertyValue -Path $CorrectInstall -Name "Super User"
            }
        }
    }
    if ($null -eq $PGUser -or $PGUser -eq "") {
        $PGUser = "postgres"
    }

    return $PGUser
}

Function Get-PostgresConfigContent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]$ConfigFile,
        [Parameter(Mandatory = $False)]
        [String]$SearchPattern,
        [Parameter(Mandatory = $False)]
        [Switch]$NotMatch
    )

    $OutList = New-Object System.Collections.Generic.List[System.Object]

    if ($PgInstance.ContainerEngine -eq "") {
        if (-not (Test-Path -Path $ConfigFile)) {
            $NewObj = [PSCustomObject]@{
                Path       = "Not Found"
                ConfigLine = "Not Found"
            }

            $OutList.Add($NewObj)

            return $OutList
        }

        if (($null -eq $SearchPattern) -or ($SearchPattern -eq "")) {
            $configLines = Select-String -Path $ConfigFile -Pattern '^\s{0,}#|^$' -NotMatch
        }
        else {
            if ($NotMatch) {
                $configLines = Select-String -Path $ConfigFile -Pattern '^\s{0,}#|^$' -NotMatch | Select-String -Pattern "$SearchPattern" -NotMatch
            }
            else {
                $configLines = Select-String -Path $ConfigFile -Pattern '^\s{0,}#|^$' -NotMatch | Select-String -Pattern "$SearchPattern"
            }
        }
    }
    else {
        $exists = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "[ -f $ConfigFile ] && echo 'TRUE'"

        if ($exists -ne "TRUE") {
            $NewObj = [PSCustomObject]@{
                Path       = "Not Found"
                ConfigLine = "Not Found"
            }

            $OutList.Add($NewObj)

            return $OutList
        }

        $configLines = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "grep -Env '^\s{0,}#|^$' ""$ConfigFile"""

        if (($null -ne $SearchPattern) -and ($SearchPattern -ne "")) {
            if ($NotMatch) {
                $configLines = $configLines | Select-String -Pattern "$SearchPattern" -NotMatch
            }
            else {
                $configLines = $configLines | Select-String -Pattern "$SearchPattern"
            }
        }
    }

    if ( $null -eq $configLines ) {
        $NewObj = [PSCustomObject]@{
            Path       = $ConfigFile
            ConfigLine = "Not Found"
        }

        $OutList.Add($NewObj)

        return $OutList
    }

    ForEach ($line in $configLines) {

        $ConfigLine = $line.Line

        $NewObj = [PSCustomObject]@{
            Path       = $ConfigFile
            ConfigLine = $ConfigLine
        }

        $OutList.Add($NewObj)
    }

    return $OutList
}

Function Get-PostgresFormattedOutput {
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $True)]
        [string] $PG_Parameter, ###Define the parameter to check.
        [Parameter(Mandatory = $True)]
        [string] $ExpectedValue, ###Expected value being checked (e.g. True, False, on, off, etc.).
        [Parameter(Mandatory = $True)]
        [string] $DetectedValue ###The value detected by STIG functions/commands.
    )

    Process {
        $Output = "" # Start with a clean slate.
        foreach ($value in $DetectedValue) {
            $Output += "Parameter:`t`t$($PG_Parameter)" | Out-String
            $Output += "Expected Value:`t$($ExpectedValue)" | Out-String
            $Output += "Detected Value:`t$($value)" | Out-String
            $Output += "" | Out-String
        }
        return $Output
    }
}

Function Get-PostgreSQLInstance {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessId,
        [Parameter(Mandatory = $True)]
        [int]$Index
    )

    $ContainerEngine = Get-ContainerEngine
    $ContainerName = $null

    $ProcessString = Get-ProcessString -ProcessId $ProcessId

    if ($ContainerEngine -eq "") {
        $Server = Get-ProcessIPBinding -ProcessId $ProcessID
        $Port = Get-ProcessPortBinding -ProcessId $ProcessID
        $ProcessUser = Get-ProcessUser -ProcessId $ProcessID
        $Executable = Get-ProcessExecPath -ProcessString $ProcessString | Out-NormalizedPath
        $PSQL = Get-PSQL -PostgresExecutablePath $Executable
        $PG_DATA = Get-ProcessParameter -ProcessString $ProcessString -ParameterFlag "-D" | Out-NormalizedPath
        $ODBCData = Get-ODBCData -PgData $PG_DATA
        $PGUser = Get-PGUser -ODBCData $ODBCData
        $Database = Get-PGDatabase -ODBCData $ODBCData
        $PSQLAccess = Test-PSQLAccess -PSQL $PSQL -Database $Database -UserName $PGUser -Port $Port
        $LogDir = Get-PgLogDirectory -PSQL $PSQL -PSQLAccess $PSQLAccess -PG_DATA $PG_DATA -Database $Database -UserName $PGUser -Port $Port
        $LogDest = Get-PgLogDestination -PSQL $PSQL -PSQLAccess $PSQLAccess -Database $Database -UserName $PGUser -Port $Port
    }
    else {
        $ContainerName = Get-ImageContainerName -Engine $ContainerEngine -ImageName postgres
        $Server = Get-ContainerIPBinding -Engine $ContainerEngine -Container $ContainerName
        $Port = Get-ContainerPortBinding -Engine $ContainerEngine -Container $ContainerName
        $ProcessUser = Get-ContainerProcessUser -Engine $ContainerEngine -Container $ContainerName -Process postgres
        $Executable = Get-ProcessExecPath -ProcessString $ProcessString | Out-NormalizedPath
        $PSQL = Invoke-ContainerCommand -Engine $ContainerEngine -Container $ContainerName -Command "find / -name psql -xdev" | head -1

        $QueryResult = Invoke-ContainerCommand -Engine $ContainerEngine -Container $ContainerName -Command "find / -name pg_hba.conf 2>/dev/null"
        $ODBCData = Get-ODBCDataFromString -HbaLines ($queryResult | Out-String)

        $PGUser = Get-PGUser -ODBCData $ODBCData
        $Database = Get-PGDatabase -ODBCData $ODBCData

        $QueryResult = Invoke-ContainerCommand -Engine $ContainerEngine -Container $ContainerName -Command "$PSQL -U $PGUser -p $Port -c 'show data_directory;'"
        $PG_DATA = Get-QueryOutputValue -QueryOutput ($QueryResult | Out-String)

        $QueryResult = Invoke-ContainerCommand -Engine $ContainerEngine -Container $ContainerName -Command "$PSQL -U $PGUser -p $Port -c 'select version();'"

        if ($null -ne $QueryResult) {
            $PSQLAccess = $True
        }
        else {
            $PSQLAccess = $False
        }

        $LogPath = Get-ContainerLogPath -Engine $ContainerEngine -Container $ContainerName
        $LogDir = $LogPath | Split-Path -Parent -ErrorAction SilentlyContinue
        $LogDest = Get-PgLogDestination -PSQL $PSQL -PSQLAccess $PSQLAccess -Database $Database -UserName $PGUser -Port $Port -ContainerEngine $ContainerEngine -ContainerName $ContainerName
    }


    $Instance = [PSCustomObject]@{
        Index           = $Index
        ProcessID       = $ProcessID
        ProcessUser     = $ProcessUser
        PGUser          = $PGUser
        Server          = $Server
        Port            = $Port
        Database        = $Database
        PG_DATA         = $PG_DATA
        LogDir          = $LogDir
        LogDest         = $LogDest
        Executable      = $Executable
        PSQL            = $PSQL
        PSQLAccess      = $PSQLAccess
        ContainerEngine = $ContainerEngine
        ContainerName   = $ContainerName
        ProcessString   = $ProcessString
    }

    return $Instance
}

Function Get-PostgreSQLInstances {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param ()

    $Engine = Get-ContainerEngine

    if ($Engine -ne "") {
        $ContainerName = Get-ImageContainerName -Engine $Engine -ImageName "postgres"
        $postgresPids = Get-ContainerProcessIds -Engine $Engine -ContainerName $ContainerName
    }
    else {
        $postgresPids = Get-PostgreSQLProcessId
    }

    $Index = 0
    [System.Collections.ArrayList]$Instances = @()
    foreach ($postgresPid in $postgresPids) {
        $Instance = Get-PostgreSQLInstance -ProcessId $postgresPid -Index $Index
        [void] $Instances.add($Instance)
        $Index++
    }

    return $Instances
}

Function Get-PostgreSQLProcessId {
    param ()

    if ($IsLinux) {
        $pIds = ps f -opid','cmd -C 'postgres,postmaster' --no-headers | awk '$2 !~ /^(\\_)/ {print $1}'
    }
    else {
        $pIds = Get-ProcessCommandLine -ProcessName "postgres" | ForEach-Object {
            $processId = ($_ -split "\|")[0]
            $cmdLine = ($_ -split "\|")[1]
            if ([string]::IsNullOrEmpty($cmdLine)) {
                $cmdLine = ''
            }

            if ($cmdLine | Select-String -Pattern " -D") {
                Write-Output "$($processId)"
            }
        }
    }

    [System.Collections.ArrayList]$ProcessIds = @()
    foreach ($p in $pIds) {
        [void] $ProcessIds.add($p)
    }

    return $ProcessIds
}

Function Get-ProcessExecPath {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessString
    )

    $processExecPath = ""

    if ($null -ne $ProcessString) {
        $ProcessString = $ProcessString.Trim()

        if ( $processString[0] -eq '"') {
            $processExecPath = ($ProcessString -split '"')[1]
        }
        else {
            $processExecPath = ($ProcessString -split ' ')[0]
        }

        return $processExecPath | Out-NormalizedPath
    }

    return $processExecPath
}

Function Get-ProcessId {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessString
    )

    $processId = ($ProcessString.Trim() -split " ")[0]

    return $processId
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

Function Get-ProcessParameter {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessString,
        [Parameter(Mandatory = $True)]
        [string]$ParameterFlag
    )

    $parameterValuePreSplit = ($processString -split "$($ParameterFlag)")[1].Trim()

    if ($parameterValuePreSplit[0] -eq '"') {
        $parameterValue = ($parameterValuePreSplit -split '"')[1]
        $parameterValue = """$parameterValue"""
    }
    else {
        $parameterValue = ($parameterValuePreSplit -split " ")[0]
    }

    return $parameterValue
}

Function Get-ProcessPortBinding {
    param (
        [Parameter(Mandatory = $True)]
        [string]$ProcessId
    )

    if ($IsLinux) {
        $netstatString = netstat -pant | grep $ProcessId
        $processPort = (((($netstatString -replace '\s+', ' ') -split " ")[3]) -split ":")[1]
    }
    else {
        $processPort = ((((netstat -ano | findstr $ProcessId | findstr "LISTENING" | Select-Object -First 1) -split ":")[1]) -split " ")[0]
    }

    return $processPort
}

Function Get-ProcessString {
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessId
    )

    if ($IsLinux) {
        $processString = ps f -ocmd',' -p $ProcessId --no-headers
    }
    else {
        if (($PsVersionTable.PSVersion).ToString() -match "5.*") {
            $processString = (Get-WmiObject Win32_Process -Filter "ProcessId = '$($ProcessId)'").CommandLine
        }
        else {
            $processString = (Get-Process -Id $ProcessId).CommandLine
        }

    }

    return $processString
}

Function Get-PSQL {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$PostgresExecutablePath
    )

    $BinDir = $PostgresExecutablePath | Split-Path

    if ($IsLinux) {
        $PSQL = Join-Path -Path $BinDir -ChildPath "psql"
    }
    else {
        $PSQL = Join-Path -Path $BinDir -ChildPath "psql.exe"
    }

    if (Test-Path $PSQL) {
        return $PSQL
    }
    else {
        # Return "psql" to use System PATH
        if ($IsLinux) {
            return "psql"
        }
        else {
            return "psql.exe"
        }
    }
}

Function Get-PSQLVariable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]$PG_Parameter
    )

    $Result = $null
    $Query = "SHOW $($PG_Parameter)"

    $Result = Invoke-PSQLQuery -Query $Query | Out-String
    if ($null -eq $Result -or $Result -eq "") {
        return $Result
    }
    else {
        $Errors = Get-SqlError -QueryOutput $Result
        if ($null -ne $Errors -and $Errors -ne "") {
            return $Errors
        }
        else {
            $Result = Get-QueryOutputValue -QueryOutput $Result
            return $Result
        }
    }
}

Function Get-QueryOutputValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [AllowEmptyString()]
        [String]$QueryOutput
    )

    if ($null -eq $QueryOutput -or $QueryOutput -eq "") {
        return "No Value returned from query output"
    } else {
        $From = "-$([System.Environment]::NewLine)"
        $To = "\(\d+ rows{0,1}\)"
        $FromIndex = $QueryOutput.LastIndexOf($From) + $From.Length
        $ToIndex = ($QueryOutput | Select-String -Pattern $To -AllMatches).Matches.Index - 1
        $Result = $QueryOutput.Substring($FromIndex, $ToIndex - $FromIndex)

        return $Result.Trim()
    }
}

Function Get-RandomTableName {
    [CmdletBinding()]
    [OutputType([String])]
    param ()

    $TablePrefix = Get-TableNamePrefix
    $TableSuffix = Get-TableNameSuffix

    return $TablePrefix + '_' + $TableSuffix
}

Function Get-SqlError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]$QueryOutput
    )

    $sqlError = $QueryOutput | Select-String -Pattern "ERROR:.*" | ForEach-Object {((($_.matches).Value -split ':')[1]).Trim()}

    if ( $null -eq $sqlError -or $sqlError -eq "" ) {
        $sqlError = $null
    }
    return $sqlError
}

Function Get-TableNamePrefix {
    [CmdletBinding()]
    [OutputType([String])]
    param ()

    # These are lowercase ascii characters.
    $LowerCaseLetters = @(97..122)
    $TablePrefix = -join ($LowerCaseLetters | Get-Random -Count 10 | ForEach-Object {[char]$_})

    return $TablePrefix
}

Function Get-TableNameSuffix {
    [CmdletBinding()]
    [OutputType([int])]
    param ()

    $MinValue = 1
    $MaxValue = 100000

    if ($MaxValue -lt $MinValue) {
        Write-Error 'Min must be less than Max' -ErrorAction Stop
    }

    # Initialize everything
    $diff = $MaxValue - $MinValue + 1

    [Byte[]] $bytes = 1..4  # 4 byte array for int32/uint32

    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()

    # Generate the number
    $rng.getbytes($bytes)
    $number = [System.BitConverter]::ToUInt32(($bytes), 0)
    $number = $number % $diff + $MinValue

    return $number
}

Function Get-TotalRows {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]$Query
    )

    $DataSet = Get-DataSet -Query $Query

    if ($null -eq $Dataset) {
        return 0
    }

    return ($DataSet.Tables[0]).Rows.Count
}

Function Get-UnixLSFilesToFormat {
    param (
        [Parameter(Mandatory = $True)]
        [string[]] $listing
    )

    $Details = "Owner`t`tPerms`t`tFilename" | Out-String

    foreach ($line in $listing) {
        $perms = ((($line -split "\s+")[0]) -replace "\.")
        $DigitPerms = Set-ModeStringtoDigits -line $perms
        $ListFileName = ($($line -replace '\s+', ' ') -split " ")[8]
        $ListFileOwner = ($($line -replace '\s+', ' ') -split " ")[2]
        $Details += "$ListFileOwner`t`t$DigitPerms`t`t`t$ListFileName" | Out-String
    }

    return $Details
}

Function Invoke-NoOutputQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]$Query
    )

    $QueryOutput = Invoke-PSQLQuery -Query $Query | Out-String
    $NumOfRows = Get-NumOfRows -QueryOutput $QueryOutput
    $Errors = Get-SqlError -QueryOutput $QueryOutput

    $OutputObject = [PSCustomObject]@{
        NumOfRows = $NumOfRows
        Errors    = $Errors
    }

    return $OutputObject
}

Function Invoke-PSQL {
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [string]$PSQL,
        [Parameter(Mandatory = $True)]
        [string]$UserName,
        [Parameter(Mandatory = $True)]
        [string]$Database,
        [Parameter(Mandatory = $True)]
        [int]$Port,
        [Parameter(Mandatory = $True)]
        [string]$Query
    )

    $QueryOutput = ""
    $Output = $null

    try {
        $ErrorOutput = $($Output = & "$PSQL" -U $UserName -d $Database -p $Port -c "$Query") 2>&1
    }
    catch {
    }

    $Result = [PSCustomObject]@{
        Query  = $Query
        Output = $Output
        Error  = $ErrorOutput
    }

    return $Result
}

Function Invoke-PSQLQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [String]$Query,
        [Parameter(Mandatory = $False)]
        [switch]$ExpandTable,
        [Parameter(Mandatory = $False)]
        [String]$User,
        [Parameter(Mandatory = $False)]
        [switch]$DisableRecordLimit
    )

    if ($null -eq $User -or $User -eq "") {
        $User = $PgInstance.PGUser
    }

    if ( $ExpandTable ) {
        $ExpandTableParam = "-x"
    }

    $Result = @()
    $RecordLimit = 50
    $LimitCount = 0

    try {
        if ($PgInstance.ContainerEngine -eq "") {
            $ResultArray = & "$($PgInstance.PSQL)" -p $($PgInstance.Port) -d $($PgInstance.Database) $ExpandTableParam -c "$($Query)" -U $User 2>&1
        }
        else {
            $QueryString = "$($PgInstance.PSQL) -p $($PgInstance.Port) -d $($PgInstance.Database) $ExpandTableParam -c ""$($Query)"" -U $User"
            $ResultArray = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "$QueryString" 2>&1
        }

        foreach ($line in $ResultArray) {
            if ($ExpandTable) {
                if ($line | Select-String -Pattern "\[ RECORD \d{1,2} \]") {
                    $LimitCount++
                }
            }
            else {
                $LimitCount++
            }

            if (-not $DisableRecordLimit -and $LimitCount -gt $RecordLimit) {
                $Result += " " | Out-String
                if ($ExpandTable) {
                    $Result += "Output truncated at 50 Records" | Out-String
                }
                else {
                    $Result += "Output truncated at 50 Lines" | Out-String
                }
                $Result += " " | Out-String
                break
            }

            $Result += $line | Out-String
        }
    }
    catch {
        $Result = $_.Exception.Message
    }

    return $Result
}

Function Set-ModeStringtoDigits {
    Param(
        [Parameter(Mandatory = $True)]
        [string[]] $line
    )

    $Digits = ($line.substring(1)) | sed -re 's/rwx/7/g' -e 's/rw-/6/g' -e 's/r-x/5/g' -e 's/r--/4/g' -e 's/-wx/3/g' -e 's/-w-/2/g' -e 's/--x/1/g' -e 's/---/0/g'

    return $Digits
}

Function Set-PermStringToWindows {
    Param(
        [Parameter(Mandatory = $True)]
        [string] $perm
    )

    $WindowsPerm = "NoPermission"

    switch -Regex ($perm) {
        "[r?]--" {
            $WindowsPerm = "Read"
        }
        "-[w?]-" {
            $WindowsPerm = "Write"
        }
        "--[x?]" {
            $WindowsPerm = "ReadAndExecute"
        } # There is no Execute Only"
        "[r?][w?]-" {
            $WindowsPerm = "Write, Read"
        }
        "[r?]-[x?]" {
            $WindowsPerm = "ReadAndExecute"
        }
        "[r?][w?][x?]" {
            $WindowsPerm = "Write, ReadAndExecute"
        }
    }

    return $WindowsPerm
}

Function Test-Access {
    param (
        [Parameter(Mandatory = $True)]
        [string] $Target,
        [Parameter(Mandatory = $True)]
        [string] $UserName
    )

    $Permission = ((Get-Acl $Target).Access | Where-Object {$_.IdentityReference -match $UserName} | Select-Object FileSystemRights).FileSystemRights

    if ($null -eq $Permission -or $Permission -eq "") {
        return $False
    }
    else {
        return $True
    }
}

Function Test-FileListingToPerms {
    param (
        [Parameter(Mandatory = $True)]
        [string[]] $listing,
        [Parameter(Mandatory = $True)]
        [string] $FilePerms
    )

    foreach ($line in $listing) {
        $perms = ((($line -split "\s+")[0]) -replace "\.")
        if ($perms -notlike $FilePerms ) {
            return $false
        }
    }
    return $true
}

Function Test-FileListingToPermsAndOwner {
    param (
        [Parameter(Mandatory = $True)]
        [string[]] $listing,
        [Parameter(Mandatory = $True)]
        [string] $FileOwner,
        [Parameter(Mandatory = $True)]
        [string] $FilePerms
    )

    $BadOwner = $false
    foreach ($line in $listing) {
        if ($IsLinux) {
            $ListingPerms = ((($line -split "\s+")[0]) -replace "\.")
            $ListingFileOwner = ($($line -replace '\s+', ' ') -split " ")[2]

            if ($ListingPerms -notlike $FilePerms) {
                return $false
            }
        }
        else {
            $IgnoreAccounts = @("NT AUTHORITY\\", "BUILTIN\\Administrators", "CREATOR OWNER")
            $IgnoreRegex = ($IgnoreAccounts | ForEach-Object { "(" + ($_) + ")" }) -join "|"

            $ListingPerms = Get-FileACLs -path $line
            $ListingFileOwner = $ListingPerms.Owner

            if ( $ListingFileOwner -Notmatch $IgnoreRegex ) {
                $BadOwner = $true
            }

            $PermsCheck = Test-WindowsFilePerms -ListingPerms $ListingPerms -FileOwner $FileOwner -FilePerms $FilePerms

            if (-not $PermsCheck) {
                return $false
            }
        }

        if (($ListingFileOwner -ne $FileOwner) -and ($ListingFileOwner -ne $PgInstance.ProcessUser) -and ($BadOwner -eq $true)) {
            return $false
        }
    }

    return $true
}

Function Test-IsADGroup {
    param (
        [Parameter(Mandatory = $True)]
        [string] $GroupName
    )

    $hostname = $env:computername

    if ($GroupName -match $hostname) {
        return $false
    }

    $name = $GroupName -replace "\S*\\"
    $SamObjectClass = ([ADSISEARCHER]"SamAccountName=$($name)").Findone().Properties.objectclass
    $IsGroup = $SamObjectClass | Select-String -Pattern "group"

    if ($null -eq $IsGroup -or $IsGroup -eq "") {
        return $false
    }
    else {
        return $true
    }
}

Function Test-IsADUser {
    param (
        [Parameter(Mandatory = $True)]
        [string] $UserName
    )

    $hostname = $env:computername

    if ($UserName -match $hostname) {
        return $false
    }

    $name = $UserName -replace "\S*\\"
    $SamObjectClass = ([ADSISEARCHER]"SamAccountName=$($name)").Findone().Properties.objectclass
    $IsUser = $SamObjectClass | Select-String -Pattern "user"

    if ($null -eq $IsUser -or $IsUser -eq "") {
        return $false
    }
    else {
        return $true
    }
}

Function Test-IsGroup {
    param (
        [Parameter(Mandatory = $True)]
        [string] $GroupName
    )

    $GroupType = 0

    if ( Test-IsLocalGroup -GroupName $GroupName ) {
        $GroupType = 1
    }
    elseif ( Test-IsADGroup -GroupName $GroupName ) {
        $GroupType = 2
    }

    return $GroupType
}

Function Test-IsLocalGroup {
    param (
        [Parameter(Mandatory = $True)]
        [string] $GroupName
    )

    $name = $GroupName -replace "\S*\\"
    $IsGroup = (Get-LocalGroup | Where-Object {$_.Name -eq "$($name)" } | Select-Object Name).Name

    if ($null -eq $IsGroup -or $IsGroup -eq "") {
        return $false
    }
    else {
        return $true
    }
}

Function Test-IsLocalUser {
    param (
        [Parameter(Mandatory = $True)]
        [string] $UserName
    )

    $name = $UserName -replace "\S*\\"
    $IsUser = (Get-LocalUser | Where-Object {$_.Name -eq "$($name)" } | Select-Object Name).Name

    if ($null -eq $IsUser -or $IsUser -eq "") {
        return $false
    }
    else {
        return $true
    }
}

Function Test-IsUser {
    param (
        [Parameter(Mandatory = $True)]
        [string] $UserName
    )

    $UserType = 0

    if ( Test-IsLocalUser -UserName $UserName ) {
        $UserType = 1
    }
    elseif ( Test-IsADUser -UserName $UserName ) {
        $UserType = 2
    }

    return $UserType
}

Function Test-PSQLAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$PSQL,
        [Parameter(Mandatory = $True)]
        [string]$UserName,
        [Parameter(Mandatory = $True)]
        [string]$Database,
        [Parameter(Mandatory = $True)]
        [int]$Port
    )

    $Success = $false

    try {
        $Result = Invoke-PSQL -PSQL $PSQL -UserName $UserName -Database $Database -Port $Port -Query "SELECT version()"

        if ($null -eq $Result.Error -and $null -ne $Result.Output) {
            $Success = $true
        }
    }
    catch {
    }

    return $Success
}

Function Test-WindowsFilePerms {
    param (
        [Parameter(Mandatory = $True)]
        [System.Collections.Hashtable] $ListingPerms,
        [Parameter(Mandatory = $True)]
        [string] $FileOwner,
        [Parameter(Mandatory = $True)]
        [string] $FilePerms
    )

    $PermissionLevel = @("NoPermission", "Read", "ReadAndExecute", "Write", "Write, Read", "Write, ReadAndExecute", "Modify", "FullControl")
    $IgnoreAccounts = @("NT AUTHORITY\\", "BUILTIN\\Administrators", "CREATOR OWNER")
    $IgnoreRegex = ($IgnoreAccounts | ForEach-Object { "(" + ($_) + ")" }) -join "|"
    $WindowsFullPermissions = @("Modify", "FullControl")
    $WindowsRegex = ($WindowsFullPermissions | ForEach-Object { "(" + ($_) + ")" }) -join "|"
    $LinuxFullPermission = "Write, ReadAndExecute"

    $OwnerPerms = Set-PermStringToWindows -perm $FilePerms.Substring(1, 3)
    $GroupPerms = Set-PermStringToWindows -perm $FilePerms.Substring(4, 3)
    $OtherPerms = Set-PermStringToWindows -perm $FilePerms.Substring(7, 3)


    $OwnerPermissionLevel = $PermissionLevel.IndexOf($OwnerPerms)
    $GroupPermissionLevel = $PermissionLevel.IndexOf($GroupPerms)
    $OtherPermissionLevel = $PermissionLevel.IndexOf($OtherPerms)

    foreach ($account in $ListingPerms.Accounts) {

        if ( $account.Name -match $IgnoreRegex ) {
            continue
        }

        if ( $account.Name -eq $FileOwner ) {
            $FileOwnerPermission = $account.Permission

            if ( $FileOwnerPermission -match $WindowsRegex ) {
                $FileOwnerPermission = $LinuxFullPermission
            }

            $FileOwnerPermissionLevel = $PermissionLevel.IndexOf($FileOwnerPermission)

            if ( $FileOwnerPermissionLevel -gt $OwnerPermissionLevel ) {
                return $false
            }
        }
        else {
            $FileOtherPermission = $account.Permission

            if ( $FileOtherPermission -match $WindowsRegex ) {
                $FileOtherPermission = $LinuxFullPermission
            }

            $FileOtherPermissionLevel = $PermissionLevel.IndexOf($FileOtherPermission)

            if ( $FileOtherPermissionLevel -gt $OtherPermissionLevel ) {
                return $false
            }
        }
    }

    return $true
}

Function Get-V214048 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214048
        STIG ID    : PGS9-00-000100
        Rule ID    : SV-214048r960966_rule
        CCI ID     : CCI-000382, CCI-001762
        Rule Name  : SRG-APP-000142-DB-000094
        Rule Title : PostgreSQL must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
        DiscussMD5 : FCD5962C92E4B55529A6FF58BAA13BD4
        CheckMD5   : EF813357A726AB56AA55A3E115F76365
        FixMD5     : BD977BCA7603A66B5B06884A4B55B5C2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Server:`t$($PgInstance.Server)" | Out-String
    $FindingDetails += "Port:`t`t$($PgInstance.Port)" | Out-String
    $FindingDetails += "" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214049 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214049
        STIG ID    : PGS9-00-000200
        Rule ID    : SV-214049r960903_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-DB-000043
        Rule Title : PostgreSQL must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.
        DiscussMD5 : 04E1419558547041DC36A1B3BD0221D9
        CheckMD5   : 36B1391848765659DD2F686B41EF9E52
        FixMD5     : 017C5113A87F6E36D58ABBD6D5CFCE1D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile -and $PgLogFile -ne "") {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "------------------------------------------------------------------------" | Out-String
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    for ($i = 0 ; $i -lt 3; $i++) {
        #Loop is based on how many queries we have that expect errors.

        # Get the unique table name.
        $RandomTableName = Get-RandomTableName
        $RandomRoleName = Get-RandomTableName
        $FindingDetails += "Table Name:`t`t$($RandomTableName)" | Out-String
        $FindingDetails += "Role Name:`t`t$($RandomRoleName)" | Out-String

        $ErrorQueries = @(
            @"
SET ROLE ${RandomRoleName};
INSERT INTO ${RandomTableName}(id) VALUES (1);
"@,
            @"
SET ROLE ${RandomRoleName};
ALTER TABLE ${RandomTableName} DROP COLUMN name;
"@,
            @"
SET ROLE ${RandomRoleName};
UPDATE ${RandomTableName} SET id = 0 WHERE id = 1;
"@
        )

        $ErrorsToCheck = @(
            "must be owner of relation $($RandomTableName)", # Expect 1 occurance for 9.X
            "permission denied for relation $($RandomTableName)", # Expect 2 occurances for 9.X
            "must be owner of table $($RandomTableName)", # Expect 1 occurance
            "permission denied for table $($RandomTableName)" # Expect 2 occurances

        )

        # This will be run as a user with admin / elevated privs.
        $Query =
        @"
CREATE TABLE ${RandomTableName}(id INT);
INSERT INTO ${RandomTableName}(id) VALUES (0);
ALTER TABLE ${RandomTableName} ADD COLUMN name text;
UPDATE ${RandomTableName} SET id = 1 WHERE id = 0;
CREATE ROLE ${RandomRoleName};
"@

        $QueryResult = Invoke-NoOutputQuery -Query $Query
        # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
        if ($null -ne $QueryResult.Errors) {
            # If we have errors or haven't affected any rows for whatever reason, leave as not reviewed.
            $SetNotReviewed = $true
            break
        }

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQuery = $ErrorQueries[$i]
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $FoundErrorToCheck = ""

            $QueryErrorMessage = $ErrorQueryResult.Errors
            $ErrorToCheck = Get-ErrorToCheck -ExpectedError $ErrorsToCheck -QueryResult $QueryErrorMessage
            if ($null -ne $ErrorToCheck) {
                $IsMatch = $true
            }
            if ($IsMatch) {
                $FoundErrorToCheck = $ErrorToCheck
                if ($IgnoreLogs) {
                    $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                    $FindingDetails += "Query Error:`t`t`"$($QueryErrorMessage)`"" | Out-String
                    $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                    $FindingDetails += "Query:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $ErrorQuery | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $($QueryResult.Errors) | Out-String
                $ErrorCount++
            }
            else {
                if (-not $IgnoreLogs) {
                    # Parse the Query for the error as well.
                    $LogError = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern "${FoundErrorToCheck}"
                    $ErrorToCheck = Get-ErrorToCheck -ExpectedError $ErrorsToCheck -QueryResult $LogError
                    if ($null -eq $ErrorToCheck) {
                        $ErrorCount++
                        $LogError = "Expected Error Not Found"
                    }
                    $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"
                    $FindingDetails += "Log Error:`t`t`t`"$($LogError.Trim())`"" | Out-String
                    $FindingDetails += "Expected Error:`t`"$($ExpectedError)`"" | Out-String
                    $FindingDetails += "Query:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $ErrorQuery | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += $Query | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomTableName};
DROP ROLE ${RandomRoleName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
    }

    if ($SetNotReviewed -eq $true) {
        $FindingDetails += "The initial queries needed to set up the table were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String

        # Always try to drop the tables you attempt to create just in case. We dont' want to leave a mess behind.
        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomTableName};
DROP ROLE ${RandomRoleName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214050 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214050
        STIG ID    : PGS9-00-000300
        Rule ID    : SV-214050r961683_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-DB-000390
        Rule Title : Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).
        DiscussMD5 : 600331300FB18A4E85240F7D3C63FA4B
        CheckMD5   : 5C7832E7B5AA82701E939373C466F727
        FixMD5     : D290D4F5D00CF44AF96B438217478520
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # Some notes about this check.
    # The check shows you how to obtain software versions using APT
    # BUT, running the provided command will not work for some reason.
    # PowerShell will treat 'apt-cache' as a PowerShell command.
    # The psql --version command should be good enough since we know PG
    # Should be running on the target machine.

    if ($IsLinux) {
        if ($PgInstance.ContainerEngine -eq "") {
            $Version = & "$($PgInstance.PSQL)" --version
            $HeaderName = "RPMs"
            $RpmVersion = $(rpm -qa | grep postgres)
        }
        else {
            $Version = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "$($PgInstance.PSQL) --version"
        }
    }
    else {
        $Version = & "$($PgInstance.PSQL)" --version
        $RegPaths = Get-ChildItem "HKLM:\Software\PostgreSQL\Installations"
        foreach ($Path in $RegPaths) {
            $SearchPath = "Registry::$($PATH)"
            $PackageName = Get-ItemPropertyValue -Path $SearchPath -Name "Branding"
            $VersionNum = Get-ItemPropertyValue -Path $SearchPath -Name "Version"
            $RpmVersion += "$PackageName Version: $VersionNum" | Out-String
        }
        $HeaderName = "Installed Versions"
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

Function Get-V214051 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214051
        STIG ID    : PGS9-00-000400
        Rule ID    : SV-214051r960933_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-APP-000119-DB-000060
        Rule Title : The audit information produced by PostgreSQL must be protected from unauthorized modification.
        DiscussMD5 : 394388026D4B0E679DFA1C758CD50107
        CheckMD5   : 07BBB099064B389A2FFF0DC28D7FB7D6
        FixMD5     : 3FC38FA6027223E6ECF542E8D3A3CC9F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PostgresUser = $PgInstance.PGUser
    $PGPerms = "???-------"
    $PG_Parameter = "log_destination"
    $ErrorCount = 0
    $LogDest = $PGInstance.LogDest
    $FindingDetails += "${PG_Parameter}:`t$LogDest" | Out-String

    if ($IsLinux) {
        $IsValid = $LogDest | grep -i -E '(stderr|csvlog)'
    }
    else {
        $IsValid = $LogDest | Select-String -Pattern 'stderr|csvlog'
    }

    if ( $null -eq $IsValid -or $IsValid -eq "" ) {
        $FindingDetails += "Log Destination is not stderr or csvlog, therefore this STIG must be checked manually"
    }
    Else {
        $PG_Parameter = "log_file_mode"
        $LogFileMode = Get-PSQLVariable -PG_Parameter $PG_Parameter
        $FindingDetails += "${PG_Parameter}:`t`t$LogFileMode" | Out-String

        if ( $LogFileMode -ne "0600" ) {
            $ErrorCount++
        }

        $PG_Parameter = "log_directory"
        $LogDir = $PgInstance.LogDir
        $FindingDetails += "${PG_Parameter}:`t`t$LogDir" | Out-String


        if ($IsLinux) {
            if ( Test-Path -Path $LogDir ) {
                if ( $($PgInstance.ContainerEngine) -eq "") {
                    $listing = ls -la $LogDir | grep '^-'
                }
                else {
                    $listing = ls -la $LogDir | grep '^-' | grep '\.log$'
                }
            }
        }
        else {
            if ( Test-Path -Path $LogDir ) {
                $listing = Get-ChildItem -Path "$LogDir" -File | ForEach-Object { $_.FullName }
            }
        }

        if ( $null -ne $listing -and $listing -ne "" ) {
            if ($IsLinux) {
                $FindingDetails += $listing | Out-String
            }
            else {
                $FindingDetails += Get-FormattedFileListing -listing $listing -limit 5 | Out-String
            }

            if ($($PgInstance.ContainerEngine) -eq "") {
                $CheckVar = Test-FileListingToPermsAndOwner -listing $listing -FileOwner $PostgresUser -FilePerms $PGPerms
            }
            else {
                $CheckVar = Test-FileListingToPerms -listing $listing -FilePerms $PGPerms
            }

            if ( -not ( $CheckVar )) {
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "Directory is empty"
            $FindingDetails += "" | Out-String
        }
    }
    if ( $LogDest -eq 'syslog' ) {
        $Status = "Not_Reviewed"
    }
    elseif ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    elseif ( $($PgInstance.ContainerEngine) -eq "" ) {
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

Function Get-V214052 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214052
        STIG ID    : PGS9-00-000500
        Rule ID    : SV-214052r960768_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : PostgreSQL must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.
        DiscussMD5 : E665EADB6467F6F429A4443FF7B27795
        CheckMD5   : 4EB8DE5B9F24D6DE2482F1DF9C41BAC4
        FixMD5     : 5E309C707D837BCA0BC67C788D1BE367
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $PGParameter = "auth-method"
    $ExpectedValues = "gss|sspi|ldap"
    $ExpectedValuesString = "auth-method is gss or sspi or ldap"

    $PgConfigFile = "$($PgInstance.PG_DATA)/pg_hba.conf"
    if ($PgInstance.ContainerEngine -eq "") {
        $ConfigLines = Get-PostgresConfigContent $PgConfigFile
    }
    else {
        $ConfigLines = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "(cat $($PgInstance.PG_DATA)/pg_hba.conf | grep -v '^#' | sed '/^$/d')"
    }
    $FindingDetails += "Parameter:`t`t$($PGParameter)" | Out-String
    $FindingDetails += "Expected Value:`t$($ExpectedValuesString)" | Out-String
    $FindingDetails += "Detected Value:" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "TYPE`tDATABASE`tUSER`tADDRESS`tMETHOD" | Out-String
    ForEach ($line in $ConfigLines) {
        if ($PgInstance.ContainerEngine -eq "") {
            $ConfigLine = $line.ConfigLine | Out-String
        }
        else {
            $ConfigLine = $line | Out-String
        }

       	$FindingDetails += $ConfigLine | Out-String

        if ($ConfigLine | Select-String -Pattern $ExpectedValues -NotMatch) {
            $ErrorCount++
        }
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

Function Get-V214053 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214053
        STIG ID    : PGS9-00-000600
        Rule ID    : SV-214053r961167_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-DB-000162
        Rule Title : PostgreSQL must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
        DiscussMD5 : 62C2AC0114B3E348D66E44A7865B6FA9
        CheckMD5   : B9328CEEF6716AC8668ABE0C1FB17D73
        FixMD5     : 20E5CA5CF56D5C58DB2F677D03D37A85
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "client_min_messages"
    $ExpectedValue = "error"

    $DetectedValue = Get-PSQLVariable -PG_Parameter $PG_Parameter

    $IsValid = $DetectedValue | Select-String -Pattern "$($ExpectedValue)"

    if ( $null -eq $IsValid -or $IsValid -eq "" ) {
        $ErrorCount++
    }

    $FindingDetails += "Parameter:`t`t$($PG_Parameter)" | Out-String
    $FindingDetails += "Expected Value:`t$($ExpectedValue)" | Out-String
    $FindingDetails += "Detected Value:`t$($DetectedValue)" | Out-String

    If ($ErrorCount -ge 1) {
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

Function Get-V214054 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214054
        STIG ID    : PGS9-00-000700
        Rule ID    : SV-214054r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : Privileges to change PostgreSQL software modules must be limited.
        DiscussMD5 : 89F84CF161AC31A6B0B744BE6E2FB9BE
        CheckMD5   : 7E388ABF76C027D280F65737AED883D9
        FixMD5     : B58B33083ACCAB2E739EC3F2BBBE0C49
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PostgresUser = $PgInstance.PGUser
    $ErrorCount = 0
    $PGPerms = "????????-?"
    $IndPath = "$($PgInstance.PG_Data)"
    $LibraryFiles = @()
    if ($isLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $LibraryFiles += ls -l $IndPath 2>/dev/null | grep '^-'
        }
        else {
            $LibraryFiles += Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -l $IndPath 2>/dev/null | grep '^-'"
        }
    }
    else {
        $LibraryFiles += Get-ChildItem -Path "$IndPath" -File | ForEach-Object { $_.FullName }
    }
    $FindingDetails += "$($IndPath):" | Out-String
    if ( $null -eq $LibraryFiles -or ($LibraryFiles | Measure-Object).Count -eq 0 ) {
        $FindingDetails += "No Shared Libraries Detected" | Out-String
    }
    else {
        if ($IsLinux) {
            $FindingDetails += $LibraryFiles | Out-String
        }
        else {
            $FindingDetails += Get-FormattedFileListing -listing $LibraryFiles -limit 5 | Out-String
        }
        $CheckVar = Test-FileListingToPermsAndOwner -listing $LibraryFiles -FileOwner $PostgresUser -FilePerms $PGPerms
        if ( -not ( $CheckVar )) {
            $ErrorCount++
        }
    }
    $FindingDetails += "" | Out-String

    if ($isLinux) {
        $CheckPath = ("/usr/pgsql-*", "/usr/pgsql-*/bin", "/usr/pgsql-*/include", "/usr/pgsql-*/lib", "/usr/pgsql-*/share")
    }
    else {
        $CheckPath = ($IndPath.replace('data', ''), $IndPath.replace('data', 'bin'), $IndPath.replace('data', 'include'), $IndPath.replace('data', 'lib'), $IndPath.replace('data', 'share'))
    }

    foreach ($IndPath in $CheckPath) {
        $LibraryFiles = @()
        if ($isLinux) {
            if ($($PgInstance.ContainerEngine) -eq "") {
                $LibraryFiles += ls -l $IndPath 2>/dev/null | grep '^-'
            }
            else {
                $LibraryFiles += Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -l $IndPath 2>/dev/null | grep '^-'"
            }
        }
        else {
            $LibraryFiles += Get-ChildItem -Path "$IndPath" -File | ForEach-Object { $_.FullName }
        }
        $FindingDetails += "$($IndPath):" | Out-String
        if ( $null -eq $LibraryFiles -or ($LibraryFiles | Measure-Object).Count -eq 0 ) {
            $FindingDetails += "No Shared Libraries Detected" | Out-String
        }
        else {
            if ($IsLinux) {
                $FindingDetails += $LibraryFiles | Out-String
            }
            else {
                $FindingDetails += Get-FormattedFileListing -listing $LibraryFiles -limit 5 | Out-String
            }
            $CheckVar = Test-FileListingToPermsAndOwner -listing $LibraryFiles -FileOwner 'root' -FilePerms $PGPerms
            if ( -not ( $CheckVar )) {
                $ErrorCount++
            }
        }
        $FindingDetails += "" | Out-String
    }
    if ($ErrorCount -gt 0) {
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

Function Get-V214055 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214055
        STIG ID    : PGS9-00-000710
        Rule ID    : SV-214055r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : PostgreSQL must limit privileges to change functions and triggers, and links to software external to PostgreSQL.
        DiscussMD5 : 4F8565AE31D2B70BB252BFF32B57F46C
        CheckMD5   : BC74286595C2E7FF8F98931140E6EF98
        FixMD5     : F40599CA0B772083AE5C623436B34183
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PGPerms = "?????-??-?"
    $ErrorCount = 0
    $Query = "\df+"
    if ($($PgInstance.ContainerEngine) -eq "") {
        $ResultArray = Invoke-PSQLQuery -ExpandTable -Query $Query
    }
    else {
        $ResultArray = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "$($PgInstance.PSQL) -U $($PgInstance.PgUser) -p $($PgInstance.Port) -c '\df+' "
    }
    $FindingDetails += "List of Functions, Triggers, and Trigger Procedures" | Out-String

    if ($null -eq $ResultArray -or $ResultArray -eq "" ) {
        $FindingDetails += "None Found" | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        foreach ($line in $ResultArray) {
            if ($line -eq "(0 rows)") {
                $FindingDetails += "None Found" | Out-String
                $FindingDetails += "" | Out-String
                break
            }
            else {
                if ($line.StartsWith('Name')) {
                    $FindingDetails += $line -replace '\s+\|\s*', ":`t" | Out-String
                    continue
                }
                if ($line.StartsWith('Owner')) {
                    if ( -not ( $line | Select-String -Pattern "\|\s+$($PgInstance.PGUser)" )) {
                        $ErrorCount++
                    }
                    $FindingDetails += $line -replace '\s+\|\s*', ":`t" | Out-String
                    $FindingDetails += "" | Out-String
                    continue
                }
            }
        }
    }

    if ($IsLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $listing = ls -la $($PgInstance.PG_DATA) | grep '^-'
        }
        else {
            $listing = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -la $($PgInstance.PG_DATA) | grep '^-' "
        }
    }
    else {
        $listing = Get-ChildItem -Path $($PgInstance.PG_DATA) -File | ForEach-Object { $_.FullName }
    }

    if ( $null -ne $listing -and $listing -ne "" ) {
        $FindingDetails += "Database Configuration Files:" | Out-String
        $FindingDetails += "" | Out-String
        if ($IsLinux) {
            $FindingDetails += $listing | Out-String
        }
        else {
            $FindingDetails += Get-FormattedFileListing -listing $listing -limit 10 | Out-String
        }
        $PostgresUser = "$PgInstance.PGUser"
        $PermTest = Test-FileListingToPermsAndOwner -listing $listing -FileOwner $PostgresUser -FilePerms $PGPerms

        if ( -not ( $PermTest )) {
            $ErrorCount++
        }
    }

    If ($ErrorCount -ge 1) {
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

Function Get-V214056 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214056
        STIG ID    : PGS9-00-000800
        Rule ID    : SV-214056r961029_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-APP-000172-DB-000075
        Rule Title : If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of passwords.
        DiscussMD5 : 10BD84D7388DB62A28812F01C140D7F4
        CheckMD5   : 2DD212E6F42EA7E2865D99EC58F1CDA8
        FixMD5     : E4447BB0C7ECA9D03E143BABB6FD370A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $PGParameter = "auth-method"
    $ExpectedValue = "password"
    $ExpectedValueString = "auth_method is not password"

    $PgConfigFile = "$($PgInstance.PG_DATA)/pg_hba.conf"
    if ($($PgInstance.ContainerEngine) -eq "") {
        $ConfigLines = Get-PostgresConfigContent $PgConfigFile
    }
    else {
        $ConfigLines = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $PgInstance.ContainerName -Command "(cat $($PgInstance.PG_DATA)/pg_hba.conf | grep -v '^#' | sed '/^$/d')"
    }
    $FindingDetails += "Parameter:`t`t$($PGParameter)" | Out-String
    $FindingDetails += "Expected Value:`t$($ExpectedValueString)" | Out-String
    $FindingDetails += "Detected Value:" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "TYPE`tDATABASE`tUSER`tADDRESS`tMETHOD" | Out-String
    ForEach ($line in $ConfigLines) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $ConfigLine = $line.ConfigLine | Out-String
        }
        else {
            $ConfigLine = $line | Out-String
        }
        $FindingDetails += $ConfigLine | Out-String
        if ($ConfigLine | Select-String -Pattern $ExpectedValue) {
            $ErrorCount++
        }
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

Function Get-V214057 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214057
        STIG ID    : PGS9-00-000900
        Rule ID    : SV-214057r960792_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-DB-000084
        Rule Title : PostgreSQL must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
        DiscussMD5 : 9C4388F59FA1E65C017D222168F2733A
        CheckMD5   : CD77743ACA37353B279C24054BF9D1F3
        FixMD5     : E67A87903000157C5F314A398F89B133
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DBQuery = '\du'
    $DBArray = Invoke-PSQLQuery -ExpandTable -Query $DBQuery

    $FindingDetails += "Privileges of all roles in the database" | Out-String
    foreach ($line in $DBArray) {
        $FindingDetails += $line | Out-String
    }
    $FindingDetails += "" | Out-String

    $TCQuery = '\dp'
    $TCArray = Invoke-PSQLQuery -ExpandTable -Query $TCQuery

    $FindingDetails += "Privileges for tables and columns" | Out-String
    foreach ($line in $TCArray) {
        $FindingDetails += $line | Out-String
    }
    $FindingDetails += "" | Out-String

    if ($($PgInstance.ContainerEngine) -eq "") {
        $PgConfigFile = "$($PGInstance.PG_DATA)/pg_hba.conf"
        $ConfigLines = Get-PostgresConfigContent $PgConfigFile
    }
    else {
        $ConfigLines = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $PgInstance.ContainerName -Command "(cat $($PgInstance.PG_DATA)/pg_hba.conf | grep -v '^#' | sed '/^$/d')"
    }

    $FindingDetails += "Configured authentication settings" | Out-String
    $FindingDetails += "TYPE  DATABASE        USER            ADDRESS                 METHOD" | Out-String
    foreach ($line in $ConfigLines) {
        if ($PgInstance.ContainerEngine -eq "") {
            $FindingDetails += $line.ConfigLine | Out-String
        }
        else {
            $FindingDetails += $line | Out-String
        }
    }
    $FindingDetails += "" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214059 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214059
        STIG ID    : PGS9-00-001200
        Rule ID    : SV-214059r960735_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-DB-000031
        Rule Title : PostgreSQL must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.
        DiscussMD5 : C90DBB63A8EBA84509D83F48370C1334
        CheckMD5   : 51DCA6D8FA8EF420B4DCD4A148E1D005
        FixMD5     : 62F9856C49CDF87ED01DB4A95615E6D5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "max_connections"
    $DetectedValue = Get-PSQLVariable -PG_Parameter $PG_Parameter
    $ExpectedValue = "$($PG_Parameter) not exceed the organizations documentation"
    $FindingDetails += "Parameter:`t`t$($PG_Parameter)" | Out-String
    $FindingDetails += "Expected Value:`t$($ExpectedValue)" | Out-String
    $FindingDetails += "Detected Value:`t$($DetectedValue)`n" | Out-String

    if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
        $ErrorCount++
    }

    $PG_Parameter = "rolconnlimit"
    $ExpectedValue = "$($PG_Parameter) not equal '-1' and not exceed the organizations documentation"
    $Query = "SELECT rolname,$($PG_Parameter) from pg_authid"

    $DetectedValue = Invoke-PSQLQuery -Query $Query

    $FindingDetails += "Parameter:`t`t$PG_Parameter" | Out-String
    $FindingDetails += "Expected Value:`t$($ExpectedValue)" | Out-String
    $FindingDetails += "Detected Value:" | Out-String

    foreach ( $row in $DetectedValue ) {
        $FindingDetails += "$($row)" | Out-String

        if (($row | Select-String -Pattern '\s-1\b' | Measure-Object).Count -ge 1 ) {
            $ErrorCount++
        }
    }

    If ($ErrorCount -ge 1) {
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

Function Get-V214060 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214060
        STIG ID    : PGS9-00-001300
        Rule ID    : SV-214060r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000362
        Rule Title : The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (functions, trigger procedures, links to software external to PostgreSQL, etc.) must be restricted to authorized users.
        DiscussMD5 : C5584BF02D99F2E08453776929643B87
        CheckMD5   : BB9E19D9FCE87D8C00D2DEEEB8AD427F
        FixMD5     : A93B3040C97E3E8EACD056EF0C156EAD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DBQuery = "\dp *.*"

    $ResultArray = Invoke-PSQLQuery -Query $DBQuery

    foreach ($line in $ResultArray) {
        $FindingDetails += $line | Out-String
    }

    $FindingDetails += "Directory:`t`t$($PgInstance.PG_DATA)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Database Directory Permissions" | Out-String
    $FindingDetails += "" | Out-String
    if ($IsLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $listing = ls -la $($PgInstance.PG_DATA) | grep '^-'
        }
        else {
            $listing = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -la $($PgInstance.PG_DATA) | grep '^-' "
        }
    }
    else {
        $listing = Get-ChildItem -Path $($PgInstance.PG_DATA) -File | ForEach-Object { $_.FullName }
    }
    if ( $null -ne $listing -and $listing -ne "" ) {
        if ($IsLinux) {
            $FindingDetails += $listing | Out-String
        }
        else {
            $FindingDetails += Get-FormattedFileListing -listing $listing -limit 10 | Out-String
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

Function Get-V214061 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214061
        STIG ID    : PGS9-00-001400
        Rule ID    : SV-214061r961053_rule
        CCI ID     : CCI-000804
        Rule Name  : SRG-APP-000180-DB-000115
        Rule Title : PostgreSQL must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).
        DiscussMD5 : 7EEAE3D6C16255ACD47852D639397EF1
        CheckMD5   : EB9C6CF45B1D4B5494B2F24F2520FB73
        FixMD5     : 64EAE44CF1EBC0840D7FCB51C0B79559
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DBQuery = '\du'
    $DBArray = Invoke-PSQLQuery -ExpandTable -Query $DBQuery

    foreach ($line in $DBArray) {
        $FindingDetails += $line | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214067 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214067
        STIG ID    : PGS9-00-002200
        Rule ID    : SV-214067r961317_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-APP-000328-DB-000301
        Rule Title : PostgreSQL must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.
        DiscussMD5 : 597921AC57B1918582E4F7C64889A15B
        CheckMD5   : 81C0336EC91F2DFFEF822C01BB33841C
        FixMD5     : B3543E20D72C5B5AC216EC49907EE946
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Query = @("\dn *.*", "\dt *.*", "\ds *.*", "\dv *.*", "\df+ *.*")


    foreach ($command in $Query) {
        $FindingDetails += "Meta Command:`t$($command)" | Out-String
        $FindingDetails += "------------------------------------------------------" | Out-String
        $ResultArray = Invoke-PSQLQuery -ExpandTable -Query $command
        $FindingDetails += $ResultArray | Out-String

        if ($ResultArray -match "No matching relations found") {
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

Function Get-V214068 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214068
        STIG ID    : PGS9-00-002300
        Rule ID    : SV-214068r960936_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-DB-000061
        Rule Title : The audit information produced by PostgreSQL must be protected from unauthorized deletion.
        DiscussMD5 : A613A5A959FF699E11BB058A051FABDB
        CheckMD5   : 1FF563FF12CD3E391210C58156E2CD35
        FixMD5     : 3FC38FA6027223E6ECF542E8D3A3CC9F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PostgresUser = $PgInstance.PGUser
    $PGPerms = "???-------"
    $PG_Parameter = "log_destination"
    $ErrorCount = 0
    $LogDest = $PGInstance.LogDest
    $FindingDetails += "${PG_Parameter}:`t$LogDest" | Out-String

    if ($IsLinux) {
        $IsValid = $LogDest | grep -i -E '(stderr|csvlog)'
    }
    else {
        $IsValid = $LogDest | Select-String -Pattern 'stderr|csvlog'
    }

    if ( $null -eq $IsValid -or $IsValid -eq "" ) {
        $FindingDetails += "Log Destination is not stderr or csvlog, therefore this STIG must be checked manually"
    }
    Else {
        $PG_Parameter = "log_file_mode"
        $LogFileMode = Get-PSQLVariable -PG_Parameter $PG_Parameter
        $FindingDetails += "${PG_Parameter}:`t`t$LogFileMode" | Out-String

        if ( $LogFileMode -ne "0600" ) {
            $ErrorCount++
        }

        $PG_Parameter = "log_directory"
        $LogDir = $PgInstance.LogDir
        $FindingDetails += "${PG_Parameter}:`t`t$LogDir" | Out-String
        $FindingDetails += "" | Out-String

        if ($IsLinux) {
            if ( Test-Path -Path $LogDir ) {
                if ( $($PgInstance.ContainerEngine) -eq "") {
                    $listing = ls -la $LogDir | grep '^-'
                }
                else {
                    $listing = ls -la $LogDir | grep '^-' | grep '.log'
                }
            }
        }
        else {
            if ( Test-Path -Path $LogDir ) {
                $listing = Get-ChildItem -Path "$LogDir" -File | ForEach-Object { $_.FullName }
            }
        }

        if ( $null -ne $listing -and $listing -ne "" ) {
            if ($IsLinux) {
                $FindingDetails += $listing | Out-String
            }
            else {
                $FindingDetails += Get-FormattedFileListing -listing $listing -limit 5 | Out-String
            }

            if ($($PgInstance.ContainerEngine) -eq "") {
                $CheckVar = Test-FileListingToPermsAndOwner -listing $listing -FileOwner $PostgresUser -FilePerms $PGPerms
            }
            else {
                $CheckVar = Test-FileListingToPerms -listing $listing -FilePerms $PGPerms
            }

            if ( -not ( $CheckVar )) {
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "Directory is empty"
            $FindingDetails += "" | Out-String
        }
    }

    if ( $LogDest -eq 'syslog' ) {
        $Status = "Not_Reviewed"
    }
    elseif ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    elseif ($($PgInstance.ContainerEngine) -eq "") {
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

Function Get-V214069 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214069
        STIG ID    : PGS9-00-002400
        Rule ID    : SV-214069r961443_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-APP-000374-DB-000322
        Rule Title : PostgreSQL must record time stamps, in audit records and application data, that can be mapped to Coordinated Universal Time (UTC, formerly GMT).
        DiscussMD5 : E6BFA14D3EE56217C563D5B2108BFB6F
        CheckMD5   : CEC32E53556AE1AFACE4F898379BCBCE
        FixMD5     : 02286EE43AB5315956F23FF7D94114BE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PG_Parameter = "log_timezone"
    $DetectedValue = Get-PSQLVariable -PG_Parameter $PG_Parameter
    $ExpectedValue = "Set to the desired time zone."

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214070 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214070
        STIG ID    : PGS9-00-002500
        Rule ID    : SV-214070r961170_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-DB-000163
        Rule Title : PostgreSQL must reveal detailed error messages only to the ISSO, ISSM, SA and DBA.
        DiscussMD5 : D982F0C3E40619E14A5F11BF5C1B25EE
        CheckMD5   : F3B713576CB407AC93F67FA532964128
        FixMD5     : 49784B5DE99396905F457F5E993B0F88
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "client_min_messages"
    $ExpectedValuesString = "$($PG_Parameter) not set to LOG or DEBUG"
    $ClientMessages = Get-PSQLVariable -PG_Parameter $PG_Parameter
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $ClientMessages

    if ( $ClientMessages -match '(LOG|DEBUG)' ) {
        $ErrorCount++
    }

    $PG_Parameter = "log_destination"
    $LogDest = $PgInstance.LogDest
    $FindingDetails += "Detected ${PG_Parameter}:`t$LogDest" | Out-String
    $LogAutoCheck = $LogDest | Select-String -Pattern "stderr"
    if ( $null -eq $LogAutoCheck -or $LogAutoCheck -eq "" ) {
        $FindingDetails += "Log Destination is not stderr, therefore this STIG must be checked manually"
    }
    Else {
        $PG_Parameter = "log_file_mode"
        $LogFileMode = Get-PSQLVariable -PG_Parameter $PG_Parameter
        if ( $LogFileMode -ne "0600" ) {
            $ErrorCount++
        }
        $FindingDetails += "Expected ${PG_Parameter}:`t`t0600" | Out-String
        $FindingDetails += "Detected ${PG_Parameter}:`t`t$LogFileMode" | Out-String
        $PG_Parameter = "log_directory"
        $LogDir = $PgInstance.LogDir
        $FindingDetails += "${PG_Parameter}:`t`t`t`t$LogDir" | Out-String
        $FindingDetails += "" | Out-String
        if ($IsLinux) {
            if ( Test-Path -Path $LogDir ) {
                if ($($PgInstance.ContainerEngine) -eq "") {
                    $listing = ls -la $LogDir | grep '^-'
                }
                else {
                    $FindingDetails += "" | Out-String
                    $listing = ls -la $LogDir | grep '^-' | grep '.log'
                }
            }
        }
        else {
            if ( Test-Path -Path $LogDir ) {
                $listing = Get-ChildItem -Path "$LogDir" -File | ForEach-Object { $_.FullName }
            }
        }
        $FindingDetails += "" | Out-String

        if ( $null -ne $listing -and $listing -ne "" ) {
            $PGPerms = "-rw-------"
            if ($IsLinux) {
                $FindingDetails += $listing | Out-String
            }
            else {
                $FindingDetails += Get-FormattedFileListing -listing $listing -limit 5 | Out-String
            }
            if ($($PGInstance.ContainerEngine) -eq "") {
                $PermTest = Test-FileListingToPermsAndOwner -listing $listing -FileOwner $PgInstance.Database -FilePerms $PGPerms
            }
            else {
                $PermTest = Test-FileListingToPerms -listing $listing -FilePerms $PGPerms
            }

            if ( -not ( $PermTest )) {
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "Directory is empty"
            $ErrorCount++
        }
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

Function Get-V214071 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214071
        STIG ID    : PGS9-00-002600
        Rule ID    : SV-214071r960882_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : PostgreSQL must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
        DiscussMD5 : 399867828DF606C19B45A8014399DEE3
        CheckMD5   : 5F3FE8AF61361B06675FBE0C5B7727B2
        FixMD5     : 5648B293589B3EEB7ACA291851487BB9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PGUser = $PgInstance.PGUser
    $IgnoreAccounts = @("NT AUTHORITY\\", "BUILTIN\\Administrators", "CREATOR OWNER")
    $IgnoreRegex = ($IgnoreAccounts | ForEach-Object { "(" + ($_) + ")" }) -join "|"

    if ($IsLinux) {
        $FindingDetails += "Directory:`t`t$($PgInstance.PG_DATA)" | Out-String
        $FindingDetails += "" | Out-String

        if ($PgInstance.ContainerEngine -eq "") {
            $listing = ls -la $($PgInstance.PG_DATA) | grep '^-' | Out-String
        }
        else {
            $listing = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "ls -la $($PgInstance.PG_DATA) | grep '^-'" 2>&1 | Out-String
        }
        foreach ($line in $Listing) {
            $ListFileOwner = ($($line -replace '\s+', ' ') -split " ")[2]
            if ($ListFileOwner -ne $PGUser) {
                $ErrorCount++
            }
        }
    }
    else {
        $FullListing = Get-ChildItem -Path $($PgInstance.PG_DATA) -File | ForEach-Object { $_.FullName }
        foreach ($file in $FullListing) {
            $FileOwner = Get-Acl -Path $file
            $listing += "File:`t`t$file" | Out-String
            $listing += "Owner:`t$($FileOwner.owner)" | Out-String
            $listing += "" | Out-String
            if (($FileOwner.owner -notmatch $IgnoreRegex) -and ($FileOwner.owner -ne $PGUser)) {
                $ErrorCount++
            }
        }
    }

    $FindingDetails += $listing
    $FindingDetails += "" | Out-String

    $DBQuery = '\du'
    $FindingDetails += "Meta Command:`t$($DBQuery)" | Out-String
    $FindingDetails += "------------------------------------------------------" | Out-String
    $SearchPattern = 'Attributes.*Superuser'
    $FindingDetails += 'Roles with Superuser rights' | Out-String
    $FindingDetails += Get-PgRecordFromMeta -Command $DBQuery -SearchPattern $SearchPattern

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

Function Get-V214073 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214073
        STIG ID    : PGS9-00-003000
        Rule ID    : SV-214073r961641_rule
        CCI ID     : CCI-002422
        Rule Name  : SRG-APP-000442-DB-000379
        Rule Title : PostgreSQL must maintain the confidentiality and integrity of information during reception.
        DiscussMD5 : A790D02729C95C8F3F3AB74E19824D18
        CheckMD5   : D411D04C807B3D8FAFDE84BA7C73423F
        FixMD5     : C8DD5F5FF5F499CDF2878D7FA3D56B03
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SSLErrorCount = 0
    $HostSSLErrorCount = 0

    $QuerySetting = "ssl"
    $ExpectedValuesString = "$($QuerySetting) is enabled (on)"
    $Result = Get-PSQLVariable -PG_Parameter $QuerySetting
    if ($null -eq $Result -or $Result -eq "") {
        $SSLErrorCount++
        $Result = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $QuerySetting -ExpectedValue $ExpectedValuesString -DetectedValue $Result
    }
    else {
        if ($Result | Select-String -Pattern "on" -NotMatch) {
            $SSLErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $QuerySetting -ExpectedValue $ExpectedValuesString -DetectedValue $Result
    }

    $ExpectedValues = "hostssl"
    $ExpectedInclude = "clientcert\s*=\s*1"
    $ExpectedValuesString = "Config lines must be type 'hostssl' and contain clientcert=1."

    $PgConfigFile = "$($PgInstance.PG_DATA)/pg_hba.conf"
    $ConfigLines = Get-PostgresConfigContent -ConfigFile $PgConfigFile

    $FindingDetails += "Parameter:`t`t$($ExpectedValues)" | Out-String
    $FindingDetails += "Expected Value:`t($ExpectedValuesString)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Detected Value:" | Out-String
    $FindingDetails += "TYPE    DATABASE        USER            ADDRESS                 METHOD" | Out-String

    ForEach ($line in $ConfigLines) {
        if ($line.ConfigLine | Select-String -Pattern $ExpectedValues -NotMatch) {
            $HostSSLErrorCount++
        }
        elseif ($line.ConfigLine | Select-String -Pattern $ExpectedInclude -NotMatch) {
            $HostSSLErrorCount++
        }
        $FindingDetails += "$($line.ConfigLine)" | Out-String
    }

    if ($SSLErrorCount -eq 0) {
        if ($HostSSLErrorCount -eq 0) {
            $Status = "NotAFinding"
        }
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

Function Get-V214074 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214074
        STIG ID    : PGS9-00-003100
        Rule ID    : SV-214074r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000200
        Rule Title : Database objects (including but not limited to tables, indexes, storage, trigger procedures, functions, links to software external to PostgreSQL, etc.) must be owned by database/DBMS principals authorized for ownership.
        DiscussMD5 : 3E1B11E2057A590F89F7B91CCF314A0C
        CheckMD5   : 62566E4C8ACACBF40F61A626B23F48F2
        FixMD5     : 95833A061105C0CA451B6E6B18090926
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Query = @("\dn *.*", "\dt *.*", "\ds *.*", "\dv *.*", "\df+ *.*")


    foreach ($command in $Query) {
        $FindingDetails += "Meta Command:`t$($command)" | Out-String
        $FindingDetails += "------------------------------------------------------" | Out-String
        $ResultArray = Invoke-PSQLQuery -ExpandTable -Query $command
        $FindingDetails += $ResultArray | Out-String

        if ($ResultArray -match "No matching relations found") {
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

Function Get-V214078 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214078
        STIG ID    : PGS9-00-003600
        Rule ID    : SV-214078r961359_rule
        CCI ID     : CCI-002233
        Rule Name  : SRG-APP-000342-DB-000302
        Rule Title : Execution of software modules (to include functions and trigger procedures) with elevated privileges must be restricted to necessary cases only.
        DiscussMD5 : 229B6584844B51FBD5100834815C0A97
        CheckMD5   : 7E8297335F66935ADDBE0BC048FEABB2
        FixMD5     : F060E1FCD11C1C82C1D55B850315FB07
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Query = "SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL"
    $ResultArray = Invoke-PSQLQuery -ExpandTable -Query $Query
    $FindingDetails += "Query:`t${Query}" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output:" | Out-String
    $FindingDetails += "" | Out-String

    foreach ( $row in $ResultArray ) {
        $FindingDetails += $row | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214079 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214079
        STIG ID    : PGS9-00-003700
        Rule ID    : SV-214079r961656_rule
        CCI ID     : CCI-002754
        Rule Name  : SRG-APP-000447-DB-000393
        Rule Title : When invalid inputs are received, PostgreSQL must behave in a predictable and documented manner that reflects organizational and system objectives.
        DiscussMD5 : 9751414306E0BC7AEA44463D8903C55A
        CheckMD5   : CACFD6851E46B9490D688FBE273E6493
        FixMD5     : 06DC3AE9AB45B65FC838F21EB7E3E2BE
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t`t`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t`t`t$PgLogFile" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $FindingDetails += "" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $IgnoreLogs = $true
    }

    $RandomTableName = Get-RandomTableName
    $Query = "CREATE TABLE$RandomTableName(id INT)"
    $ErrorToCheck = "syntax error at or near \`"TABLE$RandomTableName\`""
    $ErrorQueryResult = Invoke-NoOutputQuery -Query $Query

    if ($IgnoreLogs) {
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "$ErrorToCheck" | Out-String
    }
    else {

        if ($null -ne $ErrorQueryResult.Errors) {

            $LogError = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern "${ErrorToCheck}"
            $linenumber = Select-String -Path $PgLogFile -Pattern $ErrorToCheck | Select-Object -Last 1
            $FormattedError = "syntax error at or near `"TABLE$RandomTableName`""
            $ExpectedError = "ERROR:`t$($FormattedError)"
            $FindingDetails += "Query:`t`t`t$Query" | Out-String
            $FindingDetails += "Expected Error:`t`"$($ExpectedError)`"" | Out-String
            $FindingDetails += "Log Error:`t`t`t`"$($LogError.Trim())`"" | Out-String
            $FindingDetails += "Log Line Number:`t$($linenumber.LineNumber)" | Out-String
        }

        else {
            $FindingDetails += "The following query was expected to generate an error in the logs, but did not:" | Out-String
            $FindingDetails += $Query | Out-String
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

Function Get-V214080 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214080
        STIG ID    : PGS9-00-003800
        Rule ID    : SV-214080r981952_rule
        CCI ID     : CCI-001844
        Rule Name  : SRG-APP-000356-DB-000314
        Rule Title : PostgreSQL must utilize centralized management of the content captured in audit records generated by all components of PostgreSQL.
        DiscussMD5 : 520E107CB185EE0EFC5C71545C9F5568
        CheckMD5   : BE82B3DD83371E792F0FDCEE999CFF90
        FixMD5     : 9F0B93C5B378FA84171E25A37A3FDA28
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PG_Parameter = "log_destination"
    $LogDest = $PgInstance.LogDest
    $FindingDetails += "${PG_Parameter}:`t$($LogDest)" | Out-String

    $PG_Parameter = "syslog_facility"
    $SysLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    $FindingDetails += "${PG_Parameter}:`t`t$($SysLog)" | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214081 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214081
        STIG ID    : PGS9-00-004000
        Rule ID    : SV-214081r961131_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-DB-000124
        Rule Title : PostgreSQL must isolate security functions from non-security functions.
        DiscussMD5 : 96601656FB09FC51FD270C0059FDAC9E
        CheckMD5   : 74DE0FCE056217DF3938216146D6427B
        FixMD5     : 1A936599DA4A2B482C597B1E1929BDDD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MetaCommands = @('\dp pg_catalog.*', '\dp information_schema.*', '\df+ pg_catalog.*', '\df+ information_schema.*')
    foreach ($metaCommand in $MetaCommands) {
        $Result = Invoke-PSQLQuery -ExpandTable -Query $metaCommand

        $FindingDetails += "Command:`t$($metaCommand)" | Out-String
        $FindingDetails += "------------------------------------------------------------" | Out-String
        $FindingDetails += "" | Out-String

        if ($null -eq $Result -or $Result -eq "") {
            $FindingDetails += "This command produced no output."
        }
        else {
            # We have some sort of output.
            $FindingDetails += $Result | Out-String
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

Function Get-V214082 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214082
        STIG ID    : PGS9-00-004100
        Rule ID    : SV-214082r981958_rule
        CCI ID     : CCI-001814
        Rule Name  : SRG-APP-000381-DB-000361
        Rule Title : PostgreSQL must produce audit records of its enforcement of access restrictions associated with changes to the configuration of PostgreSQL or database(s).
        DiscussMD5 : FE6AAC9595961F4C8AF1B9D2C1035A0A
        CheckMD5   : 47AFB28E17C0ADE36A1C669E1BE74956
        FixMD5     : 45AFEE361A59AC3E78DE4D7D546D3A5C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "------------------------------------------------------------------------" | Out-String
        $IgnoreLogs = $true
        $SetNotReviewed = $true
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------" | Out-String

    # Get the unique table name.
    $RandomRoleName = Get-RandomTableName
    $FindingDetails += "Role Name:`t`t$($RandomRoleName)" | Out-String
    # Get the unique table name.
    $RandomRoleName2 = Get-RandomTableName
    $FindingDetails += "Test Role Name:`t$($RandomRoleName2)" | Out-String
    $FindingDetails += "" | Out-String
    # This will be run as a user with admin / elevated privs.
    $Query =
    @"
CREATE ROLE ${RandomRoleName};
"@

    $QueryResult = Invoke-NoOutputQuery -Query $Query
    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }
    else {
        $ErrorToCheck = "permission denied to set parameter `"pgaudit.role`""
        $LogErrorToCheck = "permission denied to set parameter \`"pgaudit.role\`""
        $StatementToCheck = "SET pgaudit.role='${RandomRoleName2}'"
        $ErrorQuery =
        @"
SET ROLE ${RandomRoleName};
SET pgaudit.role='${RandomRoleName2}';
"@

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $QueryErrorMessage = $ErrorQueryResult.Errors
            $FindingDetails += "Query Error Message:`t$($QueryErrorMessage)" | Out-String
            $IsMatch = $QueryErrorMessage.Contains($ErrorToCheck)
            if ($IsMatch) {
                if ($IgnoreLogs) {
                    $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                    $FindingDetails += "Query Error:`t`"$($QueryErrorMessage)`"" | Out-String
                    $FindingDetails += "Expected Error:`t`t$($ExpectedError)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $($QueryResult.Errors) | Out-String
                $ErrorCount++
            }
            else {
                # Parse the Query for the error as well.
                $LogError = Get-PgErrorFromLogWithContext -LogPath $PgLogFile -StatementPattern "${StatementToCheck}" -ErrorPattern "${LogErrorToCheck}"
                $ExpectedError = "ERROR:`t$($LogErrorToCheck)"

                If ($null -eq $LogError -or $LogError -eq "") {
                    $IgnoreLogs = $true
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Please check your log files for the following entries:" | Out-String
                    $FindingDetails += "Error Statement:`t`t$($StatementToCheck)" | Out-String
                    $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                }
                Else {
                    $FindingDetails += "Log Error:`t`t`t`t`"$($LogError.Trim())`"" | Out-String
                    $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += $ErrorQuery | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropRoleQuery =
        @"
RESET ROLE;
DROP ROLE ${RandomRoleName};
"@

        # Yeet the role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery
        if ($null -ne $DropQueryResult.Errors) {
            $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" was unsucessful." | Out-String
            $FindingDetails += "The role will need to be dropped manually." | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
        }
    }

    $PGPerms = "-rw-------"
    $PgConfigFile = "$($PgInstance.PG_DATA)/postgresql.conf"
    if ($isLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $listing = ls -la $($PgConfigFile)
        }
        else {
            $listing = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -la $PgConfigFile"
        }
    }
    else {
        $listing += Get-ChildItem -Path "$PgConfigFile" -File | ForEach-Object { $_.FullName }
    }
    $FindingDetails += ""
    $FindingDetails += "PostgreSQL Configuration File" | Out-String
    $PermTest = Test-FileListingToPermsAndOwner -listing $listing -FileOwner $PgInstance.ProcessUser -FilePerms $PGPerms

    if ( -not ( $PermTest )) {
        $ErrorCount++
    }
    if ($IsLinux) {
        $FindingDetails += $listing | Out-String
    }
    else {
        $FindingDetails += Get-FormattedFileListing -listing $listing -limit 5 | Out-String
    }
    $FindingDetails += "" | Out-String

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214083 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214083
        STIG ID    : PGS9-00-004200
        Rule ID    : SV-214083r960930_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-DB-000059
        Rule Title : The audit information produced by PostgreSQL must be protected from unauthorized read access.
        DiscussMD5 : 5EE5D77A854CE8D0BAF5559E081F3ED3
        CheckMD5   : 7E012E4EB4225D002335823B2BE56B58
        FixMD5     : 8FF6A4A90A3AFD229E08F68AFAB8FE20
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PGUser = $PgInstance.PGUser
    $PGPerms = "???-------"
    $ErrorCount = 0
    $PG_Parameter = "log_destination"
    $LogDest = $PgInstance.LogDest
    $FindingDetails += "${PG_Parameter}:`t$LogDest" | Out-String

    if ($IsLinux) {
        $IsValid = $LogDest | grep -i -E '(stderr|csvlog)'
    }
    else {
        $IsValid = $LogDest | Select-String -Pattern 'stderr|csvlog'
    }

    if ( $null -eq $IsValid -or $IsValid -eq "" ) {
        $FindingDetails += "Log Destination is not stderr or csvlog, therefore this STIG must be checked manually"
    }
    else {
        $PG_Parameter = "log_file_mode"
        $LogFileMode = Get-PSQLVariable -PG_Parameter $PG_Parameter
        $FindingDetails += "${PG_Parameter}:`t`t$LogFileMode" | Out-String
        if ( $LogFileMode -ne "0600" ) {
            $ErrorCount++
        }
        $PG_Parameter = "log_directory"
        $LogDir = $PgInstance.LogDir
        $FindingDetails += "${PG_Parameter}:`t`t$LogDir" | Out-String
        $FindingDetails += "" | Out-String

        if ( Test-Path -Path $LogDir ) {

            if ($IsLinux) {
                $listing = ls -l $LogDir | grep '^-'
            }
            else {
                $listing = Get-ChildItem -Path "$LogDir" -File | ForEach-Object { $_.FullName }
            }

            $FindingDetails += "Directory:`t`t`t$LogDir" | Out-String
        }
        else {
            $FullLogDir = "$($PgInstance.PG_DATA)/$LogDir" | Out-NormalizedPath
            if ( Test-Path -Path $FullLogDir ) {
                if ($IsLinux) {
                    $listing = ls -l $FullLogDir | grep '^-'
                }
                else {
                    $listing = Get-ChildItem -Path "$FullLogDir" -File | ForEach-Object { $_.FullName }
                }

                $FindingDetails += "Directory:`t`t`t$FullLogDir" | Out-String
                $FindingDetails += "" | Out-String
            }
            else {
                $FindingDetails += "Log Directory does not exist"
                $FindingDetails += "" | Out-String
                $ErrorCount++
            }
        }
        if ( $null -ne $listing -and $listing -ne "" ) {
            if ($IsLinux) {
                if ( $($PgInstance.ContainerEngine) -eq "") {
                    $listing = ls -la $LogDir | grep '^-'
                }
                else {
                    $listing = ls -la $LogDir | grep '^-' | grep '\.log$'
                }
                $FindingDetails += $listing | Out-String
                foreach ( $line in $listing ) {
                    $perms = ($line -split " ")[0]
                    $ModePerms = Set-ModeStringtoDigits -line $perms
                    $IntModePerms = [int]$ModePerms
                    $IntLogFileMode = [int]$LogFileMode
                    if ( $IntModePerms -ne $IntLogFileMode ) {
                        $ErrorCount++
                    }
                }
            }
            else {
                $FindingDetails += Get-FormattedFileListing -listing $listing -limit 5 | Out-String
                foreach ($line in $listing) {
                    $ListingPerms = Get-FileACLs -path $line
                    $LogFilePerms = Test-WindowsFilePerms -ListingPerms $ListingPerms -FileOwner $PGUser -FilePerms $PGPerms
                    if ($LogFilePerms -eq $false) {
                        $ErrorCount++
                        break
                    }
                }
            }
        }
        else {
            $FindingDetails += "Directory is empty"
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        if ( $ErrorCount -gt 0 ) {
            $Status = "Open" # Log directory is empty or mode of logs files does not match config file
        }
        else {
            $Status = "NotAFinding" # Mode is 0600 and files in log dir match these permissions
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

Function Get-V214084 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214084
        STIG ID    : PGS9-00-004300
        Rule ID    : SV-214084r961677_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-APP-000454-DB-000389
        Rule Title : When updates are applied to PostgreSQL software, any software components that have been replaced or made unnecessary must be removed.
        DiscussMD5 : 607571937F91B16199ADF0160546FB8A
        CheckMD5   : DFD7A4A1428452576056179912400074
        FixMD5     : 9E47D3DFD6568840209BA7097E96D2FD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
        if ($($PgInstance.ContainerEngine) -eq "") {
            $Packages = sudo rpm -qa | grep postgres | Out-String

            $DupPackages = rpm -qai | grep postgres | grep -i Name | sort | uniq -D
            if ($null -eq $DupPackages -or $DupPackages -eq "") {
                $Status = "NotAFinding"
            }
        }
        else {
            $pkgQueryCmds = @("apt list", "rpm -qa", "dpkg -l", "yum list installed")
            foreach ($pkgCmd in $pkgQueryCmds) {
                $CmdResult = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "$pkgCmd 2>/dev/null | grep postgres" | Out-String -ErrorAction SilentlyContinue
                if ($null -ne $CmdResult -and $CmdResult -ne "") {
                    $Packages = $CmdResult
                    break
                }
            }
        }

        if ($null -ne $Packages -and $Packages -ne "") {
            $FindingDetails += "Packages:" | Out-String
            $FindingDetails += $Packages
        }
        else {
            $FindingDetails = "No packages containing the text postgres found on this system."
        }
    }
    else {
        $RegPaths = Get-ChildItem "HKLM:\Software\PostgreSQL\Installations"
        foreach ($Path in $RegPaths) {
            $SearchPath = "Registry::$($Path)"
            $PackageName = Get-ItemPropertyValue -Path $SearchPath -Name "Branding"
            $VersionNum = Get-ItemPropertyValue -Path $SearchPath -Name "Version"
            $RpmVersion += "$PackageName Version: $VersionNum" | Out-String
        }
        $HeaderName = "Installed Versions"
        if ($null -ne $RpmVersion -and $RpmVersion -ne "") {
            $FindingDetails += "$($HeaderName):" | Out-String
            foreach ($rpm in $RpmVersion) {
                $FindingDetails += "$($rpm)" | Out-String
            }
        }
        if ($RegPaths.count -le 1) {
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

Function Get-V214085 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214085
        STIG ID    : PGS9-00-004400
        Rule ID    : SV-214085r961797_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000494-DB-000344
        Rule Title : PostgreSQL must generate audit records when categorized information (e.g., classification levels/security levels) is accessed.
        DiscussMD5 : F44617087F7F84FCE843ABA1F9186C40
        CheckMD5   : 8C82F5D8836FE980577E4FE14177A3A5
        FixMD5     : 33EAD2D72A2410625FEDA2231ED7FD78
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "$($PG_Parameter) must contain ddl, write, role"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214086 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214086
        STIG ID    : PGS9-00-004500
        Rule ID    : SV-214086r961791_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000492-DB-000333
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to access security objects occur.
        DiscussMD5 : 1AD56A0F3CE469EC0902F82BE0A0C7ED
        CheckMD5   : C7C99FEC5AD294C174083421DBD65AA6
        FixMD5     : 90479827782499CE29F72B96534C2A01
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "------------------------------------------------------------------------" | Out-String
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    for ($i = 0 ; $i -lt 8; $i++) {
        #Loop is based on how many queries we have that expect errors.

        # Get the unique table name.
        $RandomTableName = Get-RandomTableName
        $RandomRoleName = Get-RandomTableName
        $RandomSchemaName = Get-RandomTableName
        $FindingDetails += "Schema Name:`t$($RandomSchemaName)" | Out-String
        $FindingDetails += "Table Name:`t`t$($RandomTableName)" | Out-String
        $FindingDetails += "Role Name:`t`t$($RandomRoleName)" | Out-String

        $ErrorQueries = @(
            @"
SET ROLE ${RandomRoleName};
CREATE TABLE ${RandomSchemaName}.${RandomTableName}(id INT);
"@,
            @"
SET ROLE ${RandomRoleName};
INSERT INTO ${RandomSchemaName}.${RandomTableName}(id) VALUES (0);
"@,
            @"
SET ROLE ${RandomRoleName};
SELECT * FROM ${RandomSchemaName}.${RandomTableName};
"@,
            @"
SET ROLE ${RandomRoleName};
ALTER TABLE ${RandomSchemaName}.${RandomTableName} ADD COLUMN name TEXT;
"@,
            @"
SET ROLE ${RandomRoleName};
UPDATE ${RandomSchemaName}.${RandomTableName} SET id = 1 WHERE id = 0;
"@,
            @"
SET ROLE ${RandomRoleName};
DELETE FROM ${RandomSchemaName}.${RandomTableName} WHERE id = 0;
"@,
            @"
SET ROLE ${RandomRoleName};
PREPARE stig_test_plan(int) AS SELECT id FROM ${RandomSchemaName}.${RandomTableName} WHERE id=`$1;
"@,
            @"
SET ROLE ${RandomRoleName};
DROP TABLE ${RandomSchemaName}.${RandomTableName};
"@
        )

        $ErrorToCheck = "permission denied for schema ${RandomSchemaName}"

        # This will be run as a user with admin / elevated privs.
        $Query =
        @"
CREATE SCHEMA ${RandomSchemaName} AUTHORIZATION $($PgInstance.PGUser);
REVOKE ALL ON SCHEMA ${RandomSchemaName} FROM public;
GRANT ALL ON SCHEMA ${RandomSchemaName} TO $($PgInstance.PGUser);
CREATE TABLE ${RandomSchemaName}.${RandomTableName}(id INT);
INSERT INTO ${RandomSchemaName}.${RandomTableName}(id) VALUES (0);
CREATE ROLE ${RandomRoleName};
"@

        $QueryResult = Invoke-NoOutputQuery -Query $Query
        # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
        if ($null -ne $QueryResult.Errors) {
            # If we have errors or haven't affected any rows for whatever reason, leave as not reviewed.
            $SetNotReviewed = $true
            break
        }

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQuery = $ErrorQueries[$i]
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $FoundErrorToCheck = ""

            $QueryErrorMessage = $ErrorQueryResult.Errors
            $IsMatch = $QueryErrorMessage.Contains($ErrorToCheck)

            if ($IsMatch) {
                $FoundErrorToCheck = $ErrorToCheck
                if ($IgnoreLogs) {
                    $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                    $FindingDetails += "Query Error:`t`t`"$($QueryErrorMessage)`"" | Out-String
                    $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                    $FindingDetails += "Query:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $ErrorQuery | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $ErrorQuery | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "------------------------------------------------------------------------" | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
            }
            else {
                # Parse the Query for the error as well.
                if (-not $IgnoreLogs) {
                    $LogError = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern "${FoundErrorToCheck}"
                    $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"
                    $FindingDetails += "Log Error:`t`t`t`"$($LogError.Trim())`"" | Out-String
                    $FindingDetails += "Expected Error:`t`"$($ExpectedError)`"" | Out-String
                    $FindingDetails += "Query:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $ErrorQuery | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Query | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "------------------------------------------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomSchemaName}.${RandomTableName};
DROP ROLE ${RandomRoleName};
DROP SCHEMA ${RandomSchemaName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
    }

    if ($SetNotReviewed -eq $true) {
        $FindingDetails += "The initial queries needed to set up the table were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String

        # Always try to drop the tables you attempt to create just in case. We dont' want to leave a mess behind.
        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomTableName};
DROP ROLE ${RandomRoleName};
DROP SCHEMA ${RandomSchemaName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $Query
    }

	if ($($PgInstance.ContainerEngine) -ne "") {
		$SetNotReviewed = $true
	}

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214087 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214087
        STIG ID    : PGS9-00-004600
        Rule ID    : SV-214087r961824_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-DB-000351
        Rule Title : PostgreSQL must generate audit records when unsuccessful logons or connection attempts occur.
        DiscussMD5 : 6286794FC812DFF19E7CFBF7D0A4D94F
        CheckMD5   : B240016E1B23E9EE65333E2A1996DBAB
        FixMD5     : A95CF7AD4393CDB2BD7E71FC836CF45B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $UseLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
            $UseLogs = $true
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Log Destination is not stderr or csvlog, therefore this STIG must be checked manually"
    }

    if ( $UseLogs ) {
        $RandomRoleName = Get-RandomTableName
        $ErrorPrep = "`"${RandomRoleName}`""
        $ErrorToCheck = "role `"${RandomRoleName}`" does not exist"
        $ReturnString = $(Invoke-PSQLQuery -ExpandTable -User ${RandomRoleName}) 2>&1
        $LogError = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern ".*${ErrorPrep}"
        $ErrorQuery = "$($PgInstance.PSQL) -p $($PgInstance.Port) -d $($PgInstance.Database) -U ${RandomRoleName}"
        $FindingDetails += "" | Out-String
        $FindingDetails += "Login Attempt:`t$($ErrorQuery)" | Out-String

        if ( $ReturnString -match $ErrorToCheck ) {
            if ($null -ne $LogError -and $LogError -ne "") {
                $MatchesError = [bool]($LogError | Select-String -Pattern ".*$($ErrorToCheck)" -Quiet)
                if ($MatchesError -eq $true) {
                    $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                    $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                    $FindingDetails += "Query Error:`t`t$($ReturnString)" | Out-String
                    $FindingDetails += "Log Error:`t`t`t$($LogError)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                else {
                    $FindingDetails += "Could not find matching error for:" | Out-String
                    $FindingDetails += $ReturnString | Out-String
                    $ErrorCount++
                }
            }
            else {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $ReturnString | Out-String
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "The following login attempt was expected to generate an error but did not:" | Out-String
            $FindingDetails += $ErrorQuery | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
        if ( $UseLogs ) {
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

Function Get-V214088 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214088
        STIG ID    : PGS9-00-004700
        Rule ID    : SV-214088r961830_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000505-DB-000352
        Rule Title : PostgreSQL must generate audit records showing starting and ending time for user access to the database(s).
        DiscussMD5 : A41D29A665399D62CD6E03E7C70088A0
        CheckMD5   : D89D7D3F32A451EA7284CA79990AEDD0
        FixMD5     : 4F368CFF97A892CAA0C9D67F74D87CCD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`t`tNot Found" | Out-String
            $IgnoreLogs = $True
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $IgnoreLogs = $True
    }

    #Create a role with ability to login
    $RandomRoleName = Get-RandomTableName
    $ErrorQuery = "CREATE ROLE ${RandomRoleName} WITH LOGIN;"
    $QueryResult1 = Invoke-NoOutputQuery -Query $ErrorQuery

    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult1.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }

    else {
        #Run a query as user to generate connection activity

        $Command = "\q"
        $LoginAttempt = Invoke-PSQLQuery -ExpandTable -Query $Command -User ${RandomRoleName}
        #Drop role we created
        $DropRoleQuery = "DROP ROLE ${RandomRoleName};"
        $DropQueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery

        if ($null -ne $DropQueryResult.Errors) {
            $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" was unsucessful." | Out-String
            $FindingDetails += "The role will need to be dropped manually." | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
        }

        $FindingDetails += "User:`t${RandomRoleName}" | Out-String
        $FindingDetails += "" | Out-String

        if ($IgnoreLogs) {
            $FindingDetails += "Please check your log files for connection activity for user=${RandomRoleName}" | Out-String
        }
        else {

            $Connection += (Select-String -Path $pgLogFile -Pattern "connection\sauthorized:\suser=${RandomRoleName}").line
            $Disconnection += (Select-String -Path $pgLogFile -Pattern "disconnection:.*user=${RandomRoleName}").line

            if ( $null -eq $Connection -or $Connection -eq "" ) {
                $ErrorCount++
                $FindingDetails += "" | Out-String
                $FindingDetails += "Connection activity could not be found" | Out-String
            }
            else {
                $FindingDetails += "Connection:`t${Connection}" | Out-String
                $FindingDetails += "" | Out-String
            }
            if ( $null -eq $Disconnection -or $Disconnection -eq ""  ) {
                $ErrorCount++
                $FindingDetails += "" | Out-String
                $FindingDetails += "Disconnection activity could not be found" | Out-String
            }
            else {
                $FindingDetails += "Disconnection:`t${Disconnection}" | Out-String
            }
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214089 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214089
        STIG ID    : PGS9-00-004800
        Rule ID    : SV-214089r961803_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000496-DB-000335
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to modify security objects occur.
        DiscussMD5 : 1CA738C156715E0D25202DDA25D0E9C8
        CheckMD5   : FBDE4E53778199BE306FB50698A860AC
        FixMD5     : FBBA8CFAABD08FE38FBC527CC78A4502
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    # Get the unique table name.
    $RandomRoleName = Get-RandomTableName

    # This will be run as a user with admin / elevated privs.
    $Query =
    @"
CREATE ROLE ${RandomRoleName};
"@

    $QueryResult = Invoke-NoOutputQuery -Query $Query
    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }
    else {

        $ErrorsToCheck = @("permission denied for relation pg_authid", "permission denied for table pg_authid")
        $StatementToCheck = "UPDATE pg_authid SET rolsuper='t' WHERE rolname='${RandomRoleName}'"
        $ErrorQuery =
        @"
SET ROLE ${RandomRoleName};
UPDATE pg_authid SET rolsuper='t' WHERE rolname='${RandomRoleName}';
"@

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $FoundErrorToCheck = ""

            $QueryErrorMessage = $ErrorQueryResult.Errors
            $FindingDetails += "Query Error Message:`t$($QueryErrorMessage)" | Out-String
            $ErrorToCheck = Get-ErrorToCheck -ExpectedError $ErrorsToCheck -QueryResult $QueryErrorMessage
            if ($null -ne $ErrorToCheck) {
                $IsMatch = $true
            }
            if ($IsMatch) {
                $FoundErrorToCheck = $ErrorToCheck
                if ($IgnoreLogs) {
                    $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                    $FindingDetails += "Query Error:`t`"$($QueryErrorMessage)`"" | Out-String
                    $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $($QueryResult.Errors) | Out-String
                $ErrorCount++
            }
            else {
                # Parse the Query for the error as well.
                $LogError = Get-PgErrorFromLogWithContext -LogPath $PgLogFile -StatementPattern "${StatementToCheck}" -ErrorPattern "${FoundErrorToCheck}"
                $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"

                If ($null -eq $LogError -or $LogError -eq "") {
                    $IgnoreLogs = $true
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Please check your log files for the following entries:" | Out-String
                    $FindingDetails += "Error Statement:`t`t$($StatementToCheck)" | Out-String
                    $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                }
                Else {
                    $FindingDetails += "Log Error:`t`t`t`t`"$($LogError.Trim())`"" | Out-String
                    $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += $ErrorQuery | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropRoleQuery =
        @"
RESET ROLE;
DROP ROLE ${RandomRoleName};
"@

        # Yeet the role we created.
        $DropQueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery
        if ($null -ne $DropQueryResult.Errors) {
            $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" was unsucessful." | Out-String
            $FindingDetails += "The role will need to be dropped manually." | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214090 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214090
        STIG ID    : PGS9-00-004900
        Rule ID    : SV-214090r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000326
        Rule Title : PostgreSQL must generate audit records when privileges/permissions are added.
        DiscussMD5 : CFC6815B3BC9190229BAFC8258743157
        CheckMD5   : AE31D170558DE3EFF7AE1E4705BF9F11
        FixMD5     : A00FC53EA3207795232F4E13129DB3F7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    $LogDir = $PgInstance.LogDir
    $RandomRoleName = Get-RandomTableName
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t`t`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t`t`t$PgLogFile" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $FindingDetails += "" | Out-String
            $IgnoreLogs = $true
        }
        $FindingDetails += "Role Name:`t`t$($RandomRoleName)" | Out-String
        $FindingDetails += "" | Out-String
        }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Log Destination is not stderr or csvlog, therefore this STIG must be checked manually"
        $FindingDetails += "" | Out-String
        $IgnoreLogs = $true
    }


    # This will be run as a user with admin / elevated privs.
    $Queries = @(
        @"
CREATE ROLE ${RandomRoleName};
"@,
        @"
GRANT CONNECT ON DATABASE $($PgInstance.Database) TO ${RandomRoleName};
"@,
        @"
REVOKE CONNECT ON DATABASE $($PgInstance.Database) FROM ${RandomRoleName};
"@
    )

    for ($i = 0 ; $i -lt $Queries.Length; $i++) {
        $QueryResult = Invoke-NoOutputQuery -Query $Queries[$i]
        # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
        if ($null -ne $QueryResult.Errors) {
            # If we have errors, leave as not reviewed.
            $FindingDetails += "The initial queries needed to setup this STIG were unsucessful." | Out-String
            $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Query:`t`t`t$($Queries[$i])" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
            $SetNotReviewed = $true
            break;
        }
        else {
            if (-not $IgnoreLogs) {
                if ($i -eq 0) {
                    #Do not check log on first query
                    continue
                }

                switch ($i) {
                    1 {
                        $LogToCheck = "SESSION,\d+,\d+,ROLE,GRANT,,,$($Queries[$i])"
                    }
                    2 {
                        $LogToCheck = "SESSION,\d+,\d+,ROLE,REVOKE,,,$($Queries[$i])"
                    }
                }

                $LogMessage = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern "${LogToCheck}"
                if ($LogMessage.length -eq 0) {
                    $LogEntry = "Not Found"
                    $ErrorCount++
                }
                else {
                    $LogEntry = ($LogMessage -split '\n')[0]
                }

                $ExpectedEntry = "AUDIT:`t$($LogToCheck)"
                $FindingDetails += "Query:`t`t`t$($Queries[$i])" | Out-String
                $FindingDetails += "Log Entry:`t`t`t`"$($LogEntry.Trim())`"" | Out-String
                $FindingDetails += "Expected Entry:`t`"$($ExpectedEntry)`"" | Out-String
                $FindingDetails += "------------------------------------------------------------------------" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }

    $DropRoleQuery =
    @"
RESET ROLE;
DROP ROLE ${RandomRoleName};
"@

    # Yeet the role we created.
    $QueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery
    if ($null -ne $DropQueryResult.Errors) {
        $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" was unsucessful." | Out-String
        $FindingDetails += "The role will need to be dropped manually." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214091 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214091
        STIG ID    : PGS9-00-005000
        Rule ID    : SV-214091r961821_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000502-DB-000349
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 6E9B8A9CF78C65F0893B04FF96814119
        CheckMD5   : 247FE7E7FA062020162C14D8E321BC34
        FixMD5     : 0489A7049C311E0D20B2A7BED7BE958D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "$($PG_Parameter) must contain ddl, write, role"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214092 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214092
        STIG ID    : PGS9-00-005100
        Rule ID    : SV-214092r961824_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-DB-000350
        Rule Title : PostgreSQL must generate audit records when successful logons or connections occur.
        DiscussMD5 : 26CAE17257C7EFB4C9382870A1BEA61F
        CheckMD5   : EB6F7C8D09B5D98ED317293D18B59016
        FixMD5     : 61570991CBE886B43A74B5307196BCDD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SetNotReviewed = $false
    $IgnoreLogs = $false
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t`t`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t`t`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`t`t`tNot Found" | Out-String
            $IgnoreLogs = $True
        }
    }
    else {
        $FindingDetails += "Log Dir:`t`t`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t`t`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $IgnoreLogs = $True
    }

    $ErrorCount = 0
    $ExpectedValuesString = "on"
    $PG_Parameter = "log_connections"

    #Create a role with ability to login
    $RandomRoleName = Get-RandomTableName
    $ErrorQuery = "CREATE ROLE ${RandomRoleName} WITH LOGIN;"
    $QueryResult1 = Invoke-NoOutputQuery -Query $ErrorQuery

    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult1.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }

    else {
        #Run a query as user to generate connection activity
        $Command = "SHOW $PG_PARAMETER"
        $Connections = ((Invoke-PSQLQuery -ExpandTable -Query $Command -User ${RandomRoleName}) -split '\|').Trim()[2]
        if ($null -eq $Connections -or $Connections -eq "") {
            $ErrorCount++
            $Connections = "Not Found"
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }
        else {
            $Checker = $Connections | Select-String -Pattern $ExpectedValuesString
            if ( $null -eq $Checker -or $Checker -eq "" ) {
                $ErrorCount++
            }
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }

        #Drop role we created
        $DropRoleQuery = "DROP ROLE ${RandomRoleName};"
        $DropQueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery

        if ($null -ne $DropQueryResult.Errors) {
            $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" was unsucessful." | Out-String
            $FindingDetails += "The role will need to be dropped manually." | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
        }

        $FindingDetails += "User:`t`t`t${RandomRoleName}" | Out-String

        if ($IgnoreLogs) {
            $FindingDetails += "Please check your log files for connection activity for user=${RandomRoleName}" | Out-String
        }
        else {

            $Connection += (Select-String -Path $pgLogFile -Pattern "connection\sauthorized:\suser=${RandomRoleName}").line

            if ( $null -eq $Connection -or $Connection -eq "" ) {
                $ErrorCount++
                $FindingDetails += "" | Out-String
                $FindingDetails += "Connection activity could not be found" | Out-String
            }
            else {
                $FindingDetails += "Connection:`t`t${Connection}" | Out-String
            }
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214093 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214093
        STIG ID    : PGS9-00-005200
        Rule ID    : SV-214093r961818_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000501-DB-000336
        Rule Title : PostgreSQL must generate audit records when security objects are deleted.
        DiscussMD5 : D3D8462AEFD0044E8CE7A1D481C3A580
        CheckMD5   : C3066E496A6664105F89D4A4B31E3115
        FixMD5     : 62B766D57416644ACD6DA5756F94FF76
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false
    $QueryError = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "" | Out-String
        $IgnoreLogs = $true
        $SetNotReviewed = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    for ($i = 0 ; $i -lt 2; $i++) {
        #Loop is based on how many queries we have that expect errors.

        # Get the unique table name.
        $RandomTableName = Get-RandomTableName
        $FindingDetails += "Table Name:`t$($RandomTableName)" | Out-String
        $FindingDetails += "" | Out-String

        $LogQueries = @(
            @"
DROP POLICY lock_table ON ${RandomTableName};
"@,
            @"
ALTER TABLE ${RandomTableName} DISABLE ROW LEVEL SECURITY;
"@
        )

        $LogLinesToCheck = @(
            "DROP POLICY lock_table ON ${RandomTableName}", # Expect 1 occurance
            "ALTER TABLE ${RandomTableName} DISABLE ROW LEVEL SECURITY" # Expect 1 occurances
        )

        # This will be run as a user with admin / elevated privs.
        $Query =
        @"
CREATE TABLE ${RandomTableName}(id INT);
ALTER TABLE ${RandomTableName} ENABLE ROW LEVEL SECURITY;
CREATE POLICY lock_table ON ${RandomTableName} USING ('$($PgInstance.ProcessUser)' = current_user);
"@

        $QueryResult = Invoke-NoOutputQuery -Query $Query
        # Check to see if we have any errors. If we have, we know our initial queries failed.
        if ($null -ne $QueryResult.Errors) {
            # If we have errors or haven't affected any rows for whatever reason, leave as not reviewed.
            $SetNotReviewed = $true
            $QueryError = $true
            break
        }

        # Assume our query was successful and continue on to the rest of the check
        $LogQuery = $LogQueries[$i]
        $LogQueryResult = Invoke-NoOutputQuery -Query $LogQuery

        if (-not $IgnoreLogs) {
            # We do not want to see any errors.
            if ($null -eq $LogQueryResult.Errors) {

                # Continue to check the errors generated from the query.
                $TrueLog = ""
                foreach ($LogToCheck in $LogLinesToCheck) {
                    $SomeLog = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern $LogToCheck
                    if ($SomeLog.Length -gt 0) {
                        # If we get here it means our array is populated and we found something.
                        $TrueLog = $SomeLog
                        break
                    }
                }

                if ($TrueLog -ne "") {
                    $FindingDetails += "Log Entry:`t`t`"$($TrueLog)`"" | Out-String
                    $FindingDetails += "Query:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $LogQuery | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------" | Out-String
                    $FindingDetails += "" | Out-String
                }
                else {
                    $ErrorCount++
                    $FindingDetails += "Could not find matching log entry for:" | Out-String
                    $FindingDetails += $LogQuery | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "------------------------------------------------------------------------" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            else {
                $ErrorCount++
                $FindingDetails += "The following query was not expected to generate an error but did:" | Out-String
                $FindingDetails += $LogQuery | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "------------------------------------------------------------------------" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "Query:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $LogQuery | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "------------------------------------------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
        }

        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomTableName};
"@

        # Yeet the table role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
    }

    if ($QueryError -eq $true) {
        $FindingDetails += "The initial queries needed to set up the table were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String

        # Always try to drop the tables you attempt to create just in case. We dont' want to leave a mess behind.
        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomTableName};
"@

        # Yeet the table we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214094 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214094
        STIG ID    : PGS9-00-005300
        Rule ID    : SV-214094r960885_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-DB-000325
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.
        DiscussMD5 : EEBE01DE1EB0118EFDDBB6D9AB86DC0E
        CheckMD5   : 9D37CD6DDE5423AE9BA5F3EEF5BA13A3
        FixMD5     : DF4F421DCA6F52707C8800BBC6DA8D26
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }

    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    # Get the unique table name.
    $RandomRoleName = Get-RandomTableName

    # This will be run as a user with admin / elevated privs.
    $Query =
    @"
CREATE ROLE ${RandomRoleName};
"@

    $QueryResult = Invoke-NoOutputQuery -Query $Query
    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }
    else {

        $ErrorsToCheck = @("permission denied for relation pg_authid", "permission denied for table pg_authid")
        $StatementToCheck = "SET ROLE ${RandomRoleName};"
        $ErrorQuery =
        @"
SET ROLE ${RandomRoleName};
SELECT * FROM pg_authid;
"@

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $FoundErrorToCheck = ""

            $QueryErrorMessage = $ErrorQueryResult.Errors
            $FindingDetails += "Query Error Message :`t$($QueryErrorMessage)" | Out-String
            $ErrorToCheck = Get-ErrorToCheck -ExpectedError $ErrorsToCheck -QueryResult $QueryErrorMessage
            if ($null -ne $ErrorToCheck) {
                $IsMatch = $true
            }

            if ($IsMatch) {
                $FoundErrorToCheck = $ErrorToCheck
                if ($IgnoreLogs) {
                    $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                    $FindingDetails += "Query Error:`t`"$($QueryErrorMessage)`"" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $($QueryResult.Errors) | Out-String
                $ErrorCount++
            }
            else {
                # Parse the Query for the error as well.
                $LogError = Get-PgErrorFromLogWithContext -LogPath $PgLogFile -StatementPattern "${StatementToCheck}" -ErrorPattern "${FoundErrorToCheck}"
                $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"

                If ($null -eq $LogError -or $LogError -eq "" -or $null -eq $LogDir ) {
                    $IgnoreLogs = $true
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Please check your log files for the following entries:" | Out-String
                    $FindingDetails += "Error Statement:`t`t$($StatementToCheck)" | Out-String
                    $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                }
                Else {
                    $FindingDetails += "Log Error:`t`t`t`t`"$($LogError.Trim())`"" | Out-String
                    $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += $ErrorQuery | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropRoleQuery =
        @"
RESET ROLE;
DROP ROLE ${RandomRoleName};
"@

        # Yeet the role we created.
        $DropQueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery
        if ($null -ne $DropQueryResult.Errors) {
            $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" was unsucessful." | Out-String
            $FindingDetails += "The role will need to be dropped manually." | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214095 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214095
        STIG ID    : PGS9-00-005400
        Rule ID    : SV-214095r961812_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-DB-000331
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to delete privileges/permissions occur.
        DiscussMD5 : D54F73DBE727F8DB6A848A2CF1160A7A
        CheckMD5   : 67B91EBB74B502BAA1040BB692730BCF
        FixMD5     : E4D834C6C7EB4C37B4E6300C6DF64CAA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    # Get the unique table name.
    $RandomRoleName1 = Get-RandomTableName
    $RandomRoleName2 = Get-RandomTableName

    # This will be run as a user with admin / elevated privs.
    $Query =
    @"
CREATE ROLE ${RandomRoleName1} LOGIN;
CREATE ROLE ${RandomRoleName2} LOGIN;
"@

    $QueryResult = Invoke-NoOutputQuery -Query $Query
    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }
    else {

        $ErrorToCheck = "permission denied"
        $ErrorQuery =
        @"
SET ROLE ${RandomRoleName1};
ALTER ROLE ${RandomRoleName2} NOLOGIN;
"@

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""

            $QueryErrorMessage = $ErrorQueryResult.Errors
            $FindingDetails += "Query Error Message:`t$($QueryErrorMessage)" | Out-String
            $IsMatch = $QueryErrorMessage.Contains($ErrorToCheck)

            if ($IsMatch) {
                if ($IgnoreLogs) {
                    $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                    $FindingDetails += "Query Error:`t`"$($QueryErrorMessage)`"" | Out-String
                    $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }

            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $($QueryResult.Errors) | Out-String
                $ErrorCount++
            }
            elseif (-not $IgnoreLogs) {
                # Parse the Query for the error as well.
                $LogError = Select-String -Path $PgLogFile -Pattern "SET ROLE ${RandomRoleName1}" -Context 1, 1 | ForEach-Object {$_.context.precontext; $_.line; $_.context.postcontext}
                $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                $FindingDetails += "Log Error:`t`t`t`t`"$($LogError)`"" | Out-String
                $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += $ErrorQuery | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropRoleQuery =
        @"
RESET ROLE;
DROP ROLE ${RandomRoleName1};
DROP ROLE ${RandomRoleName2};
"@

        # Yeet the role we created.
        $DropQueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery
        if ($null -ne $DropQueryResult.Errors) {
            $FindingDetails += "DROP ROLE `"$($RandomRoleName1)`" and DROP ROLE `"$($RandomRoleName2)`" was unsucessful." | Out-String
            $FindingDetails += "The role will need to be dropped manually." | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214096 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214096
        STIG ID    : PGS9-00-005500
        Rule ID    : SV-214096r960885_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-DB-000066
        Rule Title : PostgreSQL must be able to generate audit records when privileges/permissions are retrieved.
        DiscussMD5 : 85AFA8D27C8660852D61F98F581927A8
        CheckMD5   : 2AC75A7051F0D2B73397D52E9640A6D4
        FixMD5     : 08310CA574E72DC3B7EC861ABBBB2301
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false
    $SetNotReviewed = $false

    #Part One of check
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries

    #Part Two
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t`t$($PgLogFile)" | Out-String
        }
        else {
            $FindingDetails += "Log File:`t`tNot Found" | Out-String
            $IgnoreLogs = $True
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Please check your log files for a role membership select statement." | Out-String
        $IgnoreLogs = $True
        $SetNotReviewed = $true
    }

    if (-not $IgnoreLogs) {

        #Query for permissions

        #Check for entry in log using Pre crafted error messages.
        $RoleMembership = Get-PgLogEntryFromSyntaxError -LogPath $PgLogFile -Command "\du" -LogQuery "select r.rolname" -NumLines 11 | Out-String

        #Remove spaces to compare with correct log entry
        $FormattedRoleMembership = $RoleMembership -replace '\s+', ''
        $CorrectLog = "SELECT r.rolname, r.rolsuper, r.rolinherit,
                r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
                r.rolconnlimit, r.rolvaliduntil,
                ARRAY(SELECT b.rolname
                    FROM pg_catalog.pg_auth_members m
                    JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
                    WHERE m.member = r.oid) as memberof
            , r.rolreplication
            , r.rolbypassrls
            FROM pg_catalog.pg_roles r"

        #Remove spaces for comparison
        $FormattedLog = $CorrectLog -replace '\s+', ''

        if ( $RoleMembership -eq "" ) {
            #If nothing is found
            $ErrorCount++
            $FindingDetails += "" | Out-String
            $FindingDetails += "Role membership activity could not be found." | Out-String
        }
        elseif (-Not ($FormattedRoleMembership.Contains($FormattedLog))) {
            #If something is found but does not contain correct logging
            $ErrorCount++
            $FindingDetails += "" | Out-String
            $FindingDetails += "Log is incorrect." | Out-String
            $FindingDetails += "Log Entry:`t$($RoleMembership)" | Out-String
            $FindingDetails += "Expected Log Entry:`t$($CorrectLog)" | Out-String
        }
        else {
            #Correct log found
            $FindingDetails += "Log Entry:`t$($RoleMembership)" | Out-String
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ( $ErrorCount -gt 0 ) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214097 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214097
        STIG ID    : PGS9-00-005600
        Rule ID    : SV-214097r961809_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000347
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 6E9B8A9CF78C65F0893B04FF96814119
        CheckMD5   : 247FE7E7FA062020162C14D8E321BC34
        FixMD5     : E08747A646C8DD8E32BC90885094CD96
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214098 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214098
        STIG ID    : PGS9-00-005700
        Rule ID    : SV-214098r961836_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000507-DB-000357
        Rule Title : PostgreSQL must generate audit records when unsuccessful accesses to objects occur.
        DiscussMD5 : B952A178AC3BCCD2573DD8351E2270BC
        CheckMD5   : B3B8B19A37B5CE1DF8AC433593500082
        FixMD5     : 62C5354F50CA87FE9354C06F490D4AF7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "------------------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    for ($i = 0 ; $i -lt 5; $i++) {
        #Loop is based on how many queries we have that expect errors.

        # Get the unique table name.
        $RandomTableName = Get-RandomTableName
        $RandomRoleName = Get-RandomTableName
        $RandomSchemaName = Get-RandomTableName
        $FindingDetails += "Schema:`t`t`t$($RandomSchemaName)" | Out-String
        $FindingDetails += "Table Name:`t`t$($RandomTableName)" | Out-String
        $FindingDetails += "Role Name:`t`t$($RandomRoleName)" | Out-String
        $FindingDetails += "" | Out-String

        $ErrorQueries = @(
            @"
SET ROLE ${RandomRoleName};
SELECT * FROM ${RandomSchemaName}.${RandomTableName};
"@,
            @"
SET ROLE ${RandomRoleName};
INSERT INTO ${RandomSchemaName}.${RandomTableName}(id) VALUES (0);
"@,
            @"
SET ROLE ${RandomRoleName};
UPDATE ${RandomSchemaName}.${RandomTableName} SET id = 1 WHERE id = 0;
"@,
            @"
SET ROLE ${RandomRoleName};
DROP TABLE ${RandomSchemaName}.${RandomTableName};
"@,
            @"
SET ROLE ${RandomRoleName};
DROP SCHEMA ${RandomSchemaName};
"@
        )

        $ErrorsToCheck = @(
            "must be owner of schema $($RandomSchemaName)", # Expect 1 occurance
            "permission denied for schema $($RandomSchemaName)" # Expect 2 occurances
        )

        # This will be run as a user with admin / elevated privs.
        $Query =
        @"
CREATE SCHEMA ${RandomSchemaName};
CREATE TABLE ${RandomSchemaName}.${RandomTableName}(id INT);
INSERT INTO ${RandomSchemaName}.${RandomTableName}(id) VALUES (0);
CREATE ROLE ${RandomRoleName};
"@

        $QueryResult = Invoke-NoOutputQuery -Query $Query
        # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
        if ($null -ne $QueryResult.Errors) {
            # If we have errors or haven't affected any rows for whatever reason, leave as not reviewed.
            $SetNotReviewed = $true
            break
        }

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQuery = $ErrorQueries[$i]
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $FoundErrorToCheck = ""

            foreach ($ErrorToCheck in $ErrorsToCheck) {

                $QueryErrorMessage = $ErrorQueryResult.Errors
                $IsMatch = $QueryErrorMessage.Contains($ErrorToCheck)

                if ($IsMatch) {
                    $FoundErrorToCheck = $ErrorToCheck
                    if ($IgnoreLogs) {
                        $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                        $FindingDetails += "Query Error:`t`t`"$($QueryErrorMessage)`"" | Out-String
                        $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                        $FindingDetails += "Query:" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $ErrorQuery | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "------------------------------------------------------------------------" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    break
                }
            }

            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $($QueryResult.Errors) | Out-String
                $ErrorCount++
            }
            elseif (-not $IgnoreLogs) {
                # Parse the Query for the error as well.
                $LogError = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern "${FoundErrorToCheck}"
                $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"
                $FindingDetails += "Log Error:`t`t`t`"$($LogError.Trim())`"" | Out-String
                $FindingDetails += "Expected Error:`t`"$($ExpectedError)`"" | Out-String
                $FindingDetails += "Query:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $ErrorQuery | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "------------------------------------------------------------------------" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += $Query | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomSchemaName}.${RandomTableName};
DROP SCHEMA ${RandomSchemaName};
DROP ROLE ${RandomRoleName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
        if ($null -ne $QueryResult.Errors) {
            $FindingDetails += "The following query used to clean up Schemas, Tables, and Roles during the check has generated an error." | Out-String
            $FindingDetails += "Please refere to the query below to drop the appropriate Schemas, Tables, and Roles."
            $FindingDetails += "Query:" | Out-String
            $FindingDetails += $DropTableAndRoleQuery | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Errors:" | Out-String
            $FindingDetails += " $($QueryResult.Errors)" | Out-String
            $FindingDetails += "------------------------------------------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ($SetNotReviewed -eq $true) {
        $FindingDetails += "The initial queries needed to set up the table were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String

        # Always try to drop the tables you attempt to create just in case. We dont' want to leave a mess behind.
        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomSchemaName}.${RandomTableName};
DROP SCHEMA ${RandomSchemaName};
DROP ROLE ${RandomRoleName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
        if ($null -ne $QueryResult.Errors) {
            $FindingDetails += "The following query used to clean up Schemas, Tables, and Roles during the check has generated an error." | Out-String
            $FindingDetails += "Please refere to the query below to drop the appropriate Schemas, Tables, and Roles."
            $FindingDetails += "Query:" | Out-String
            $FindingDetails += $DropTableAndRoleQuery | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Errors:" | Out-String
            $FindingDetails += " $($QueryResult.Errors)" | Out-String
            $FindingDetails += "------------------------------------------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214099 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214099
        STIG ID    : PGS9-00-005800
        Rule ID    : SV-214099r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000354
        Rule Title : PostgreSQL must generate audit records for all privileged activities or other system-level access.
        DiscussMD5 : 794241CCED7688C45D95ACF7A400A233
        CheckMD5   : A244B46487B1BBFA9F4B3BA889261D1D
        FixMD5     : 744B168F3BEDACC1B1C08A283C5C7A00
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214100 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214100
        STIG ID    : PGS9-00-005900
        Rule ID    : SV-214100r961797_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000494-DB-000345
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 6E9B8A9CF78C65F0893B04FF96814119
        CheckMD5   : 1E5EFC32BC6F71DE2B44F1A90C1AF370
        FixMD5     : 45A04FE94FD24360B300EC3376A6A347
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains ddl, write, and role"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214101 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214101
        STIG ID    : PGS9-00-006000
        Rule ID    : SV-214101r961791_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000492-DB-000332
        Rule Title : PostgreSQL must be able to generate audit records when security objects are accessed.
        DiscussMD5 : 91B9CB9FB895AACFE90CCA0B551A1F9D
        CheckMD5   : A244B46487B1BBFA9F4B3BA889261D1D
        FixMD5     : 437183CD35124BF4D8A48C8E313FD91B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214102 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214102
        STIG ID    : PGS9-00-006100
        Rule ID    : SV-214102r961812_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-DB-000330
        Rule Title : PostgreSQL must generate audit records when privileges/permissions are deleted.
        DiscussMD5 : 27B6CE816C1283C1A8762B2216F902D6
        CheckMD5   : A244B46487B1BBFA9F4B3BA889261D1D
        FixMD5     : 48CABF4E9E22E1CC350C55979B9F479B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214103 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214103
        STIG ID    : PGS9-00-006200
        Rule ID    : SV-214103r961833_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000506-DB-000353
        Rule Title : PostgreSQL must generate audit records when concurrent logons/connections by the same user from different workstations occur.
        DiscussMD5 : 5E54CABDED688AA0EC01AF4AEFBB00FD
        CheckMD5   : 7CA9262490E9D4CD5CE5F2D800E56537
        FixMD5     : 1DA2DA7978EF008FC30A22699229FEC5
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "on"
    $PG_Parameter = @('log_connections', 'log_disconnections')
    foreach ($parameter in $PG_Parameter) {
        $Connections = Get-PSQLVariable -PG_Parameter $parameter
        if ($null -eq $Connections -or $Connections -eq "") {
            $ErrorCount++
            $Connections = "Not Found"
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }
        else {
            $Checker = $Connections | Select-String -Pattern $ExpectedValuesString
            if ( $null -eq $Checker -or $Checker -eq "" ) {
                $ErrorCount++
            }
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }
    }

    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must at least contain %m %u %d %c"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $ErrorCount++
        $LogPrefix = "Not Found"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix
    }
    else {
        $Checker = $LogPrefix | Select-String "%m" | Select-String "%u" | Select-String "%d" | Select-String "%c"
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix
    }

    if ( $ErrorCount -ge 1 ) {
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

Function Get-V214104 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214104
        STIG ID    : PGS9-00-006300
        Rule ID    : SV-214104r961818_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000501-DB-000337
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to delete security objects occur.
        DiscussMD5 : C9E4205E2B23FE50D20D377B107C55F4
        CheckMD5   : FA3D0E682C41A40CB42A8631D018EFCB
        FixMD5     : BEC1B996E216E602E68316A69B9D6EE4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214105 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214105
        STIG ID    : PGS9-00-006400
        Rule ID    : SV-214105r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000328
        Rule Title : PostgreSQL must generate audit records when privileges/permissions are modified.
        DiscussMD5 : 602D3B53ACBACFB3B5F2471391F8E688
        CheckMD5   : 2FFF1967F4C89FAEA68D2424E49AAD4D
        FixMD5     : 0093A095ED1C9CECBC4F50E8C5764F9A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "must contain role"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'role'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-role") {
                $ErrorCount++
            }
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog

    if ( $ErrorCount -gt 0 ) {
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

Function Get-V214106 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214106
        STIG ID    : PGS9-00-006500
        Rule ID    : SV-214106r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000355
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.
        DiscussMD5 : 894F9468E68AA7FC25FF7130E90D9F6F
        CheckMD5   : 2029D1032B3024AAFDE370B54735AA94
        FixMD5     : C454FFFA7455883D3A325962F29506EB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "------------------------------------------------------------------------"
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String


    $RandomRoleName = Get-RandomTableName
    $RandomErrorName = Get-RandomTableName
    $Query = "CREATE ROLE ${RandomRoleName} NOCREATEROLE NOCREATEDB;"

    $QueryResult = Invoke-NoOutputQuery -Query $Query
    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }
    else {

        $ErrorToCheck1 = "must be superuser to create superusers"
        $ErrorToCheck2 = "permission denied to create role"
        $ErrorToCheck3 = "unrecognized role option"

        $Attributes = @("SUPERUSER", "CREATEDB", "CREATEROLE", "CREATEUSER")
        foreach ($att in $Attributes) {

            $Set = "SET ROLE ${RandomRoleName};CREATE ROLE ${RandomErrorName} ${att};"

            # Assume our query was successful and continue on to the rest of the check
            $SetResult = Invoke-NoOutputQuery -Query $Set

            # This time we WANT Errors and we want NO rows to be affected.
            if ($null -ne $SetResult.Errors) {
                # Continue to check the errors generated from the query.
                $IsMatch = $false
                $QueryErrorMessage = ""
                $FoundErrorToCheck = ""

                $QueryErrorMessage = $SetResult.Errors
                $FindingDetails += "Query:`t`t`t`t$Set" | Out-String
                $FindingDetails += "Query Error Message:`t$($QueryErrorMessage)" | Out-String
                $IsMatch = $QueryErrorMessage.Contains($ErrorToCheck1)
                $IsMatch2 = $QueryErrorMessage.Contains($ErrorToCheck2)
                $IsMatch3 = $QueryErrorMessage.Contains($ErrorToCheck3)

                if ($IsMatch) {
                    $FoundErrorToCheck = $ErrorToCheck1
                    if ($IgnoreLogs) {
                        $ExpectedError = "ERROR:`t$($ErrorToCheck1)"
                        $FindingDetails += "Query Error:`t`"$($QueryErrorMessage)`"" | Out-String
                        $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                elseif ($IsMatch2) {
                    $FoundErrorToCheck = $ErrorToCheck2
                    if ($IgnoreLogs) {
                        $ExpectedError = "ERROR:`t$($ErrorToCheck2)"
                        $FindingDetails += "Query Error:`t`"$($QueryErrorMessage)`"" | Out-String
                        $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                elseif ($IsMatch3) {
                    $FoundErrorToCheck = $ErrorToCheck3
                    if ($IgnoreLogs) {
                        $ExpectedError = "ERROR:`t$($ErrorToCheck3)"
                        $FindingDetails += "Query Error:`t`"$($QueryErrorMessage)`"" | Out-String
                        $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }

                if ((-not $IsMatch) -and (-not $IsMatch2) -and (-not $IsMatch3)) {
                    $FindingDetails += "Could not find matching error for:" | Out-String
                    $FindingDetails += $($QueryResult.Errors) | Out-String
                    $ErrorCount++
                }
                elseif (-not $IgnoreLogs) {
                    [string]$LogError = Select-String -Pattern "CREATE ROLE ${RandomErrorName} ${att}" -Path $PgLogFile -Context 1, 0
                    $ErrorRegex = "$ErrorToCheck1|$ErrorToCheck2|$ErrorToCheck3"
                    $TrueError = $LogError | Select-String -Pattern "$ErrorRegex"
                    $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"
                    $FindingDetails += "Log Error:`t`t`t`t`"$($TrueError)`"" | Out-String
                    $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
                    $FindingDetails += "" | Out-String
                }

            }
            else {
                $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
                $FindingDetails += $Set | Out-String
                $FindingDetails += "" | Out-String
                $ErrorCount++
            }

        }

        $DropRoleQuery =
        @"
RESET ROLE;
DROP ROLE ${RandomRoleName};
"@

        # Yeet the role we created.
        $DropQueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery
        if ($null -ne $DropQueryResult.Errors) {
            $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" was unsucessful." | Out-String
            $FindingDetails += "The role will need to be dropped manually." | Out-String
            $FindingDetails += "------------------------------------------------------------"
            $FindingDetails += "" | Out-String
        }
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214107 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214107
        STIG ID    : PGS9-00-006600
        Rule ID    : SV-214107r961803_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000496-DB-000334
        Rule Title : PostgreSQL must generate audit records when security objects are modified.
        DiscussMD5 : A9617436DE3772C110F16B19303EE1B7
        CheckMD5   : A2FF70A224F23A99BDE10AE67E311AD5
        FixMD5     : 43CA52613F13C18BFD71D82B2B30BA34
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'role' | Select-String 'read' | Select-String 'write' | Select-String 'ddl'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog

    $PG_Parameter = "pgaudit.log_catalog"
    $ExpectedValuesString = "on"
    $QueryResult = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $QueryResult -or $QueryResult -eq "") {
        $ErrorCount++
        $QueryResult = "No value returned from query"
    }
    else {
        if ( $null -eq ($QueryResult | Select-String -Pattern "on") ) {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $QueryResult

    if ( $ErrorCount -gt 0 ) {
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

Function Get-V214108 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214108
        STIG ID    : PGS9-00-006700
        Rule ID    : SV-214108r961809_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000346
        Rule Title : PostgreSQL must generate audit records when categorized information (e.g., classification levels/security levels) is modified.
        DiscussMD5 : F44617087F7F84FCE843ABA1F9186C40
        CheckMD5   : 5BCAB5131A74F82E10C686A4D39BAAA8
        FixMD5     : D0E5003B0A579F9F7476B60FA448C951
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214109 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214109
        STIG ID    : PGS9-00-006800
        Rule ID    : SV-214109r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000329
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to modify privileges/permissions occur.
        DiscussMD5 : 26BA68E25CB46DE8A279894D738CDF4F
        CheckMD5   : FC6304A4B37245D9CA2706D969EE88F2
        FixMD5     : 92C3F5807E6078337E1C3DDB923C8DDD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "------------------------------------------------------------------------"
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    for ($i = 0 ; $i -lt 2; $i++) {
        #Loop is based on how many queries we have that expect errors.
        # Get the unique table name.
        $RandomTableName = Get-RandomTableName
        $RandomRoleName = Get-RandomTableName
        $FindingDetails += "Table Name:`t`t$($RandomTableName)" | Out-String
        $FindingDetails += "Role Name:`t`t$($RandomRoleName)" | Out-String

        $ErrorQueries = @(
            @"
SET ROLE ${RandomRoleName};
GRANT ALL PRIVILEGES ON ${RandomTableName} TO ${RandomRoleName};
"@,
            @"
SET ROLE ${RandomRoleName};
REVOKE ALL PRIVILEGES ON ${RandomTableName} FROM ${RandomRoleName};
"@
        )

        $ErrorsToCheck = @(
            "permission denied for relation $($RandomTableName)",
            "permission denied for table $($RandomTableName)"
        )

        # This will be run as a user with admin / elevated privs.
        $Query =
        @"
CREATE TABLE ${RandomTableName}(id INT);
CREATE ROLE ${RandomRoleName};
"@

        $QueryResult = Invoke-NoOutputQuery -Query $Query

        # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
        if ($null -ne $QueryResult.Errors) {
            # If we have errors or haven't affected any rows for whatever reason, leave as not reviewed.
            $SetNotReviewed = $true
            break
        }

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQuery = $ErrorQueries[$i]
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $FoundErrorToCheck = ""

            foreach ($ErrorToCheck in $ErrorsToCheck) {

                $QueryErrorMessage = $ErrorQueryResult.Errors
                $IsMatch = $QueryErrorMessage.Contains($ErrorToCheck)

                if ($IsMatch) {
                    $FoundErrorToCheck = $ErrorToCheck
                    if ($IgnoreLogs) {
                        $ExpectedError = "ERROR:`t$($ErrorToCheck)"
                        $FindingDetails += "Query Error:`t`t`"$($QueryErrorMessage)`"" | Out-String
                        $FindingDetails += "Expected Error:`t$($ExpectedError)" | Out-String
                        $FindingDetails += "Query:" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $ErrorQuery | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "------------------------------------------------------------------------" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    break
                }
            }

            if (-not $IsMatch) {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += $($QueryResult.Errors) | Out-String
                $ErrorCount++
            }
            elseif (-not $IgnoreLogs) {
                # Parse the Query for the error as well.
                $LogError = Get-PgErrorFromLog -LogPath $PgLogFile -ErrorPattern "${FoundErrorToCheck}"
                $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"
                $FindingDetails += "Log Error:`t`t`t`"$($LogError.Trim())`"" | Out-String
                $FindingDetails += "Expected Error:`t`"$($ExpectedError)`"" | Out-String
                $FindingDetails += "Query:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $ErrorQuery | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "------------------------------------------------------------------------" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += $Query | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }

        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomTableName};
DROP ROLE ${RandomRoleName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
    }

    if ($SetNotReviewed -eq $true) {
        $FindingDetails += "The initial queries needed to set up the table were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String

        # Always try to drop the tables you attempt to create just in case. We dont' want to leave a mess behind.
        $DropTableAndRoleQuery =
        @"
DROP TABLE ${RandomTableName};
DROP ROLE ${RandomRoleName};
"@

        # Yeet the table and role we created.
        $QueryResult = Invoke-NoOutputQuery -Query $DropTableAndRoleQuery
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214110 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214110
        STIG ID    : PGS9-00-006900
        Rule ID    : SV-214110r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000327
        Rule Title : PostgreSQL must generate audit records when unsuccessful attempts to add privileges/permissions occur.
        DiscussMD5 : B35EF21A04A2D85482160DD8DAF08C74
        CheckMD5   : EAF158BE7439FDDEA2417CA3A0E8A95B
        FixMD5     : E2BE34EFB319786D91FCE5FD21FD7FD3
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IgnoreLogs = $false

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String

        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $IgnoreLogs = $true
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "Please check your log files for the following errors." | Out-String
        $FindingDetails += "------------------------------------------------------------------------"
        $IgnoreLogs = $true
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output" | Out-String
    $FindingDetails += "------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String

    # Get the unique role name.
    $RandomRoleName = Get-RandomTableName
    $FindingDetails += "Role Name:`t$($RandomRoleName)" | Out-String

    # Get the unique table name.
    $RandomTableName = Get-RandomTableName
    $FindingDetails += "Table Name:`t$($RandomTableName)" | Out-String

    $FindingDetails += "" | Out-String

    # This will be run as a user with admin / elevated privs.
    $Query =
    @"
CREATE ROLE ${RandomRoleName};
CREATE TABLE ${RandomTableName}(id INT);
"@

    $QueryResult = Invoke-NoOutputQuery -Query $Query
    # Check to see if we have any errors or if we haven't changed any rows when we know we should have.
    if ($null -ne $QueryResult.Errors) {
        # If we have errors, leave as not reviewed.
        $FindingDetails += "The initial queries needed to set up the role were unsucessful." | Out-String
        $FindingDetails += "Please ensure the account used to run this check has sufficient privileges." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
        $SetNotReviewed = $true
    }
    else {

        $ErrorsToCheck = @( "permission denied for relation $($RandomTableName)", "permission denied for table $($RandomTableName)")
        $StatementToCheck = "GRANT ALL PRIVILEGES ON ${RandomTableName} TO $($RandomRoleName)"

        $ErrorQuery =
        @"
SET ROLE ${RandomRoleName};
GRANT ALL PRIVILEGES ON ${RandomTableName} TO ${RandomRoleName};
"@

        # Assume our query was successful and continue on to the rest of the check
        $ErrorQueryResult = Invoke-NoOutputQuery -Query $ErrorQuery

        # This time we WANT Errors and we want NO rows to be affected.
        if ($null -ne $ErrorQueryResult.Errors) {
            # Continue to check the errors generated from the query.
            $IsMatch = $false
            $QueryErrorMessage = ""
            $FoundErrorToCheck = ""

            $QueryErrorMessage = $ErrorQueryResult.Errors
            $FindingDetails += "Query Error Message:`t$($QueryErrorMessage)" | Out-String

            $ErrorToCheck = Get-ErrorToCheck -ExpectedError $ErrorsToCheck -QueryResult $QueryErrorMessage
            if ($null -ne $ErrorToCheck) {
                $IsMatch = $true
            }

            if ($IsMatch) {
                $FoundErrorToCheck = $ErrorToCheck
                $ExpectedError = "ERROR:`t$($FoundErrorToCheck)"

                if ( -not $IgnoreLogs) {
                    # Parse the Query for the error as well.
                    $LogError = Get-PgErrorFromLogWithContext -LogPath $PgLogFile -StatementPattern "${StatementToCheck}" -ErrorPattern "${FoundErrorToCheck}"
                    If ($null -eq $LogError -or $LogError -eq "") {
                        $IgnoreLogs = $true
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Please check your log files for the following entries:" | Out-String
                        $FindingDetails += "Error Statement:`t`t$($StatementToCheck)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Log Error:`t`t`t`t`"$($LogError.Trim())`"" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }

                $FindingDetails += "Expected Error:`t`t`"$($ExpectedError)`"" | Out-String
            }
            else {
                $FindingDetails += "Could not find matching error for:" | Out-String
                $FindingDetails += "$($QueryResult.Errors)" | Out-String
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "The following query was expected to generate an error but did not:" | Out-String
            $FindingDetails += "$ErrorQuery" | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }
    }

    $DropRoleQuery =
    @"
RESET ROLE;
DROP ROLE ${RandomRoleName};
DROP TABLE ${RandomTableName};
"@

    # Yeet the role we created.
    $QueryResult = Invoke-NoOutputQuery -Query $DropRoleQuery
    if ($null -ne $DropQueryResult.Errors) {
        $FindingDetails += "DROP ROLE `"$($RandomRoleName)`" or " | Out-String
        $FindingDetails += "DROP TABLE `"$($RandomTableName)`" was unsucessful." | Out-String
        $FindingDetails += "The role or table will need to be dropped manually." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $FindingDetails += "" | Out-String
    }

    if ($SetNotReviewed -eq $false) {
        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if (-not $IgnoreLogs) {
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

Function Get-V214111 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214111
        STIG ID    : PGS9-00-007000
        Rule ID    : SV-214111r961038_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-DB-000067
        Rule Title : PostgreSQL, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.
        DiscussMD5 : 49A664D61308C1ED7484201998EC9F34
        CheckMD5   : 773CA3C2DFF5502E0FEF2C9788DCB170
        FixMD5     : 9A81BE02435CD814B15BD73ED46769A9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $IsAbsolutePath = $false
    $IsConcatPath = $false

    $AbsolutePath = ""
    $PG_Parameter = "ssl_crl_file"
    $Query = "SHOW $($PG_Parameter)"

    $QueryOutput = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $QueryOutput -or $QueryOutput -eq "") {
        $ErrorCount++
        $QueryOutput = "Not Found"
    }
    else {
        # Test for an absolute path to a file.
        $IsAbsolutePath = Test-Path -Path $QueryOutput -PathType Leaf
        if ($IsAbsolutePath -eq $false) {
            # If our initial value is not an absolute path. Check in the PG_Data directory.
            $ConcatenatedPath = "$($PgInstance.PG_DATA)/$($QueryOutput)"
            $IsConcatPath = Test-Path -Path $ConcatenatedPath -PathType Leaf
            if ($IsConcatPath -eq $false) {
                # If this still isn't the case, then the file will not be loaded by PG when the database boots
                # because PG will look in the data directory if an absolute path is not provided as the value.
                $ErrorCount++
            }
            else {
                #PG_DATA + File.crl is valid so we set it to our "Found" value.
                $AbsolutePath = $ConcatenatedPath
            }
        }
    }

    $FindingDetails += "Query:`t`t`t$($Query)" | Out-String
    $FindingDetails += "Query Output:`t`t$($QueryOutput)" | Out-String
    if ($ErrorCount -le 0) {
        if ($IsAbsolutePath -eq $false) {
            $FindingDetails += "Absolute Path:`t`t$($AbsolutePath)" | Out-String
        }
        $FindingDetails += "Exists:`t`t`tYes" | Out-String
    }
    else {
        $FindingDetails += "Exists:`t`t`tNo" | Out-String
    }

    $FindingDetails += "" | Out-String

    $HostSSL = "hostssl"
    $PatternClientCert = "clientcert\s*=\s*1"
    $PatternCert = "\bcert\b" #This will 100% have to change.
    $ExpectedValue = "hostssl entries must contain `"cert`" and `"clientcert=1`"."

    $PgConfigFile = "$($PgInstance.PG_DATA)/pg_hba.conf"
    $ConfigLines = Get-PostgresConfigContent -ConfigFile $PgConfigFile -SearchPattern $HostSSL

    ForEach ($line in $ConfigLines) {

        if ($null -eq $line -or $line.ConfigLine -eq "Not Found") {
            $ErrorCount++
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $HostSSL -ExpectedValue $ExpectedValue -DetectedValue $line.ConfigLine
            break
        }

        $MatchesClientCert = $line.ConfigLine | Select-String -Pattern $PatternClientCert
        $MatchesCert = $line.ConfigLine | Select-String -Pattern $PatternCert
        if ($null -eq $MatchesClientCert -or $MatchesClientCert -eq "") {
            # Needs to have both on the line.
            $ErrorCount++
        }

        if ($null -eq $MatchesCert -or $MatchesCert -eq "") {
            $ErrorCount++
        }

        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $HostSSL -ExpectedValue $ExpectedValue -DetectedValue $line.ConfigLine
        $FindingDetails += "" | Out-String
    }

    if ($ErrorCount -gt 0) {
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

Function Get-V214112 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214112
        STIG ID    : PGS9-00-007100
        Rule ID    : SV-214112r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-DB-000041
        Rule Title : PostgreSQL must produce audit records containing sufficient information to establish where the events occurred.
        DiscussMD5 : E1CFF16A4A7245DBAF12DC41804CAA32
        CheckMD5   : 9FE051B7B34E364F926C1564F9D964E0
        FixMD5     : 7BB70E3088C2A85CFE09932FD6896CD4
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must at least contain %m %u %d %s"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $ErrorCount++
        $LogPrefix = "Not Found"
    }
    else {
        $Checker = $LogPrefix | Select-String "%m" | Select-String "%u" | Select-String "%d" | Select-String "%s"
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix

    if ( $ErrorCount -ge 1 ) {
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

Function Get-V214113 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214113
        STIG ID    : PGS9-00-007200
        Rule ID    : SV-214113r961638_rule
        CCI ID     : CCI-002420
        Rule Name  : SRG-APP-000441-DB-000378
        Rule Title : PostgreSQL must maintain the confidentiality and integrity of information during preparation for transmission.
        DiscussMD5 : B89D26F7D2F379D30F0EEE5BD15F5800
        CheckMD5   : 248B70086BEE06BB4096D1D587F0F4D7
        FixMD5     : CCD0CCF9FE737609E4C098945956B832
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SSLErrorCount = 0
    $HostSSLErrorCount = 0

    $QuerySetting = "ssl"
    $ExpectedValuesString = "on"
    $Result = Get-PSQLVariable -PG_Parameter $QuerySetting
    if ($null -eq $Result -or $Result -eq "") {
        $SSLErrorCount++
        $Result = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $QuerySetting -ExpectedValue $ExpectedValuesString -DetectedValue $Result
    }
    else {
        if ($Result | Select-String -Pattern "on" -NotMatch) {
            $SSLErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $QuerySetting -ExpectedValue $ExpectedValuesString -DetectedValue $Result
    }

    $ExpectedValues = "hostssl"
    $ExpectedInclude = "clientcert\s*=\s*1"
    $ExpectedValuesString = "Config lines must be type 'hostssl' and contain clientcert=1."

    $PgConfigFile = "$($PgInstance.PG_DATA)/pg_hba.conf"
    $ConfigLines = Get-PostgresConfigContent -ConfigFile $PgConfigFile

    $FindingDetails += "TYPE`tDATABASE`tUSER`tADDRESS`tMETHOD" | Out-String

    ForEach ($line in $ConfigLines) {
        $FindingDetails += $line.ConfigLine | Out-String
        if ($line.ConfigLine | Select-String -Pattern $ExpectedValues -NotMatch) {
            $HostSSLErrorCount++
        }
        elseif ($line.ConfigLine | Select-String -Pattern $ExpectedInclude -NotMatch) {
            $HostSSLErrorCount++
        }
    }

    if ($SSLErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
        if ($HostSSLErrorCount -eq 0) {
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

Function Get-V214115 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214115
        STIG ID    : PGS9-00-007700
        Rule ID    : SV-214115r961446_rule
        CCI ID     : CCI-001889
        Rule Name  : SRG-APP-000375-DB-000323
        Rule Title : PostgreSQL must generate time stamps, for audit records and application data, with a minimum granularity of one second.
        DiscussMD5 : 0A42AFF5FFE284D147C92E7F46A8684C
        CheckMD5   : 3CEDDE7FD2155BECFA57F8D970890D54
        FixMD5     : 15707D08352A31FCDE7080D8EE052D11
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $SystemErrorCount = 0
    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must at least contain %m"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $ErrorCount++
        $LogPrefix = "Not Found"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix
    }
    else {
        $Checker = $LogPrefix | Select-String "%m"
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix
    }

    $LogDir = $PgInstance.LogDir
    if ($null -ne $LogDir) {
        $FindingDetails += "Log Dir:`t$($LogDir)" | Out-String
        $PgLogFile = Get-PgLatestLogFile
        if ($null -ne $PgLogFile) {
            $FindingDetails += "Log File:`t$PgLogFile" | Out-String

            $LogOutput = @(Select-String -Path $PgLogFile -Pattern '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\s*[0-9][0-9]:[0-9][0-9].[0-9][0-9]' | Select-Object -Last 5)

            if ( ($LogOutput | Measure-Object).count -gt 0 ) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Log file contains time stamps" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $LogOutput | Out-String
            }
            else {
                $FindingDetails += "Log file does not contain time stamps"
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "Log File:`tNot Found" | Out-String
            $SystemErrorCount++
        }
    }
    else {
        $FindingDetails += "Log Dir:`tNot Found" | Out-String
        $FindingDetails += "Log Dest:`t$($PgInstance.LogDest)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Please check your log files to verify time stamps are being logged." | Out-String
        $FindingDetails += "------------------------------------------------------------"
        $SystemErrorCount++
    }

    if ( $ErrorCount -ge 1 ) {
        $Status = "Open"
    }
    else {
        if ( $SystemErrorCount -eq 0 ) {
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

Function Get-V214116 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214116
        STIG ID    : PGS9-00-007800
        Rule ID    : SV-214116r960906_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-DB-000201
        Rule Title : PostgreSQL must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.
        DiscussMD5 : 79AE286EE19DFF9F54DCA8CB8208209F
        CheckMD5   : 076A41F8C6D316EEDE7A850EEB1C3A3A
        FixMD5     : 0D04A5080151C8834E4885E1FA62C4CC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must contain %m %u %d %p %r %a"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $ErrorCount++
        $LogPrefix = "Not Found"
    }
    else {
        $Checker = $LogPrefix | Select-String "%m" | Select-String "%u" | Select-String "%d" | Select-String "%p" | Select-String "%r" | Select-String "%a"
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix

    if ( $ErrorCount -ge 1 ) {
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

Function Get-V214117 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214117
        STIG ID    : PGS9-00-008000
        Rule ID    : SV-214117r961857_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000514-DB-000381
        Rule Title : PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to generate and validate cryptographic hashes.
        DiscussMD5 : AD580B7F969797CAE2B6EABFAE408CF9
        CheckMD5   : 4DC030C71E152A067E4431EBF1E87FBD
        FixMD5     : A5E7CC654F120C6BC9C4635CF9B6378B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ExpectedValue = "1"
    if ($isLinux) {
        $PG_Parameter = "fips_enabled"
        $DetectedValue = (cat /proc/sys/crypto/fips_enabled)
        if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
            $ErrorCount++
            $DetectedValue = "Not Found"
        }
        if ($($PGInstance.ContainerEngine) -eq "docker") {
            $DockerInfo = docker info 2>/dev/null
            $SecOptionsBlock = @()
            $InBlock = $false
            foreach ($line in $DockerInfo) {
                $SecOption = $line | Select-String "Security Options"
                if ($null -ne $SecOption -and $SecOption -ne "") {
                    $InBlock = $true
                    $SecOptionsBlock += $line
                    continue
                }
                elseif ($InBlock -eq $false) {
                    continue
                }
                $InBlock = $true
                $StopBlock = $line | Select-String "Kernel Version"
                if ($null -ne $StopBlock -and $StopBlock -ne "") {
                    break
                }
                $SecOptionsBlock += $line
            }

            $FipsEnabled = $SecOptionsBlock | Select-String "fips"
            if ($null -ne $FipsEnabled -and $FipsEnabled -ne "") {
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tEnabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
            else {
                $ErrorCount++
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tDisabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
        }
        if ($($PGInstance.ContainerEngine) -eq "podman") {
            $PodmanInfo = podman info 2>/dev/null
            $SecOptionsBlock = @()
            $InBlock = $false
            foreach ($line in $PodmanInfo) {
                $SecOption = $line | Select-String "Security Options"
                if ($null -ne $SecOption -and $SecOption -ne "") {
                    $InBlock = $true
                    $SecOptionsBlock += $line
                    continue
                }
                elseif ($InBlock -eq $false) {
                    continue
                }
                $InBlock = $true
                $StopBlock = $line | Select-String "Kernel Version"
                if ($null -ne $StopBlock -and $StopBlock -ne "") {
                    break
                }
                $SecOptionsBlock += $line
            }

            $FipsEnabled = $SecOptionsBlock | Select-String "fips"
            if ($null -ne $FipsEnabled -and $FipsEnabled -ne "") {
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tEnabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
            else {
                $ErrorCount++
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tDisabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $PG_Parameter = "FipsAlgorithmPolicy"
        $Name = "Enabled"
        $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
        $DetectedValue = Get-RegistryResult -Path "$KeyPath" -ValueName "$Name"
        $DetectedValue = $DetectedValue.Value

        if ($DetectedValue -eq "(blank)" -or $DetectedValue -eq "(NotFound)") {
            $ErrorCount++
        }
        $FindingDetails += "Registry Path:`t`t$KeyPath" | Out-String
        $FindingDetails += "Value Name:`t`t$Name" | Out-String
        $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`t$DetectedValue" | Out-String
    }

    If ( $DetectedValue -ne 1 ) {
        $ErrorCount++
    }

    If ($ErrorCount -ge 1 ) {
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

Function Get-V214119 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214119
        STIG ID    : PGS9-00-008200
        Rule ID    : SV-214119r961857_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000514-DB-000383
        Rule Title : PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners requirements.
        DiscussMD5 : 82E2791E95498ED30F4CFD4DFBAAF231
        CheckMD5   : 4DC030C71E152A067E4431EBF1E87FBD
        FixMD5     : A5E7CC654F120C6BC9C4635CF9B6378B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ExpectedValue = "1"
    if ($isLinux) {
        $PG_Parameter = "fips_enabled"
        $DetectedValue = (cat /proc/sys/crypto/fips_enabled)
        if ($null -eq $DetectedValue -or $DetectedValue -eq "") {
            $ErrorCount++
            $DetectedValue = "Not Found"
        }
        if ($($PGInstance.ContainerEngine) -eq "docker") {
            $DockerInfo = docker info 2>/dev/null
            $SecOptionsBlock = @()
            $InBlock = $false
            foreach ($line in $DockerInfo) {
                $SecOption = $line | Select-String "Security Options"
                if ($null -ne $SecOption -and $SecOption -ne "") {
                    $InBlock = $true
                    $SecOptionsBlock += $line
                    continue
                }
                elseif ($InBlock -eq $false) {
                    continue
                }
                $InBlock = $true
                $StopBlock = $line | Select-String "Kernel Version"
                if ($null -ne $StopBlock -and $StopBlock -ne "") {
                    break
                }
                $SecOptionsBlock += $line
            }

            $FipsEnabled = $SecOptionsBlock | Select-String "fips"
            if ($null -ne $FipsEnabled -and $FipsEnabled -ne "") {
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tEnabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
            else {
                $ErrorCount++
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tDisabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
        }
        if ($($PGInstance.ContainerEngine) -eq "podman") {
            $PodmanInfo = podman info 2>/dev/null
            $SecOptionsBlock = @()
            $InBlock = $false
            foreach ($line in $PodmanInfo) {
                $SecOption = $line | Select-String "Security Options"
                if ($null -ne $SecOption -and $SecOption -ne "") {
                    $InBlock = $true
                    $SecOptionsBlock += $line
                    continue
                }
                elseif ($InBlock -eq $false) {
                    continue
                }
                $InBlock = $true
                $StopBlock = $line | Select-String "Kernel Version"
                if ($null -ne $StopBlock -and $StopBlock -ne "") {
                    break
                }
                $SecOptionsBlock += $line
            }

            $FipsEnabled = $SecOptionsBlock | Select-String "fips"
            if ($null -ne $FipsEnabled -and $FipsEnabled -ne "") {
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tEnabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
            else {
                $ErrorCount++
                $FindingDetails += "Container Setting:" | Out-String
                $FindingDetails += "Setting:`t`t`tFIPS Mode" | Out-String
                $FindingDetails += "Expected State:`tEnabled" | Out-String
                $FindingDetails += "Detected State:`tDisabled" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Host OS Setting:"
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValue -DetectedValue $DetectedValue
    }
    else {
        $PG_Parameter = "FipsAlgorithmPolicy"
        $Name = "Enabled"
        $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
        $DetectedValue = Get-RegistryResult -Path "$KeyPath" -ValueName "$Name"
        $DetectedValue = $DetectedValue.Value

        if ($DetectedValue -eq "(blank)" -or $DetectedValue -eq "(NotFound)") {
            $ErrorCount++
        }
        $FindingDetails += "Registry Path:`t`t$KeyPath" | Out-String
        $FindingDetails += "Value Name:`t`t$Name" | Out-String
        $FindingDetails += "Expected Value:`t$ExpectedValue" | Out-String
        $FindingDetails += "Detected Value:`t$DetectedValue" | Out-String
    }

    If ( $DetectedValue -ne 1 ) {
        $ErrorCount++
    }

    If ($ErrorCount -ge 1 ) {
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

Function Get-V214120 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214120
        STIG ID    : PGS9-00-008300
        Rule ID    : SV-214120r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : PostgreSQL must protect the confidentiality and integrity of all information at rest.
        DiscussMD5 : A3C3555A13EB18336DFA5B8A507AFD6D
        CheckMD5   : 922D72BA1B9890777A3E9ECBCCB996D2
        FixMD5     : E4D278E9CE99058E8D490C8AF37BC0CB
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = "SELECT * FROM pg_available_extensions WHERE name='pgcrypto'"


    $FindingDetails += "Query:`t$($command)" | Out-String
    $FindingDetails += "------------------------------------------------------" | Out-String
    $FindingDetails += Invoke-PSQLQuery -ExpandTable -Query $command | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214121 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214121
        STIG ID    : PGS9-00-008400
        Rule ID    : SV-214121r981956_rule
        CCI ID     : CCI-001812
        Rule Name  : SRG-APP-000378-DB-000365
        Rule Title : PostgreSQL must prohibit user installation of logic modules (functions, trigger procedures, views, etc.) without explicit privileged status.
        DiscussMD5 : 8EBA9D35661C24E6DF170ABBADD0096E
        CheckMD5   : FD4E6B8C1FC4F51EE131B10F44D6DF71
        FixMD5     : 50ACAE8716A999B206DCAA5481B7A713
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Query = @("\dp", "\dn+")

    foreach ($command in $Query) {
        $FindingDetails += "Query:`t$($command)" | Out-String
        $FindingDetails += "------------------------------------------------------" | Out-String
        $ResultArray = Invoke-PSQLQuery -ExpandTable -Query $command
        $FindingDetails += $ResultArray | Out-String

        if ( $Query.IndexOf($command) -eq 0 ) {
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

Function Get-V214122 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214122
        STIG ID    : PGS9-00-008500
        Rule ID    : SV-214122r961095_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-DB-000122
        Rule Title : PostgreSQL must separate user functionality (including user interface services) from database management functionality.
        DiscussMD5 : 597D7EFEF39C3C30E8191270709B8286
        CheckMD5   : 835925CCB00FAA66AA85DE8237C910A7
        FixMD5     : B8F09E71CC95D3101C516354D4CE8FBD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DBQuery = '\du'
    if ($isLinux) {
        $SearchPattern = 'Attributes.*Superuser\|Attributes.*Create role\|Attributes.*Create DB\|Attributes.*Bypass RLS'
    }
    else {
        $SearchPattern = '(Attributes.*Superuser)|(Attributes.*Create role)|(Attributes.*Create DB)|(Attributes.*Bypass RLS)'
    }

    $FindingDetails += 'Roles with Administrative Functionality' | Out-String
    $FindingDetails += Get-PgRecordFromMeta -command $DBQuery -SearchPattern $SearchPattern
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214123 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214123
        STIG ID    : PGS9-00-008600
        Rule ID    : SV-214123r960888_rule
        CCI ID     : CCI-001464
        Rule Name  : SRG-APP-000092-DB-000208
        Rule Title : PostgreSQL must initiate session auditing upon startup.
        DiscussMD5 : EE79C09EBFA5B51E2FA1045D5455E46B
        CheckMD5   : B699ACACCE4C3364034FC6014F40B359
        FixMD5     : 283F3914051944D1BCB88750B7D5E6F2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries

    $PG_Parameter = "log_destination"
    $ExpectedValuesString = "stderr or syslog"
    $PGAudit = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PGAudit -or $PGAudit -eq "") {
        $ErrorCount++
        $PGAudit = "No value returned from query"
    }
    else {
        $Checker = $PGAudit | Select-String -Pattern 'syslog|stderr'
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PGAudit

    if ( $ErrorCount -gt 0 ) {
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

Function Get-V214124 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214124
        STIG ID    : PGS9-00-008700
        Rule ID    : SV-214124r961599_rule
        CCI ID     : CCI-002475
        Rule Name  : SRG-APP-000428-DB-000386
        Rule Title : PostgreSQL must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.
        DiscussMD5 : 0F48CCE0DB62C7C50DED3D0E443B63BA
        CheckMD5   : EF020983D20573397AD78885B719B30C
        FixMD5     : FCF2A0033AAD5866EFBC424307660ACD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = "SELECT * FROM pg_available_extensions WHERE name='pgcrypto'"


    $FindingDetails += "Query:`t$($command)" | Out-String
    $FindingDetails += "------------------------------------------------------" | Out-String
    $FindingDetails += Invoke-PSQLQuery -ExpandTable -Query $command | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214125 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214125
        STIG ID    : PGS9-00-008800
        Rule ID    : SV-214125r960900_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098-DB-000042
        Rule Title : PostgreSQL must produce audit records containing sufficient information to establish the sources (origins) of the events.
        DiscussMD5 : EC09A4A073F6935BAD5A2832B09D2F12
        CheckMD5   : A613009F92C73600788369F52E697595
        FixMD5     : F5A12DB10AF1400EA34C7064DCF5304D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must provide enough information regarding the source of events"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $ErrorCount++
        $LogPrefix = "Not Found"
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix

    $PG_Parameter = "log_hostname"
    $ExpectedValuesString = "Must provide enough information regarding the source of events"
    $LogHostName = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogHostName -or $LogHostName -eq "") {
        $ErrorCount++
        $LogHostName = "Not Found"
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogHostName
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214126 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214126
        STIG ID    : PGS9-00-008900
        Rule ID    : SV-214126r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : Unused database components, PostgreSQL software, and database objects must be removed.
        DiscussMD5 : 0737F50B37A99667C94E4A017C1FFB7A
        CheckMD5   : F7C84CAD10C195AF47A88B3F5F9F1932
        FixMD5     : 33FBB89F0197CB8AC67024616FD523F1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Query = "select * from pg_extension where extname != 'plpgsql'"
    $FindingDetails += "Query:" | Out-String
    $FindingDetails += "$($Query)" | Out-String
    $FindingDetails += "" | Out-String
    $Results = Invoke-PSQLQuery -Query $Query
    $FindingDetails += "" | Out-String
    $FindingDetails += "Query Output:" | Out-String
    $FindingDetails += $Results | Out-String
    $ResultsOS += $Results | Out-String

    If ($null -eq $Results -or $Results -eq "" -or $ResultsOS.Contains("(0 rows)")) {
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

Function Get-V214127 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214127
        STIG ID    : PGS9-00-009100
        Rule ID    : SV-214127r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Access to external executables must be disabled or restricted.
        DiscussMD5 : E1E5FA7D5E22935249EF62389A16E390
        CheckMD5   : 8A32E4AC8BF13AE1F8CFF6F2F54598A2
        FixMD5     : 8F91D86250C5AE05158BAEC891C23212
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DBQuery = '\du'
    $FindingDetails += "Meta Command:`t$($DBQuery)" | Out-String
    $FindingDetails += "------------------------------------------------------" | Out-String
    $SearchPattern = 'Attributes.*Superuser'
    $FindingDetails += 'Roles with Superuser rights' | Out-String
    $FindingDetails += Get-PgRecordFromMeta -command $DBQuery -SearchPattern $SearchPattern

    $Query = "SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL"
    $FindingDetails += "Query:`t$($Query)" | Out-String
    $FindingDetails += "------------------------------------------------------" | Out-String
    $ResultArray = Invoke-PSQLQuery -ExpandTable -Query $Query
    $FindingDetails += $ResultArray | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214128 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214128
        STIG ID    : PGS9-00-009200
        Rule ID    : SV-214128r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : Unused database components which are integrated in PostgreSQL and cannot be uninstalled must be disabled.
        DiscussMD5 : 2F90A55199CCB63794D18E64ADAE3477
        CheckMD5   : 326503DF809EFC878084A71C6E1F3960
        FixMD5     : E96A9F0F9590B2289B442B63D3B65C00
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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

        $debian = $(cat /etc/os-release | grep -i 'debian')
        $centos = $(cat /etc/os-release | grep -i 'centos\|rhel')

        if ($debian) {
            $FindingDetails += "Installed Packages:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += (dpkg --get-selections 2>/dev/null | grep postgres) | Out-String
        }
        elseif ($centos) {
            $FindingDetails += "Installed Packages:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += (yum list installed 2>/dev/null | grep postgres) | Out-String
        }
        if ($($PGInstance.ContainerEngine) -eq "docker") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Container Images:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += (docker image list 2>/dev/null | grep postgres) | Out-String
        }
        if ($($PGInstance.ContainerEngine) -eq "podman") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Container Images:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += (podman image list 2>/dev/null | grep postgres) | Out-String
        }
    }
    else {
        $Keys = (Get-ChildItem -Path HKLM:\SOFTWARE\PostgreSQL\installations).Name
        $Packages = $Keys | Split-Path -Leaf
        $FindingDetails += "Installed Packages:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $Packages | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214130 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214130
        STIG ID    : PGS9-00-009500
        Rule ID    : SV-214130r981949_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-APP-000171-DB-000074
        Rule Title : If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords.
        DiscussMD5 : 27D19CC035D75D11863E3B6E857CE4D4
        CheckMD5   : A1C5B375E9F8E645AF27339F4B3D78EB
        FixMD5     : 98549B379CE74B108DB58E954379F4AC
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "password_encryption"
    $ExpectedValue = "on"

    $PassEncryption = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PassEncryption -or $PassEncryption -eq "") {
        $PassEncryption = "Not Found"
        $ErrorCount++
    }
    else {
        $isOn = $PassEncryption | Select-String -Pattern 'md5|on|scram-sha-256'
        if ($null -eq $isOn -or $isOn -eq "") {
            $ErrorCount++
        }
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValue -DetectedValue $PassEncryption

    if ($ErrorCount -gt 0) {
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

Function Get-V214131 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214131
        STIG ID    : PGS9-00-009600
        Rule ID    : SV-214131r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : PostgreSQL must enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).
        DiscussMD5 : 841236AE36286B8E29EE7B91507764A7
        CheckMD5   : 82E074E0E33AF901F28672F72C92B214
        FixMD5     : F9FF75B6799174159D2226BD8413AC68
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DBQuery = '\du'
    $SearchPattern = 'Attributes.*Superuser'
    $FindingDetails += 'Roles with Superuser rights' | Out-String
    $FindingDetails += Get-PgRecordFromMeta -command $DBQuery -SearchPattern $SearchPattern

    If ($isLinux) {
        $SearchPattern = '=C\|=w\|=UC\|=Uw'
    }
    else {
        $SearchPattern = '=C|=w|=UC|=Uw'
    }

    $DBQuery = '\l'
    $FindingDetails += 'Databases with update ("w") or create ("C") privileges' | Out-String
    $FindingDetails += Get-PgRecordFromMeta -command $DBQuery -SearchPattern $SearchPattern

    $DBQuery = '\dn+'
    $FindingDetails += 'Schemas with update ("w") or create ("C") privileges' | Out-String
    $FindingDetails += Get-PgRecordFromMeta -command $DBQuery -SearchPattern $SearchPattern
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214132 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214132
        STIG ID    : PGS9-00-009700
        Rule ID    : SV-214132r960864_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : PostgreSQL must protect against a user falsely repudiating having performed organization-defined actions.
        DiscussMD5 : 0ED872C0F2043C7F1764809FBC0DB9E2
        CheckMD5   : CA49BF12DB10FE7B5116B450DFE1A9E7
        FixMD5     : 7E4F23C438C6981EF6A5DDA715B4D21D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must contain %m %a %u %d %r %p"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $ErrorCount++
        $LogPrefix = "Not Found"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix
    }
    else {
        $Checker = $LogPrefix | Select-String "%m" | Select-String "%a" | Select-String "%u" | Select-String "%d" | Select-String "%r" | Select-String "%p"
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix

    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries

    if ( $ErrorCount -gt 0 ) {
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

Function Get-V214136 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214136
        STIG ID    : PGS9-00-010200
        Rule ID    : SV-214136r961041_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DB-000068
        Rule Title : PostgreSQL must enforce authorized access to all PKI private keys stored/utilized by PostgreSQL.
        DiscussMD5 : 9C48170D800BAAC80E4F7F3477E470CB
        CheckMD5   : DD029ED495FDC2A6B5B560391D422EC9
        FixMD5     : E04652EB9D33AA3C7C2E871A01C7B968
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $SSL_Path = ''
    $PG_Parameter = @("ssl_ca_file", "ssl_cert_file", "ssl_crl_file", "ssl_key_file")
    foreach ($ssl_file_var in $PG_Parameter) {
        $SSL_file = Get-PSQLVariable -PG_Parameter $ssl_file_var
        if ($null -eq $SSL_file -OR $SSL_file -eq "") {
            $FindingDetails += "Parameter:`t$ssl_file_var" | Out-String
            $FindingDetails += "Value:`t`tNo Value Defined" | Out-String
            $FindingDetails += "------------------------------------" | Out-String
        }
        else {
            $FindingDetails += "Parameter:`t$ssl_file_var" | Out-String
            $FindingDetails += "Value:`t`t$SSL_file" | Out-String

            # Test the file for absolute path.
            if ($($PgInstance.ContainerEngine) -eq "") {
                if (Test-Path -Path $SSL_file) {
                    # This is an absolute path to some directory.
                    $SSL_path = $SSL_file.Substring(0, $SSL_file.lastIndexOf('/'))
                }
                else {
                    $ConcatPath = "$($PgInstance.PG_DATA)/$($SSL_file)"
                    if (Test-Path -Path $ConcatPath) {
                        # The concatenated path is the one we want.
                        $SSL_Path = $PgInstance.PG_DATA
                    }
                    else {
                        # File could not be found.
                        $FindingDetails += "Permissions:`tFile not found" | Out-String
                        $FindingDetails += "------------------------------------" | Out-String
                        continue
                    }
                }
            }
            else {
                $SSLPathCheck = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "test -f $SSL_file && echo valid"
                if ($SSLPathCheck -eq "valid") {
                    $SSL_path = $SSL_file.Substring(0, $SSL_file.lastIndexOf('/'))
                }
                else {
                    $ConcatPathCheck = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "test -f $($PgInstance.PG_DATA)/$SSL_file && echo valid"
                    if ($ConcatPathCheck -eq 'valid') {
                        $SSL_Path = $PgInstance.PG_DATA
                    }
                    else {
                        # File could not be found.
                        $FindingDetails += "Permissions:`tFile not found" | Out-String
                        $FindingDetails += "------------------------------------" | Out-String
                        continue
                    }
                }

            }

            if ($IsLinux) {
                if ($($PGInstance.ContainerEngine) -eq "") {
                    $Dir_Listing = ls -ld $SSL_Path
                    $SSL_Perms = ls -ld $SSL_Path | awk '{print $1}'
                }
                else {
                    $Dir_Listing = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "ls -ld $SSL_Path"
                    $SSL_Perms = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "ls -ld $SSL_Path"
                }
                $FindingDetails += "Permissions:`t$Dir_Listing" | Out-String
                $hasWorldRead = ($SSL_Perms.substring(7, 1) -eq "r")
                $hasWorldWrite = ($SSL_Perms.substring(8, 1) -eq "w")
                $hasWorldExecute = ($SSL_Perms.substring(9, 1) -eq "x")
                if ($hasWorldRead -eq $true -or $hasWorldWrite -eq $true -or $hasWorldExecute -eq $true) {
                    $ErrorCount++
                }
            }
            else {
                $FindingDetails += Get-Acl -Path "$SSL_Path" | Format-Table -Wrap | Out-String
            }
            $FindingDetails += "-------------------------------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    if ( $ErrorCount -gt 0 ) {
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

Function Get-V214137 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214137
        STIG ID    : PGS9-00-010300
        Rule ID    : SV-214137r961596_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-DB-000385
        Rule Title : PostgreSQL must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.
        DiscussMD5 : C61078AB11F3DA422DAA12946DE529F7
        CheckMD5   : 7A0B2A00D2FF05956554329BF61F0AFE
        FixMD5     : ECF80B85D0D068B8633BE9EB3DC36B6D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "ssl_ca_file"
    $Result = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ( $null -eq $Result -or $Result -eq "" ) {
        $Result = "Parameter Not Found"
        $ErrorCount++
    }
   	$FindingDetails += "${PG_Parameter}:`n`t$($Result)`n" | Out-String

    Try {
        if ( $Result -ne "Parameter Not Found" ) {

            if ($($PgInstance.ContainerEngine) -eq "") {
                if (Test-Path -Path $Result) {
                    $Details = openssl x509 -noout -text -in "$($Result)" 2> /dev/null | Out-String
                }
                elseif ( Test-Path -Path "$($PgInstance.PG_DATA)/$($Result)") {
                    $Details = openssl x509 -noout -text -in "$($PgInstance.PG_DATA)/$($Result)" 2>/dev/null | Out-String
                }
                else {
                    $Details = "File Not Found"
                    $ErrorCount++
                }
            }
            else {
                $SSLCAPathCheck = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "test -f $Result && echo valid"
                $SSLCAFullPathCheck = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "test -f $($PgInstance.PG_DATA)/$Result && echo valid"
                if ($SSLCAPathCheck -eq "valid") {
                    $Details = openssl x509 -noout -text -in "$($Result)" 2>/dev/null | Out-String
                }
                elseif ( $SSLCAFullPathCheck -eq "valid") {
                    $Details = openssl x509 -noout -text -in "$($PgInstance.PG_DATA)/$($Result)" 2> /dev/null | Out-String
                }
                else {
                    $Details = "File Not Found"
                    $ErrorCount++
                }
            }
            $FindingDetails += "$($Result):`n`t$($Details)`n" | Out-String
        }

        $PG_Parameter = "ssl_cert_file"
        $Result = Get-PSQLVariable -PG_Parameter $PG_Parameter
        if ( $null -eq $Result -or $Result -eq "" ) {
            $Result = "Parameter Not Found"
            $ErrorCount++
        }

        $FindingDetails += "${PG_Parameter}:`n`t$($Result)`n" | Out-String

        if ( $Result -ne "Parameter Not Found" ) {
            if ($($PgInstance.ContainerEngine) -eq "") {
                if (Test-Path -Path $Result) {
                    $Details = openssl x509 -noout -text -in "$($Result)" 2> /dev/null | Out-String
                }
                elseif ( Test-Path -Path "$($PgInstance.PG_DATA)/$($Result)") {
                    $Details = openssl x509 -noout -text -in "$($PgInstance.PG_DATA)/$($Result)" 2> /dev/null | Out-String
                }
                else {
                    $Details = "File Not Found"
                    $ErrorCount++
                }
            }
            else {
                $SSLPathCheck = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "test -f $Result && echo valid"
                $SSLFullPathCheck = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "test -f $($PgInstance.PG_DATA)/$Result && echo valid"
                if ($SSLPathCheck -eq "valid") {
                    $Details = openssl x509 -noout -text -in "$($Result)" 2>/dev/null | Out-String
                }
                elseif ( $SSLFullPathCheck -eq "valid") {
                    $Details = openssl x509 -noout -text -in "$($PgInstance.PG_DATA)/$($Result)" 2> /dev/null | Out-String
                }
                else {
                    $Details = "File Not Found"
                    $ErrorCount++
                }
            }
            $FindingDetails += "$($Result):`n`t$($Details)`n" | Out-String
        }
    }
    Catch {
    }

    if ( $ErrorCount -gt 0 ) {
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

Function Get-V214138 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214138
        STIG ID    : PGS9-00-010400
        Rule ID    : SV-214138r960891_rule
        CCI ID     : CCI-000130
        Rule Name  : SRG-APP-000095-DB-000039
        Rule Title : PostgreSQL must produce audit records containing sufficient information to establish what type of events occurred.
        DiscussMD5 : DC9F82AF96376AF58DD6867477A7EB06
        CheckMD5   : AE7AB4EE055C72F0E6DAC47DACE5FA45
        FixMD5     : 2009414FD01DDFDB78858B16C2B28CF1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must be appropriate for the organization"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $LogPrefix = "Not Found"
        $Status = "Open"
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix

    $ErrorCount = 0
    $ExpectedValuesString = "on"
    $PG_Parameter = @('log_connections', 'log_disconnections')
    foreach ($parameter in $PG_Parameter) {
        $Connections = Get-PSQLVariable -PG_Parameter $parameter
        if ($null -eq $Connections -or $Connections -eq "") {
            $ErrorCount++
            $Connections = "Not Found"
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }
        else {
            $Checker = $Connections | Select-String -Pattern $ExpectedValuesString
            if ( $null -eq $Checker -or $Checker -eq "" ) {
                $ErrorCount++
            }
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }
    }

    if ( $ErrorCount -ge 2 ) {
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

Function Get-V214139 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214139
        STIG ID    : PGS9-00-010500
        Rule ID    : SV-214139r961602_rule
        CCI ID     : CCI-002476
        Rule Name  : SRG-APP-000429-DB-000387
        Rule Title : PostgreSQL must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.
        DiscussMD5 : 0F48CCE0DB62C7C50DED3D0E443B63BA
        CheckMD5   : 100C508786BB6212C41A3431195CABBD
        FixMD5     : 0332C61A689B11DF045544BE5EFB9790
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = "SELECT * FROM pg_available_extensions WHERE name='pgcrypto'"


    $FindingDetails += "Query:`t$($command)" | Out-String
    $FindingDetails += "------------------------------------------------------" | Out-String
    $FindingDetails += Invoke-PSQLQuery -ExpandTable -Query $command | Out-String
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214140 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214140
        STIG ID    : PGS9-00-010600
        Rule ID    : SV-214140r961113_rule
        CCI ID     : CCI-001185
        Rule Name  : SRG-APP-000220-DB-000149
        Rule Title : PostgreSQL must invalidate session identifiers upon user logout or other session termination.
        DiscussMD5 : 42CBD31F056367046DCABB0DF52CF065
        CheckMD5   : D3CCC6A609A7A4CFFB916736B9F90E92
        FixMD5     : 330AD88AEF397C7CCA4B96C76BF7C1E7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PG_Parameter = @('tcp_keepalives_idle', 'tcp_keepalives_interval', 'tcp_keepalives_count', 'statement_timeout')
    $ExpectedValuesString = "Must be set (Not 0)"

    foreach ($parameter in $PG_Parameter) {
        $PGVariable = Get-PSQLVariable -PG_Parameter $parameter
        if ($null -eq $PGVariable -or $PGVariable -eq "") {
            $ErrorCount++
            $PGVariable = "Not Found"
        }
        elseif ($PGVariable -eq "0") {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PGVariable
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

Function Get-V214141 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214141
        STIG ID    : PGS9-00-010700
        Rule ID    : SV-214141r960939_rule
        CCI ID     : CCI-001493
        Rule Name  : SRG-APP-000121-DB-000202
        Rule Title : PostgreSQL must protect its audit features from unauthorized access.
        DiscussMD5 : 2C14E00C29129F5A18EE4225B26A57BF
        CheckMD5   : B1A71909C54B50D91B39F56B90F5F7B6
        FixMD5     : 5BB605C2004DA385AABE5CFE23A7CD86
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PGAUDIT_FOUND = 0
    $PGPerms = "??????????"

    # Set to not reviewed if we can't find our log directory or log file.
    $LogDir = $PgInstance.LogDir
    if (Test-Path $LogDir -ErrorAction SilentlyContinue) {
        $FindingDetails += "Log Directory:`t`t`t${LogDir}" | Out-String
        if ($IsLinux) {
            $PGLogOwner = (stat -c "%U %G" ${LogDir})
            if ($($PgInstance.ContainerEngine) -eq "") {
                $FindingDetails += "Expected Ownership:`t$($PgInstance.PGUser) $($PgInstance.PGUser)" | Out-String
                if ($PGLogOwner -ne "$($PgInstance.PGUser) $($PgInstance.PGUser)") {
                    $ErrorCount++
                }
            }
        }
        else {
            $PGUser = $PgInstance.PGUser
            $IgnoreAccounts = @("NT AUTHORITY\\", "BUILTIN\\Administrators", "CREATOR OWNER")
            $IgnoreRegex = ($IgnoreAccounts | ForEach-Object { "(" + ($_) + ")" }) -join "|"
            $PGLogOwner = Get-FileOwner -Path $LogDir
            $FindingDetails += "Expected Ownership:`tDatabase Owner" | Out-String
            if (($PGLogOwner -notmatch $IgnoreRegex) -and ($PGLogOwner -ne $PGUser)) {
                $ErrorCount++
            }
        }

        $FindingDetails += "Detected Ownership:`t$PGLogOwner" | Out-String
        $FindingDetails += "" | Out-String

    }
    else {
        $FindingDetails += "Log Directory:`t`t`tNot Found" | Out-String
        $FindingDetails += "" | Out-String
    }

    $FindingDetails += "Data Directory:`t`t$($PgInstance.PG_DATA)" | Out-String
    # Set to not reviewed if we can't get the owner of PG_DATA.
    if ($IsLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $PGDataOwner = (stat -c "%U %G" $($PgInstance.PG_DATA))
        }
        else {
            $PGDataOwner = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "stat -c `"%U %G`" $($PgInstance.PG_DATA)"
        }

        #$PGDataOwner = (stat -c "%U %G" $($PgInstance.PG_DATA))
        $FindingDetails += "Expected Ownership:`t$($PgInstance.PGUser) $($PgInstance.PGUser)" | Out-String
        if ($null -ne $PGDataOwner -and $PGDataOwner -ne "") {
            $FindingDetails += "Detected Ownership:`t$($PGDataOwner)" | Out-String
            if ($PGDataOwner -ne "$($PgInstance.PGUser) $($PgInstance.PGUser)") {
                $ErrorCount++
            }

        }
        else {
            $FindingDetails += "Detected Ownership:`tCould not determine owner of PGDATA" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    else {
        $PGDataOwner = Get-Acl -Path $($PgInstance.PG_DATA)
        $FindingDetails += "Expected Ownership:`tDatabase Owner" | Out-String
        if ($null -ne $PGDataOwner -and $PGDataOwner -ne "") {
            $FindingDetails += "Detected Ownership:`t$($PGDataOwner.owner)" | Out-String
            $FindingDetails += "" | Out-String

            if (($PGDataOwner.owner -notmatch $IgnoreRegex) -and ($PGDataOwner.owner -ne $PGUser)) {
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "Detected Ownership:`tCould not determine owner of PGDATA" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    # Set to not reviewed if we can't find PGAUDIT
    $QueriesToRun = @("SELECT setting FROM pg_config WHERE name = 'PKGLIBDIR'", "SELECT setting FROM pg_config WHERE name = 'SHAREDIR'")

    foreach ($Query in $QueriesToRun) {
        $DirToCheck = Invoke-PSQLQuery -ExpandTable -Query $Query
        if ( $null -ne $DirToCheck -and $DirToCheck -ne "" ) {

            $DirToCheck = (($DirToCheck | Select-Object -Index 1) -split '\|')[1]
            $DirToCheck = $DirToCheck.Trim()
            if ($Query.Contains('SHAREDIR')) {
                $DirToCheck = "$DirToCheck/./extension/" -replace '\s/', '/'
            }
            elseif ($Query.Contains('PKGLIBDIR')) {
                $DirToCheck = "$DirToCheck/." -replace '\s/', '/'
            }
            if ($isLinux) {
                if ($($PgInstance.ContainerEngine) -eq "") {
                    $PGAuditFiles = ls -la $DirToCheck | grep -v "^total" | grep -v "\.\." | grep "pgaudit"
                }
                else {
                    $PGAuditFiles = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -la $DirToCheck | grep -v `"^total`" | grep -v `"\.\.`" | grep `"pgaudit`""
                }

            }
            else {
                $PGAuditFiles = (Get-ChildItem -Path $DirToCheck -File -Force | Where-Object {$_.name -Like "*pgaudit*"}).FullName
            }
            if ($null -ne $PGAuditFiles -and $PGAuditFiles -ne "") {
                $FindingDetails += "" | Out-String
                $FindingDetails += "PGAudit Install:`t`t$DirToCheck" | Out-String
                $PGAUDIT_FOUND++
                foreach ($line in $PGAuditFiles) {
                    if ($IsLinux) {
                        if ($line | Select-String -Pattern "pgaudit") {
                            $FileOwner = $line | awk '{print $3}'
                            $FileGroup = $line | awk '{print $4}'
                            $FindingDetails += $line | Out-String
                            if ($FileOwner -ne "root" -or $FileGroup -ne "root") {
                                $ErrorCount++
                            }
                        }
                    }
                    else {
                        $FindingDetails += Get-FormattedFileListing -listing $line -limit 15 | Out-String
                        $PostgresUser = $PgInstance.PGUser
                        $CheckVar = $false
                        $CheckVar = Test-FileListingToPermsAndOwner -listing $line -FileOwner $PostgresUser -FilePerms $PGPerms
                        if ( -not ( $CheckVar )) {
                            $ErrorCount++
                        }
                    }
                }
            }
        }
    }
    if ($PGAUDIT_FOUND -eq 0 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "PGAudit Install:`t`tCould not find PGAudit in expected location(s)" | Out-String
        $FindingDetails += "" | Out-String
    }

    $DBQuery = '\du'
    $SearchPattern = 'Attributes.*Superuser'
    $FindingDetails += "" | Out-String
    $FindingDetails += 'Roles with Superuser rights' | Out-String
    $FindingDetails += Get-PgRecordFromMeta -command $DBQuery -SearchPattern $SearchPattern

    $GoodSuperuser = 0
    $SearchPattern = 'Attributes.*Superuser'
    $ResultArray = Invoke-PSQLQuery -ExpandTable -Query $DBQuery

    foreach ($line in $ResultArray) {
        $SearchPattern = "Role Name.*"
        $Rolename = $line | Select-String -Pattern "$SearchPattern"
        if ($null -ne $Rolename -and $Rolename -ne "") {
            $SearchPattern = "Role Name.*$($PgInstance.PGUser)"
            $Superuser = $line | Select-String -Pattern "$SearchPattern"
            if ($null -ne $Superuser -and $Superuser -ne "") {
                $GoodSuperuser++
            }
            else {
                $GoodSuperuser = 0
                break
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        if ($GoodSuperuser -eq 1 -and $PGAUDIT_FOUND -gt 0) {
            if ($($PgInstance.ContainerEngine) -eq "") {
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

Function Get-V214142 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214142
        STIG ID    : PGS9-00-011100
        Rule ID    : SV-214142r960894_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-DB-000040
        Rule Title : PostgreSQL must produce audit records containing time stamps to establish when the events occurred.
        DiscussMD5 : BF33D539A0AD4C069AD22D28189E8C4A
        CheckMD5   : CBC93FC6C45AFCD6AEF93EAD296BEF80
        FixMD5     : DFD5A2FDAC75C283E8398B833523A17B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "log_line_prefix"
    $ExpectedValuesString = "Must contain %m"
    $LogPrefix = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $LogPrefix -or $LogPrefix -eq "") {
        $ErrorCount++
        $LogPrefix = "Not Found"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix
    }
    else {
        $Checker = $LogPrefix | Select-String -Pattern "%m"
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogPrefix
    }

    if ( $ErrorCount -ge 1 ) {
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

Function Get-V214143 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214143
        STIG ID    : PGS9-00-011200
        Rule ID    : SV-214143r960945_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-APP-000123-DB-000204
        Rule Title : PostgreSQL must protect its audit features from unauthorized removal.
        DiscussMD5 : C1114182B0C863335B7FCC7C341CD9E4
        CheckMD5   : 9AE9E0AD5D07539613E37207C7F55071
        FixMD5     : 9809805BB25A416AB2857BF0ACA6F73B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $DirsNotFound = 0
    $PostgresUser = $PgInstance.ProcessUser
    $PGPerms = "????------"

    if ($IsLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $PGDataFiles = ls -la $PgInstance.PG_DATA | grep -v "^total" | grep -v "\.\."
        }
        else {
            $PGDataFiles = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -la $($PgInstance.PG_DATA) | grep -v `"^total`" | grep -v `"\.\.`""
        }

    }
    else {
        $PGDataFiles = Get-ChildItem -Path "$($PgInstance.PG_DATA)" -File | ForEach-Object { $_.FullName }
    }

    if ( $null -ne $PGDataFiles -and $PGDataFiles -ne "" ) {
        $FindingDetails += "Directory:`t`t$($PgInstance.PG_DATA)" | Out-String
        if ($IsLinux) {
            $FindingDetails += $PGDataFiles | Out-String
        }
        else {
            $FindingDetails += Get-FormattedFileListing -listing $PGDataFiles -limit 5 | Out-String
        }

        $CheckVar = Test-FileListingToPermsAndOwner -listing $PGDataFiles -FileOwner $PostgresUser -FilePerms $PGPerms

        if ( -not ( $CheckVar )) {
            $ErrorCount++
        }
    }
    else {
        $FindingDetails += "PG_Data:`tNot Found" | Out-String
    }
    $FindingDetails += "" | Out-String

    $QueriesToRun = @("SELECT setting FROM pg_config WHERE name = 'BINDIR'", "SELECT setting FROM pg_config WHERE name = 'INCLUDEDIR'", "SELECT setting FROM pg_config WHERE name = 'LIBDIR'", "SELECT setting FROM pg_config WHERE name = 'SHAREDIR'")
    foreach ($Query in $QueriesToRun) {

        $DirToCheck = Invoke-PSQLQuery -ExpandTable -Query $Query
        if ( $null -ne $DirToCheck -and $DirToCheck -ne "" ) {
            $DirToCheck = (($DirToCheck | Select-Object -Index 1) -split '\|')[1] | Out-NormalizedPath
            $DirToCheck = $DirToCheck.Trim()
        }
        if ($null -ne $DirToCheck) {
            $FindingDetails += "Directory:`t`t$DirToCheck" | Out-String
            if ($IsLinux) {
                if ($($PgInstance.ContainerEngine) -eq "") {
                    $PGDataFiles = ls -la $DirToCheck | grep -v "^total" | grep -v "\.\."
                }
                else {
                    $PGDataFiles = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -la $DirToCheck 2>/dev/null | grep -v `"^total`" | grep -v `"\.\.`""
                }

                foreach ($line in $PGDataFiles) {
                    $FileOwner = $line | awk '{print $3}'
                    $FileGroup = $line | awk '{print $4}'
                    $FindingDetails += $line | Out-String
                    if ($FileOwner -ne "root" -or $FileGroup -ne "root") {
                        $ErrorCount++
                    }
                }
            }
            else {
                $PGDataFiles = Get-ChildItem -Path "$DirToCheck" -File | ForEach-Object { $_.FullName }
                $FindingDetails += Get-FormattedFileListing -listing $PGDataFiles -limit 10 | Out-String
                $CheckVar = Test-FileListingToPermsAndOwner -listing $PGDataFiles -FileOwner $PostgresUser -FilePerms $PGPerms

                if ( -not ( $CheckVar )) {
                    $ErrorCount++
                }
            }
        }
        else {
            $FindingDetails += 'Directory for query "', ${Query}, '" Not Found'
            $FindingDetails += "" | Out-String
            $DirsNotFound++
        }
        $FindingDetails += "" | Out-String
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        if ( $DirsNotFound -eq 0 ) {
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

Function Get-V214144 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214144
        STIG ID    : PGS9-00-011300
        Rule ID    : SV-214144r961860_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000515-DB-000318
        Rule Title : PostgreSQL must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.
        DiscussMD5 : A0A0099BC61501FB12DC218A7D1F84E6
        CheckMD5   : EB74B1B3BBB67DDD1FCF4A7FD5281420
        FixMD5     : FB3BDB92C653E815F60F4F0AA3EBC15D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PG_Parameter = "log_destination"
    $ExpectedValuesString = "syslog"
    $LogDest = $PgInstance.LogDest
    if ($null -eq $LogDest -or $LogDest -eq "") {
        $ErrorCount++
        $LogDest = "No value returned from query"
    }
    else {
        $Checker = $LogDest | Select-String -Pattern "syslog"
        if ($null -eq $Checker -or $Checker -eq "") {
            $ErrorCount++
        }
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $LogDest

    $PG_Parameter = "syslog_facility"
    $SysLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    $ExpectedValuesString = "As defined by organization"
    if ($null -eq $SysLog -or $SysLog -eq "") {
        $SysLog = "No value returned from query"
    }
    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $SysLog

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
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

Function Get-V214145 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214145
        STIG ID    : PGS9-00-011400
        Rule ID    : SV-214145r961119_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-DB-000384
        Rule Title : PostgreSQL must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.
        DiscussMD5 : 7CC1C85AA2A6EB565F6E415CF01FD2E7
        CheckMD5   : 5EC92300CC457645BFD47A475B7FDFBA
        FixMD5     : 2FA5E468D06C852B0200AD34947BC422
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $QuerySetting = "ssl"
    $ExpectedValuesString = "on"

    $QueryResult = Get-PSQLVariable -PG_Parameter $QuerySetting
    if ($null -eq $QueryResult -or $QueryResult -eq "") {
        $ErrorCount++
        $QueryResult = "No value returned from query"
    }
    else {
        if ($QueryResult | Select-String -Pattern "$ExpectedValuesString" -NotMatch) {
            $ErrorCount++
        }
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $QuerySetting -ExpectedValue $ExpectedValuesString -DetectedValue $QueryResult

    if ($ErrorCount -gt 0) {
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

Function Get-V214146 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214146
        STIG ID    : PGS9-00-011500
        Rule ID    : SV-214146r960969_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-APP-000148-DB-000103
        Rule Title : PostgreSQL must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).
        DiscussMD5 : 173DC404230EA419E51001CFF125D454
        CheckMD5   : 40C0A27721538B1F3C6AF30800901EAD
        FixMD5     : EA2B044E8723446F10137660BE6CB02E
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DBQuery = '\du'
    $DBArray = Invoke-PSQLQuery -ExpandTable -Query $DBQuery

    foreach ($line in $DBArray) {
        $FindingDetails += $line | Out-String
    }
    $FindingDetails += "" | Out-String

    $PgConfigFile = "$($PgInstance.PG_DATA)/pg_hba.conf"
    $ConfigLines = Get-PostgresConfigContent $PgConfigFile
    $FindingDetails += "Configured authentication settings" | Out-String
    $FindingDetails += "TYPE  DATABASE        USER            ADDRESS                 METHOD" | Out-String
    foreach ($line in $ConfigLines) {
        $FindingDetails += $line.ConfigLine | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214149 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214149
        STIG ID    : PGS9-00-011800
        Rule ID    : SV-214149r961044_rule
        CCI ID     : CCI-000187
        Rule Name  : SRG-APP-000177-DB-000069
        Rule Title : PostgreSQL must map the PKI-authenticated identity to an associated user account.
        DiscussMD5 : C6A2FE2D4935F82AE306F309CC5AF9CB
        CheckMD5   : 9B59FC8D66D2243BE4CBA24F48AEDA9C
        FixMD5     : FC711CCB9BF7B509D9681AB3A1F31D4D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MapNames = [System.Collections.ArrayList]@()

    # Get any mapped values in pg_hba.conf
    # Mapped values will have 'map=SomeName' at the end of the line.
    # Mappings need to match up the cn to mappings in the pg_hba.conf and pg_ident.conf files.

    $MapPattern = "map\s*=.*" # There may be a better way to do this. I am open to ideas.
    $PgConfigFile = "$($PgInstance.PG_DATA)/pg_hba.conf"
    $MappedLines = Get-PostgresConfigContent -ConfigFile $PgConfigFile -SearchPattern $MapPattern
    foreach ($mapLine in $MappedLines) {
        if ($mapLine.ConfigLine -eq "Not Found") {
            # We didn't find any line with a mapped name.
            break
        }

        $LineSplit = $mapLine.ConfigLine -split '\s+'
        foreach ($line in $LineSplit) {
            $IsMatch = $line | grep $MapPattern
            if ($null -eq $IsMatch -or $IsMatch -eq "") {
                continue
            }

            $MapName = ($line -split '=')[1]
            if ($MapNames.Contains($MapName)) {
                continue
            }

            [void]$MapNames.Add($MapName)
        }
    }

    if ($MapNames.Count -lt 1) {
        # We didn't find any mapped names.
        $FindingDetails += "There are no mapped names in pg_hba.conf." | Out-String
    }
    else {
        # We have some mapped users. Let's find out who they are mapped to in pg_ident.conf
        # The format of this file is as follows 'map-name system-username database-username'
        # The map-name is whatever map=SomeName is in pg_hba.conf
        # If we find any names that match the pg_hba.conf map name, we will create an object containing
        # entries in pg_ident.conf so that we can display it nicely later on.
        $IdentMapObjects = [System.Collections.ArrayList]@()
        $PgIdentFile = "$($PgInstance.PG_DATA)/pg_ident.conf"
        $IdentLines = Get-PostgresConfigContent -ConfigFile $PgIdentFile

        foreach ($line in $IdentLines) {
            if ($line.ConfigLine -eq "Not Found") {
                break
            }

            # Split out the 'map-name system-username database-username'
            # I'm not sure how to handle a line ending with a backslash.
            # Apparently, a user can use a backslash at the end of a line
            # to 'continue' the current line. It's a way to visually break
            # up the config line. It's odd, but something we may have to deal
            # with in the future.

            $LineSplit = $line.ConfigLine -split '\s+'
            $IdentMapName = $LineSplit[1]
            $IdentSystemUser = $LineSplit[2]
            $IdentDatabaseUser = $LineSplit[3]

            # We have matched a pg_hba.conf map name with a pg_ident map name
            $NewObj = [PSCustomObject]@{
                IdentMapName      = $IdentMapName
                IdentSystemUser   = $IdentSystemUser
                IdentDatabaseUser = $IdentDatabaseUser
            }

            [void]$IdentMapObjects.Add($NewObj)
        }

        if ($IdentMapObjects.Count -lt 1) {
            # We didn't find any mapped names.
            $FindingDetails += "There are no mapped names in pg_ident.conf." | Out-String
        }
        else {
            # Let's display everything.
            foreach ($mapName in $MapNames) {

                $TempDetails = $null
                foreach ($identMap in $IdentMapObjects) {
                    # Loop over mapped ident users onyl displaying the ones that match the pg_hba.conf entry.
                    $IsMatch = $mapName.Trim() | grep $identMap.IdentMapName.Trim()
                    if ($null -eq $IsMatch -or $IsMatch -eq "") {
                        continue
                    }

                    $TempDetails += "pg_ident Map Name:`t$($identMap.IdentMapName)" | Out-String
                    $TempDetails += "Server User:`t`t`t$($identMap.IdentSystemUser)" | Out-String
                    $TempDetails += "Database User:`t`t$($identMap.IdentDatabaseUser)" | Out-String
                }

                if ($null -ne $TempDetails) {
                    $FindingDetails += "pg_hba Map Name:`t`t$($mapName)" | Out-String
                    $FindingDetails += "$($TempDetails)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                else {
                    $FindingDetails += "pg_hbaMap Name:`t`t$($mapName)" | Out-String
                    $FindingDetails += "Server User:`t`t`tNo User Found" | Out-String
                    $FindingDetails += "Database User:`t`tNo User Found" | Out-String
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

Function Get-V214151 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214151
        STIG ID    : PGS9-00-012000
        Rule ID    : SV-214151r961149_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-APP-000243-DB-000374
        Rule Title : Access to database files must be limited to relevant processes and to authorized, administrative users.
        DiscussMD5 : 8D832F17C48F689196FC91EEA58A2645
        CheckMD5   : A4CBA0DD1CFA9DECA7F91342554F4F49
        FixMD5     : F3F36C6E6E318C792EA829B0C0E00FCD
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PGPerms = "????------"
    $PostgresUser = $PgInstance.PGUser
    $ErrorCount = 0
    if ($isLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $Listing = ls -lR $PgInstance.PG_DATA
        }
        else {
            $Listing = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -lR $($PgInstance.PG_DATA)"

        }
    }
    else {
        $Listing = Get-ChildItem -Path $($PgInstance.PG_DATA) -Recurse -File | ForEach-Object { $_.FullName }
    }
    $FindingDetails += "Permissions for $($PgInstance.PG_DATA) and Sub Folders" | Out-String
    $FindingDetails += "------------------------------------------------------------------------" | Out-String

    if ($isLinux) {
        $FindingDetails += $Listing | Out-String
        foreach ($list in $Listing) {
            $FindingDetails += "$($list)" | Out-String
            #Filter out non file lines from recursive ls
            $IsFile = ($list -split " ")[0] | grep -vE "^total" | grep -vE "^/"
            if (($null -ne "$IsFile") -and ("$IsFile" -ne "") ) {

                $CheckVar = Test-FileListingToPermsAndOwner -listing $list -FileOwner $PostgresUser -FilePerms $PGPerms

                if ( -not ( $CheckVar )) {
                    $ErrorCount++
                    break
                }
            }
        }
    }
    else {
        $FindingDetails += Get-FormattedFileListing -listing $Listing -limit 20 | Out-String
        foreach ($list in $Listing) {
            $CheckVar = Test-FileListingToPermsAndOwner -listing $list -FileOwner $PostgresUser -FilePerms $PGPerms
            if ( -not ( $CheckVar )) {
                $ErrorCount++
                break
            }
        }
    }
    if ($ErrorCount -gt 0) {
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

Function Get-V214152 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214152
        STIG ID    : PGS9-00-012200
        Rule ID    : SV-214152r960942_rule
        CCI ID     : CCI-001494
        Rule Name  : SRG-APP-000122-DB-000203
        Rule Title : PostgreSQL must protect its audit configuration from unauthorized modification.
        DiscussMD5 : BAD489896569CF47A0C4EDED4E112ACB
        CheckMD5   : E62CDDC1347A2CD82C06B06D275CE7FA
        FixMD5     : 49565B696932270677020A275AEE5912
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $PGPerms = "-rw-------"
    $FindingDetails += "PostgreSQL Configuration File:" | Out-String
    $FindingDetails += "" | Out-String
    if ($isLinux) {
        if ($($PgInstance.ContainerEngine) -eq "") {
            $listing = ls -la $($PgInstance.PG_DATA) | grep -i postgresql.conf
        }
        else {
            $listing = Invoke-ContainerCommand -Engine $($PgInstance.ContainerEngine) -Container $($PgInstance.ContainerName) -Command "ls -la $($PgInstance.PG_DATA) |  grep -i postgresql.conf"
        }

        $PermTest = Test-FileListingToPermsAndOwner -listing $listing -FileOwner $PgInstance.PGUser -FilePerms $PGPerms
        $FindingDetails += $listing | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $listing = (Get-ChildItem -Path $($PgInstance.PG_DATA) -File -Force | Where-Object {$_.name -Like "postgresql.conf"} | Select-Object FullName).FullName
        $FindingDetails += Get-FormattedFileListing -listing $listing -limit 2 | Out-String
        $PermTest = Test-FileListingToPermsAndOwner -listing $listing -FileOwner $PgInstance.PGUser -FilePerms $PGPerms
    }

    if ( -not ( $PermTest )) {
        $ErrorCount++
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }

    $PGPerms = "???-------"
    $PG_Parameter = "log_file_mode"
    $LogFileMode = Get-PSQLVariable -PG_Parameter $PG_Parameter
    $FindingDetails += "${PG_Parameter}:`t`t$LogFileMode" | Out-String
    if ( $LogFileMode -ne "0600" ) {
        $ErrorCount++
    }

    $LogDir = $PgInstance.LogDir

    if (Test-Path $LogDir -ErrorAction SilentlyContinue) {
        if ($isLinux) {
            $listing = ls -l "$LogDir" | grep '^-' | grep '\.log$'
        }
        else {
            $listing = (Get-ChildItem -Path "$LogDir" | Select-Object FullName).FullName
        }

        $FindingDetails += "Log Directory:`t`t${LogDir}" | Out-String
        $FindingDetails += "" | Out-String

        if ( $null -ne $listing -and $listing -ne "" ) {
            if ($isLinux) {
                $FindingDetails += $listing | Out-String
            }
            else {
                $FindingDetails += Get-FormattedFileListing -listing $listing -limit 10 | Out-String
            }

            $CheckVar = Test-FileListingToPerms -listing $listing -FilePerms $PGPerms

            if ( -not ( $CheckVar )) {
                $ErrorCount++
            }
        }
        else {
            $FindingDetails += "Directory is empty"
        }
    }
    else {
        $FindingDetails += "Log Directory: $($LogDir)`t`t`tNot Found" | Out-String
        $FindingDetails += "" | Out-String
        $ErrorCount++
    }

    $LogDest = $PgInstance.LogDest
    if ($null -ne $LogDest -and $LogDest -ne "") {
        $IsSyslog = $LogDest | Select-String -Pattern "syslog"
    }

    if ($Status -eq "Not_Reviewed") {
        if ( -Not ($IsSyslog)) {
            if ( $ErrorCount -gt 0 ) {
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

Function Get-V214153 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214153
        STIG ID    : PGS9-00-012300
        Rule ID    : SV-214153r961050_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-APP-000179-DB-000114
        Rule Title : PostgreSQL must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.
        DiscussMD5 : DDD51CEEA6AB579B2A4C301703945DA5
        CheckMD5   : 617933F5F5B7B467E75DF6B31504FB8E
        FixMD5     : 5F2286B49E1EDD7D97C8325092579D44
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    Try {
        if($isLinux) {
            if ($PgInstance.ContainerEngine -eq "") {
                $OpenSslVersion = & openssl version 2>/dev/null
            }
            else {
                $OpenSslVersion = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "openssl version 2>/dev/null"
            }
        }
        else {
            $OpenSslVersion = cmd /c openssl version '2>nul'
        }
    }
    Catch {
        $OpenSslVersion = $null
    }

    if ($null -eq $OpenSslVersion -or $OpenSslVersion -eq "") {
        $ErrorCount++
        $OpenSslVersion = "The command 'openssl version' did not generate a result"
    }
    else {
        $v3Check = ($OpenSslVersion -split(' '))[1]
        if ($v3Check | Select-String '^3') {
            Try {
                if ($isLinux) {
                    $Fips = fips-mode-enabled --check 2>$null
                    if ($Fips | Select-String -Pattern "enabled") {
                        $OpenSslVersion = $OpenSslVersion + $Fips
                    }
                    else {
                        $ErrorCount++
                    }
                }
            }
            Catch {
                $FindingDetails += "FIPS mode could not be determined." | Out-String
            }
        }
        else {
            $Fips = $OpenSslVersion | Select-String -Pattern "fips"
            if ($null -eq $Fips -or $Fips -eq "") {
                $ErrorCount++
            }
        }
    }

    $ExpectedValue = "fips included in the openssl version"
    $FindingDetails += "Command: `t`topenssl version" | Out-String
    $FindingDetails += "Expected Value: `t$ExpectedValue" | Out-String
    $FindingDetails += "Detected Value: `t$OpenSslVersion" | Out-String

    if ( $ErrorCount -gt 0 ) {
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

Function Get-V214154 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214154
        STIG ID    : PGS9-00-012500
        Rule ID    : SV-214154r961821_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000502-DB-000348
        Rule Title : Audit records must be generated when categorized information (e.g., classification levels/security levels) is deleted.
        DiscussMD5 : F44617087F7F84FCE843ABA1F9186C40
        CheckMD5   : 4B3960EA51B2A918E9F04229375453B2
        FixMD5     : D0E5003B0A579F9F7476B60FA448C951
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214155 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214155
        STIG ID    : PGS9-00-012600
        Rule ID    : SV-214155r961836_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000507-DB-000356
        Rule Title : PostgreSQL must generate audit records when successful accesses to objects occur.
        DiscussMD5 : 950ECBF973E593C80C1E6B40915BE750
        CheckMD5   : A07FE95D3AEB2949CFD0FEEF0BCA61E4
        FixMD5     : 4446E0B6411259A2099F4700AEBFCCAA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $PG_Parameter = "pgaudit.log"
    $ExpectedValuesString = "contains role, read, write, and ddl"
    $AuditLog = Get-PSQLVariable -PG_Parameter $PG_Parameter
    if ($null -eq $AuditLog -or $AuditLog -eq "") {
        $AuditLog = "Not Found"
        $ErrorCount++
    }
    else {
        $GoodValues = $AuditLog | Select-String 'ddl' | Select-String 'write' | Select-String 'role' | Select-String 'read'
        if ($null -eq $GoodValues -or $GoodValues -eq "" ) {
            if ($AuditLog -notmatch '\ball\b') {
                $ErrorCount++
            }
        }
        else {
            if ($AuditLog | Select-String -Pattern "-ddl|-write|-role|-read") {
                $ErrorCount++
            }
        }
    }

    if ( $ErrorCount -gt 0 ) {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
    }

    $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $AuditLog
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V214156 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214156
        STIG ID    : PGS9-00-012700
        Rule ID    : SV-214156r961839_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000508-DB-000358
        Rule Title : PostgreSQL must generate audit records for all direct access to the database(s).
        DiscussMD5 : 6A46392311E5291E31088C064110ACC5
        CheckMD5   : 4CEE986F5A8AE3A1252BF1808466B6C4
        FixMD5     : D590265AB62DC008257721BCBF3CC9EA
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
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
    $ExpectedValuesString = "pgaudit"
    $PG_Parameter = "shared_preload_libraries"
    $PreLibraries = Get-PSQLVariable -PG_Parameter $PG_Parameter

    if ($null -eq $PreLibraries -or $PreLibraries -eq "") {
        $ErrorCount++
        $PreLibraries = "No value returned from query"
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }
    else {
        $Checker = $PreLibraries | Select-String -Pattern $ExpectedValuesString
        if ( $null -eq $Checker -or $Checker -eq "" ) {
            $ErrorCount++
        }
        $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $PG_Parameter -ExpectedValue $ExpectedValuesString -DetectedValue $PreLibraries
    }

    $ExpectedValuesString = "on"
    $PG_Parameter = @('log_connections', 'log_disconnections')
    foreach ($parameter in $PG_Parameter) {
        $Connections = Get-PSQLVariable -PG_Parameter $parameter
        if ($null -eq $Connections -or $Connections -eq "") {
            $ErrorCount++
            $Connections = "Not Found"
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }
        else {
            $Checker = $Connections | Select-String -Pattern $ExpectedValuesString
            if ( $null -eq $Checker -or $Checker -eq "" ) {
                $ErrorCount++
            }
            $FindingDetails += Get-PostgresFormattedOutput -PG_Parameter $parameter -ExpectedValue $ExpectedValuesString -DetectedValue $Connections
        }
    }

    if ( $ErrorCount -ge 1 ) {
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

Function Get-V265877 {
    <#
    .DESCRIPTION
        Vuln ID    : V-265877
        STIG ID    : PGS9-00-012900
        Rule ID    : SV-265877r999537_rule
        CCI ID     : CCI-003376
        Rule Name  : SRG-APP-000456-DB-000400
        Rule Title : PostgreSQL products must be a version supported by the vendor.
        DiscussMD5 : 5EF8FC79032EE1F24369C26E2C039E10
        CheckMD5   : AA12CADFEE5ABDFD15E5D8F03CB821F6
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
    $ErrorCount = 0

    # Some notes about this check.
    # The check shows you how to obtain software versions using APT
    # BUT, running the provided command will not work for some reason.
    # PowerShell will treat 'apt-cache' as a PowerShell command.
    # The psql --version command should be good enough since we know PG
    # Should be running on the target machine.

    if ($IsLinux) {
        if ($PgInstance.ContainerEngine -eq "") {
            $Version = & "$($PgInstance.PSQL)" --version
            $HeaderName = "RPMs"
            $RpmVersion = $(rpm -qa | grep postgres)
        }
        else {
            $Version = Invoke-ContainerCommand -Engine $PgInstance.ContainerEngine -Container $PgInstance.ContainerName -Command "$($PgInstance.PSQL) --version"
        }
    }
    else {
        $Version = & "$($PgInstance.PSQL)" --version
        $RegPaths = Get-ChildItem "HKLM:\Software\PostgreSQL\Installations"
        foreach ($Path in $RegPaths) {
            $SearchPath = "Registry::$($PATH)"
            $PackageName = Get-ItemPropertyValue -Path $SearchPath -Name "Branding"
            $VersionNum = Get-ItemPropertyValue -Path $SearchPath -Name "Version"
            $RpmVersion += "$PackageName Version: $VersionNum" | Out-String
        }
        $HeaderName = "Installed Versions"
    }
    if ($null -ne $Version -and $Version -ne "") {
        $FindingDetails += "Version:`n$($Version)" | Out-String
        $FindingDetails += "" | Out-String

        if ($Version | Select-String -Pattern " 9\.") {
            $ErrorCount++
        }
    }

    if ($null -ne $RpmVersion -and $RpmVersion -ne "") {
        $FindingDetails += "$($HeaderName):" | Out-String
        foreach ($rpm in $RpmVersion) {
            $FindingDetails += "$($rpm)" | Out-String

            if ($rpm | Select-String -Pattern "-9\.") {
                $ErrorCount++
            }
        }
    }
    $FindingDetails += "" | Out-String

    If ($ErrorCount -gt 0) {
        $Status = "Open"
        $FindingDetails += "PostgreSQL 9 is installed.  [finding]" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "PostgreSQL 9 is not installed." | Out-String
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails -Algorithm SHA1
    }
    else {
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status
        FindingDetails   = $FindingDetails
        AFKey            = $AFkey
        AFStatus         = $AFStatus
        Comments         = $Comments
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDnOBYdFGbkfCGY
# TSGeDaEjPVANKPZ3wtFtO+U/8KgZSqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCAMn4GciD9TQ8IHCm3Srm5JPvWk2zxFQLTvKlGWWt/p5DANBgkqhkiG9w0BAQEF
# AASCAQBCtsnsQWPpDcDUlwx4cGLmo21aWLRbXcmiSAJtsJ62+MA4IpoluTBhmGtZ
# GbNgv7LJmUYTaOqSD4RgmJK89iA5sZQWL/pKYhDZFA6UjGWXQ1U4WKLSfaDMqIZh
# XkURzzQx7FaGA8+1VS1rj0fmTv2ULPdyTw+y+MhR+7JuwWA5RidPO5SdnrfsiHWT
# Fz7PqkTzJk+jQ9axDr6e9el7387Z7otbpc+o2UPF6rZQqYi1sC+LtLARdO7a3FxM
# rVumIBt0LbaGn8V+YbZjco8bUgkOecddiqfVwVLthG+nIQIK9NoZIz1CfHV38CBt
# z9Stuj+AGnPfzYaC6j1LrrzkbZlDoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTcwN1owLwYJKoZIhvcNAQkEMSIEIJL60sintlE82lRtcFMf/tpEeZ93
# xvTLgv3BlDfp2nqTMA0GCSqGSIb3DQEBAQUABIICAGKk7QJTpe+8/SYtvDz82KVP
# ZNqPQBMCVonmUsqCyJJayXncoqr1O9bXxnXkjdhTIWG+r13Cys9kR1Et8aLTVLUW
# oadd/o8j8t/oSoZPnEEZN1UZoZsv8wgV1K8C2hRDiHt/aRZtZOQBPA3ahVFGjUTw
# uIxN2OMoZFY/uaHqvzwC2y4zZP2CatZdUxmMkwoZrj6WggjIX5iF3DtjLVjZB7hd
# AUvU9dHUVRwpes6bAlKpk6ewDasGlA6WaUiuqtBEPwzp/DLaz3s/VZ1Z1F70BU9I
# el3Pyhdjt6v0xtDTRcjaP4JrkPdvnt+/mPcpLFXFGmHeeDfYHd6O7tldY+UqkDXN
# 3cE+rglUDEFO9KoH+TjpShBB5XbZrQ3JGdD9zXxqUj4m3hkeL5akSdPoefz1/iJM
# OqATH4E3O812Tu1etQSL2jxqh2NA25XImopAChP4wcHtxV7C+1KC7BzJ/zrPWIyQ
# /4/XjTAb6ivnTg139HUcvOpKhP19p+naostaxHToFC4WlA3W/nHhBrz/BwyE8G12
# xFHNfp/bjYaTGBWm1yTTmWepxWypb+gQBoIZvy+EuD7i1otFkrLt+AYizxZko0wO
# DcYPJY754VMbq8qvM5SmxlkoXWMd+zkNN+QDaw1U9jALii7+oaecBmC9+X4lu6FU
# VwPb6MeCaqrL0qC1rjLh
# SIG # End signature block
