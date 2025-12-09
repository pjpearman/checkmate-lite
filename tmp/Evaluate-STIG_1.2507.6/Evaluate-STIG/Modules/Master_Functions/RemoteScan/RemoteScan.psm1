Function Invoke-RemoteScan {
    Param (
        # Evaluate-STIG parameters
        [Parameter(Mandatory = $true)]
        [String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$Marking,

        [Parameter(Mandatory = $false)]
        [String]$TargetComments,

        [Parameter(Mandatory = $false)]
        [Int]$VulnTimeout = 15,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$AFPath,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey = "DEFAULT",

        [Parameter(Mandatory = $false)]
        [String[]]$Output = "",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$OutputPath,

        [Parameter(Mandatory = $false)]
        [Int]$PreviousToKeep,

        [Parameter(Mandatory = $false)]
        [SecureString]$SMPassphrase,

        [Parameter(Mandatory = $false)]
        [String]$SMCollection,

        [Parameter(Mandatory = $false)]
        [String]$SplunkHECName,

        [Parameter(Mandatory = $false)]
        [Switch]$ApplyTattoo,

        [Parameter(Mandatory = $false)]
        [Switch]$AllowDeprecated,

        [Parameter(Mandatory = $false)]
        [Switch]$AllowSeverityOverride,

        [Parameter(Mandatory = $false)]
        [Switch]$AllowIntegrityViolations,

        [Parameter(Mandatory = $false)]
        [Array]$SelectSTIG,

        [Parameter(Mandatory = $false)]
        [Array]$SelectVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeVuln,

        [Parameter(Mandatory = $false)]
        [Array]$OutputPayload,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeSTIG,

        [Parameter(Mandatory = $false)]
        [Array]$ForceSTIG,

        [Parameter(Mandatory = $false)]
        [Switch]$AltCredential,

        [Parameter(Mandatory = $false)]
        [Int]$ThrottleLimit = 10,

        # Remote scan parameters
        [Parameter(Mandatory = $true)]
        [String]$ESVersion,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ES_Path,

        [Parameter(Mandatory = $true)]
        [String] $RemoteScanDir,

        [Parameter(Mandatory = $true)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $true)]
        [String] $PowerShellVersion
    )

    Try {
        $StartTime = Get-Date

        $STIGLog_Remote = Join-Path -Path $RemoteScanDir -ChildPath "Evaluate-STIG_Remote.log"
        If (Test-Path $STIGLog_Remote) {
            Remove-Item $STIGLog_Remote -Force
        }
        $STIGLog_STIGManager = Join-Path -Path $RemoteScanDir -ChildPath "Evaluate-STIG_STIGManager.log"
        If (Test-Path $STIGLog_STIGManager) {
            Remove-Item $STIGLog_STIGManager -Force
        }
        $STIGLog_Splunk = Join-Path -Path $RemoteScanDir -ChildPath "Evaluate-STIG_Splunk.log"
        If (Test-Path $STIGLog_Splunk) {
            Remove-Item $STIGLog_Splunk -Force
        }

        # Reconstruct command line for logging purposes
        $ParamsNotForLog = @("ESVersion", "LogComponent", "OSPlatform", "ES_Path", "PowerShellVersion") # Parameters not be be written to log
        $CommandLine = Get-CommandLine -CommandName "Evaluate-STIG.ps1" -BoundParameters $PSBoundParameters -IgnoreParams $ParamsNotForLog

        # Begin logging
        Write-Log -Path $STIGLog_Remote -Message "Executing: $($CommandLine)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Log -Path $STIGLog_Remote -Message "WARNING: Executing Evaluate-STIG without local administrative rights." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
        }
        Write-Log -Path $STIGLog_Remote -Message "Evaluate-STIG Version: $($ESVersion)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

        # Verify required Evaluate-STIG files exist and their integrity
        $FileIntegrityPass = $true
        $Verified = $true
        Write-Log -Path $STIGLog_Remote -Message "Verifying Evaluate-STIG file integrity" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        If (Test-Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            If ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                $FileIntegrityPass = $false
                Write-Log -Path $STIGLog_Remote -Message "ERROR: 'FileList.xml' failed authenticity check. Unable to verify content integrity." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            Else {
                ForEach ($File in $FileListXML.FileList.File) {
                    $Path = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                    If (Test-Path $Path) {
                        If ((Get-FileHash -Path $Path -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                            $FileIntegrityPass = $false
                            $Verified = $false
                            Write-Log -Path $STIGLog_Remote -Message "WARNING: '$($Path)' failed integrity check." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                    }
                    Else {
                        If ($File.ScanReq -eq "Required") {
                            $Verified = $false
                            Write-Log -Path $STIGLog_Remote -Message "ERROR: '$($File.Name)' is a required file but not found. Scan results may be incomplete." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }
                    }
                }
                If ($Verified -eq $true) {
                    Write-Log -Path $STIGLog_Remote -Message "Evaluate-STIG file integrity check passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                Else {
                    Write-Log -Path $STIGLog_Remote -Message "WARNING: One or more Evaluate-STIG files failed integrity check." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
            }
        }
        Else {
            Write-Log -Path $STIGLog_Remote -Message "ERROR: 'FileList.xml' not found. Cannot continue." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            Exit 2
        }
        If ($FileIntegrityPass -ne $true) {
            If ($AllowIntegrityViolations -ne $true) {
                Write-Log -Path $STIGLog_Remote -Message "File integrity checks failed - refer to $STIGLog_Remote.  Aborting scan" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Return
            }
            Else {
                Write-Log -Path $STIGLog_Remote -Message "-AllowIntegrityViolations specified so continuing with scan." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
            }
        }

        # For remote scans, archive Evaluate-STIG files and, if necessary, answer files for faster transport to remote machines
        # Clean up orphaned archives
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp")) {
            Write-Log -Path $STIGLog_Remote -Message "Removing orphaned folder: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'Evaluate-STIG_tmp')" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Remove-DirectoryRecurse -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp") #Recursive Delete
        }
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP")) {
            Write-Log -Path $STIGLog_Remote -Message "Removing orphaned file: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'ESCONTENT.ZIP')" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP") -Force
        }
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP")) {
            Write-Log -Path $STIGLog_Remote -Message "Removing orphaned file: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'AFILES.ZIP')" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP") -Force
        }

        # Copy files needed for scan to Evaluate-STIG_tmp
        # FileList.xml
        If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml"))) {
            $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml") -ItemType Directory -ErrorAction Stop
        }
        Copy-Item -Path $(Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml") -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml") -Force -ErrorAction Stop

        # Files marked "Required" and "Optional"
        ForEach ($File in ($FileListXML.FileList.File | Where-Object ScanReq -In @("Required", "Optional"))) {
            If (Test-Path $(Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)) {
                If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path))) {
                    $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path) -ItemType Directory -ErrorAction Stop
                }
                $tmpSource = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                $tmpDest = (Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                Copy-Item -Path  $tmpSource -Destination $tmpDest -Force -ErrorAction Stop
            }
        }

        # Copy default answer file location
        $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "AnswerFiles") -ItemType Directory -ErrorAction Stop
        If (Test-Path $(Join-Path -Path $ES_Path -ChildPath "AnswerFiles")) {
            Get-ChildItem -Path $(Join-Path -Path $ES_Path -ChildPath "AnswerFiles") | Where-Object Extension -EQ ".xml" | Copy-Item -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "AnswerFiles") -Force -ErrorAction Stop
        }

        # Copy Manual file location
        if (-not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual"))) {
            $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual") -ItemType Directory -ErrorAction Stop
        }
        If (Test-Path $(Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual")) {
            Get-ChildItem -Path $(Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual") | Where-Object Extension -EQ ".xml" | Copy-Item -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual") -Force -ErrorAction Stop
        }

        # Create archive of Evaluate-STIG core files
        If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP"))) {
            Write-Log -Path $STIGLog_Remote -Message "Prepping files for remote scan" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Log -Path $STIGLog_Remote -Message "Compressing Evaluate-STIG files" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

            # Check for any file locks
            ForEach ($File in (Get-ChildItem -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp") -Recurse -File)) {
                Wait-FileUnlock -Path $File.FullName -ErrorAction Stop
            }
            $Result = Initialize-Archiving -Action Compress -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "*") -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP") -CompressionLevel Optimal
            If ($Result -ne "Success") {
                Throw $Result
            }

            Remove-DirectoryRecurse -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp") #Recursive Delete
        }

        # Create archive of Answer Files if not in default path (Evaluate-STIG\AnswerFiles)
        If (($AFPath.TrimEnd('\')).TrimEnd('/') -ne (Join-Path -Path $ES_Path -ChildPath "AnswerFiles")) {
            If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP"))) {
                Write-Log -Path $STIGLog_Remote -Message "Compressing answer files from $AFPath" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                ForEach ($File in (Get-ChildItem -Path $AFPath | Where-Object Extension -EQ ".xml")) {
                    $Result = Initialize-Archiving -Action Compress -Path $($File.FullName) -DestinationPath $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP") -Update -CompressionLevel Optimal
                    If ($Result -ne "Success") {
                        Throw $Result
                    }
                }
            }
        }

        # Build the list of computers, if necessary.
        $LocalHost = New-Object System.Collections.Generic.List[System.Object]
        $ComputerTempList = New-Object System.Collections.Generic.List[System.Object]
        $ComputerList = New-Object System.Collections.Generic.List[System.Object]
        $WindowsList = New-Object System.Collections.Generic.List[System.Object]
        $LinuxList = New-Object System.Collections.Generic.List[System.Object]
        $OfflineList = New-Object System.Collections.Generic.List[System.Object]
        $RemoteUnresolveCount = 0

        # Get local host data
        $NewObj = [PSCustomObject]@{
            HostName    = ($(Get-FullHostName).FullName).ToUpper()
            IPv4Address = (Get-NetIPAddress).IPv4Address
        }
        $LocalHost.Add($NewObj)

        # Put all ComputerName items into a temp list for resolving

        ForEach ($Item in ($ComputerName -split ',(?=(?:[^"]|"[^"]*")*$)')) { #convert string to array, comma delimiter.  if path has comma, it must be enclosed in double quotes
            If (Test-Path $Item -PathType Leaf) {
                Get-Content $Item | ForEach-Object {
                    If ($_ -ne $null) {
                        $ComputerTempList.Add($_)
                    }
                }
                Continue
            }
            If ($Item -is [array]) {
                $Item | ForEach-Object {
                    $ComputerTempList.Add($_)
                }
            }
            Else {
                $ComputerTempList.Add($Item)
            }
        }

        # Get NETBIOS and FQDN of each computer
        Foreach ($Computer in ($ComputerTempList)) {
            If (($Computer -eq "127.0.0.1") -or ($Computer -eq "::1") -or ($Computer -eq "localhost") -or ($Computer.Split('.')[0] -eq $LocalHost.HostName) -or ($Computer -in $LocalHost.IPv4Address)) {
                $NewObj = [PSCustomObject]@{
                    NETBIOS = $LocalHost.HostName
                    FQDN    = "LOCALHOST"
                }
                $ComputerList.Add($NewObj)
            }
            Else {
                # Resolve Computer
                Try {
                    $FQDN = ([Net.DNS]::GetHostEntry($Computer).Hostname).ToUpper()
                    $NewObj = [PSCustomObject]@{
                        NETBIOS = $FQDN.Split('.')[0]
                        FQDN    = $FQDN
                    }
                    $ComputerList.Add($NewObj)
                }
                Catch {
                    Write-Log -Path $STIGLog_Remote -Message "ERROR: Unable to resolve $Computer" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    $OfflineList.Add($Computer)
                    $RemoteUnresolveCount++
                }
            }
        }
        Remove-Variable ComputerTempList
        [System.GC]::Collect()
        $ComputerList = $ComputerList | Sort-Object NETBIOS -Unique

        $ConnectionScriptBlock = {
            Param (
                [String]$NETBIOS,
                [String]$FQDN
            )
            $tcp = New-Object Net.Sockets.TcpClient
            Try {
                $tcp.Connect($FQDN, 5986)
            }
            catch {
            }

            if ($tcp.Connected) {
                $Connection = "5986"
            }
            else {
                Try {
                    $tcp.Connect($FQDN, 5985)
                }
                catch {
                }

                if ($tcp.Connected) {
                    $Connection = "5985"
                }
                else {
                    Try {
                        $tcp.Connect($FQDN, 22)
                    }
                    catch {
                    }

                    if ($tcp.Connected) {
                        $Connection = "22"
                    }
                }
            }

            $tcp.close()

            [PSCustomObject]@{
                NETBIOS   = $NETBIOS
                FQDN      = $FQDN
                Connected = $Connection
            }
        }

        $ConnectionRunspacePool = [RunspaceFactory]::CreateRunspacePool(1, 10)
        $ConnectionRunspacePool.Open()

        $ProgressSpinner = @("|", "/", "-", "\")
        $ProgressSpinnerPos = 0
        $ConnectionJobs = New-Object System.Collections.ArrayList

        $ComputerList | ForEach-Object {
            $ParamList = @{
                NETBIOS = $_.NETBIOS
                FQDN    = $_.FQDN
            }
            $ConnectionJob = [powershell]::Create().AddScript($ConnectionScriptBlock).AddParameters($ParamList)
            $ConnectionJob.RunspacePool = $ConnectionRunspacePool

            $null = $ConnectionJobs.Add([PSCustomObject]@{
                    Pipe   = $ConnectionJob
                    Result = $ConnectionJob.BeginInvoke()
                })
        }
        Write-Host ""

        Write-Log -Path $STIGLog_Remote -Message "Generating list of scannable hosts" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Do {
            Write-Host "`rGenerating list of scannable hosts.  Attempting connection to $(($ConnectionJobs.Result.IsCompleted | Measure-Object).Count) hosts. $($ProgressSpinner[$ProgressSpinnerPos])" -NoNewline
            $ProgressSpinnerPos++
            Start-Sleep -Seconds .1
            if ($ProgressSpinnerPos -ge $ProgressSpinner.Length) {
                $ProgressSpinnerPos = 0
            }
        } While ( $ConnectionJobs.Result.IsCompleted -contains $false)

        $ConnectionResults = $(ForEach ($ConnectionJob in $ConnectionJobs) {
                $ConnectionJob.Pipe.EndInvoke($ConnectionJob.Result)
            })

        $ConnectionRunspacePool.Close()
        $ConnectionRunspacePool.Dispose()

        $ConnectionResults | ForEach-Object {
            if ($_.Connected -eq "5986") {
                $WindowsList.Add($_)
            }
            elseif ($_.Connected -eq "5985") {
                $WindowsList.Add($_)
            }
            elseif ($_.Connected -eq "22") {
                $LinuxList.Add($_)
            }
            else {
                $OfflineList.Add($_.NETBIOS)
            }
        }
        if ((($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) -eq 0) {
            Write-Log -Path $STIGLog_Remote "ERROR: No valid remote hosts found." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        }
        else {
            Write-Log -Path $STIGLog_Remote -Message "Connected to $(($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) hosts. $(($WindowsList | Measure-Object).count) Windows and $(($LinuxList | Measure-Object).count) Linux" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Host "`rGenerating list of scannable machines.  Connected to $(($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) hosts. $(($WindowsList | Measure-Object).count) Windows and $(($LinuxList | Measure-Object).count) Linux" -NoNewline
            Write-Host ""
        }

        # Prompt for AltCredential
        If ($AltCredential -and (($WindowsList | Measure-Object).count -gt 0)) {
            $Credentialcreds = Get-Creds
        }

        $RemoteScriptBlock = {
            Param(
                $ConnectionResult,
                $STIGLog_Remote,
                $LogComponent,
                $OSPlatform,
                $RemoteWorkingDir,
                $ScanType,
                $Marking,
                $TargetComments,
                $VulnTimeout,
                $AnswerKey,
                $Output,
                $OutputPath,
                $PreviousToKeep,
                $SMPassphrase,
                $SMCollection,
                $SplunkHECName,
                $AltCredential,
                $Credentialcreds,
                $AllowDeprecated,
                $AllowSeverityOverride,
                $AllowIntegrityViolations,
                $SelectSTIG,
                $SelectVuln,
                $ExcludeVuln,
                $OutputPayload,
                $ExcludeSTIG,
                $ForceSTIG,
                $ApplyTattoo,
                $AFPath,
                $ScriptRoot
            )
            $RemoteStartTime = Get-Date

            $Remote_Log = Join-Path -Path $RemoteWorkingDir -ChildPath "Remote_Evaluate-STIG_$($ConnectionResult.NETBIOS).log"

            Write-Log -Path $Remote_Log -Message "Begin Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

            Switch ($ConnectionResult.Connected) {
                "5986" {
                    Write-Log -Path $Remote_Log -Message "Connection successful on port 5986. Determined Windows OS." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                "5985" {
                    Write-Log -Path $Remote_Log -Message "Connection successful on port 5985. Determined Windows OS." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                default {
                    Write-Log -Path $Remote_Log -Message "ERROR: Connection unsuccessful on standard ports (Windows ports 5986/5985)." -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                }
            }

            Write-Log -Path $Remote_Log -Message "Scanning : $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

            Try {
                Write-Log -Path $Remote_Log -Message "Creating Windows PS Session via HTTPS" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                if ($AltCredential) {
                    $SSLOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -Credential $Credentialcreds -UseSSL -SessionOption $SSLOptions -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    if ($remoteerror) {
                        Write-Log -Path $Remote_Log -Message "WARNING: HTTPS connection failed. Attempting HTTP connection." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Creating Windows PS Session via HTTP" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -Credential $Credentialcreds -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                        if ($remoteerror) {
                            Write-Log -Path $Remote_Log -Message "WARNING: Alternate Credentials failed to create a session. Falling back to $([Environment]::Username)." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                        }
                    }
                }
                else {
                    $SSLOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -UseSSL -SessionOption $SSLOptions -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    if ($remoteerror) {
                        Write-Log -Path $Remote_Log -Message "WARNING: HTTPS connection failed. Attempting HTTP connection." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Creating Windows PS Session via HTTP" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    }
                }

                switch -WildCard ($remoteerror) {
                    "*Access is denied*" {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName requires admin rights on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                    "*WinRM*" {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName requires WinRM on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                    "*The user name or password is incorrect.*" {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName requires a valid username and password to connect to $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                    default {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName got an error" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                }

                If (-Not($Session)) {
                    $Message = $RemoteError
                    Write-Log -Path $Remote_Log -Message $Message -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                    $RemoteFailCount["RemoteFail"]++
                    Return "ERROR: $($Message)"
                }

                Write-Log -Path $Remote_Log -Message "Credential: '$(Invoke-Command -ScriptBlock { return whoami } -Session $Session)' used for remote session(s)." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                If ((Invoke-Command -ScriptBlock { (($PsVersionTable.PSVersion).ToString()) -lt 5.1 } -Session $Session)) {
                    $Message = "$($ConnectionResult.FQDN) does not meet minimum PowerShell version (5.1)"
                    Write-Log -Path $Remote_Log -Message $Message -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                    $RemoteFailCount["RemoteFail"]++
                    Return "ERROR: $($Message)"
                }

                If (Invoke-Command -ScriptBlock { Test-Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session) {
                    Write-Log -Path $Remote_Log -Message "Removing previous content found in $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Invoke-Command -ScriptBlock { Remove-Item $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                }
                Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session
                Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance } -Session $Session

                # --- Begin: Build remote commandline ---
                $ESArgs = ""
                If ($AllowDeprecated) {
                    $ESArgs += "-AllowDeprecated "
                }

                If ($SelectSTIG) {
                    If ($ForceSTIG) {
                        $ESArgs += "-SelectSTIG $($SelectSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout "
                    }
                    Else {
                        $ESArgs += "-SelectSTIG $($SelectSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout "
                    }
                }
                ElseIf ($ExcludeSTIG) {
                    If ($ForceSTIG) {
                        $ESArgs += "-ExcludeSTIG $($ExcludeSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout "
                    }
                    Else {
                        $ESArgs += "-ExcludeSTIG $($ExcludeSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout "
                    }
                }
                ElseIf ($ForceSTIG) {
                    $ESArgs += "-ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout "
                }
                Else {
                    $ESArgs += "-ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout "
                }

                If ($SelectVuln) {
                    $ESArgs += " -SelectVuln $($SelectVuln -join ',') "
                }

                If ($ExcludeVuln) {
                    $ESArgs += " -ExcludeVuln $($ExcludeVuln -join ',') "
                }

                If (($Output -split ",").Trim() -match "(^STIGManager$|^Splunk$)") {
                    $Output = "$($Output),Console" # Add 'Console' to $Output to ensure the object is returned to the host for processing
                }
                $OutputList = $(($Output -split ",").Trim() | Where-Object {$_ -notin @("STIGManager", "Splunk")})
                If ($OutputList) {
                    $ESArgs += " -Output $($OutputList -join ',') "
                    If ($OutputPayload) {
                        $ESArgs += " -OutputPayload $($OutputPayload -join ',') "
                    }
                }

                If ($PreviousToKeep) {
                    $ESArgs += " -PreviousToKeep $PreviousToKeep "
                }

                If ($Marking) {
                    $ESArgs += " -Marking $Marking "
                }

                If ($TargetComments) {
                    $ESArgs += " -TargetComments $TargetComments "
                }

                If ($ApplyTattoo) {
                    $ESArgs += " -ApplyTattoo "
                }

                If ($AllowSeverityOverride) {
                    $ESArgs += " -AllowSeverityOverride "
                }

                If ($AllowIntegrityViolations) {
                    $ESArgs += " -AllowIntegrityViolations "
                }

                $ESArgs = $ESArgs.Trim()
                # --- End: Build remote commandline ---

                $ProgressPreference = "SilentlyContinue"

                Initialize-FileXferToRemote -NETBIOS $($ConnectionResult.NETBIOS) -RemoteTemp "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -AFPath $AFPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session

                Write-Log -Path $Remote_Log -Message "Invoking Evaluate-STIG on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $Remote_Log -Message "Scan Arguments: $ESArgs" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $Remote_Log -Message "Local logging of scan is stored at $env:WINDIR\Temp\Evaluate-STIG on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                $RemoteES = Invoke-Command -Session $Session {
                    Param(
                        [string]
                        $ESArgs
                    )
                    Try {
                        $LogOutput = [System.Collections.Generic.List[System.Object]]::new()
                        $RemoteOutput = [System.Collections.Generic.List[System.Object]]::new()
                        If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                            $Thumbprint = "d95f944e33528dc23bee8672d6d38da35e6f0017" # Evaluate-STIG code signing certificate
                            ForEach ($Store in @("CurrentUser", "LocalMachine")) {
                                If (Get-ChildItem -Path "Cert:\$Store\TrustedPublisher" | Where-Object Thumbprint -EQ $Thumbprint) {
                                    $CodeSign = $true
                                }
                                Else {
                                    $CodeSign = $False
                                }
                            }
                            If ($CodeSign -eq $true) {
                                $NewObj = [PSCustomObject]@{
                                    Message = "Code signing certificate is trusted on $env:COMPUTERNAME"
                                    Type    = "Info"
                                }
                                $LogOutput.Add($NewObj)
                            }
                            Else {
                                $CodeSign = $False
                                $NewObj = [PSCustomObject]@{
                                    Message = "Code signing certificate is not trusted on $env:COMPUTERNAME"
                                    Type    = "Warning"
                                }
                                $LogOutput.Add($NewObj)
                            }

                            $ESPath = "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\Evaluate-STIG.ps1"

                            # Command to run and redirect Write-Host
                            # https://powershell.one/code/9.html
                            $ES_CmdLine = $($ESPath) + ' ' + $($ESArgs) + ' 6>$null'
                            # If -Output is creating files, set -OutputPath
                            If ((($ESArgs -split "-Output ")[1] -split " ")[0] -split "," -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                                $ES_CmdLine = $ES_CmdLine + " -OutputPath $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance"
                            }

                            Switch (Get-ExecutionPolicy) {
                                {($_ -in @("Restricted"))} {
                                    $NewObj = [PSCustomObject]@{
                                        Message = "Execution policy of '$_' found on $env:COMPUTERNAME which is not supported"
                                        Type    = "Error"
                                    }
                                    $LogOutput.Add($NewObj)
                                }
                                {($_ -in @("AllSigned", "RemoteSigned"))} {
                                    If ($CodeSign) {
                                        $NewObj = [PSCustomObject]@{
                                            Message = "Execution policy of '$_' found on $env:COMPUTERNAME"
                                            Type    = "Info"
                                        }
                                        $LogOutput.Add($NewObj)
                                        $Output = Invoke-Expression -Command $ES_CmdLine
                                    }
                                    Else {
                                        $NewObj = [PSCustomObject]@{
                                            Message = "Execution policy of '$_' found on $env:COMPUTERNAME but code signing certificate is not trusted"
                                            Type    = "Warning"
                                        }
                                        $LogOutput.Add($NewObj)
                                        $Output = Invoke-Expression -Command $ES_CmdLine
                                    }
                                }
                                Default {
                                    $NewObj = [PSCustomObject]@{
                                        Message = "Execution policy of '$_' found on $env:COMPUTERNAME"
                                        Type    = "Info"
                                    }
                                    $LogOutput.Add($NewObj)
                                    $Output = Invoke-Expression -Command $ES_CmdLine
                                }
                            }

                            If ($LASTEXITCODE -ne 0) {
                                Throw "Scan failed with exit code $LASTEXITCODE.  Refer to $env:WINDIR\Temp\Evaluate-STIG\Evaluate-STIG.log on $env:COMPUTERNAME"
                            }
                            Else {
                                $NewObj = [PSCustomObject]@{
                                    Message = "Scan completed"
                                    Type    = "Info"
                                }
                                $LogOutput.Add($NewObj)

                                $NewObj = [PSCustomObject]@{
                                    LogOutput  = $LogOutput
                                    ScanResult = $Output
                                }
                                $RemoteOutput.Add($NewObj)

                                Return $RemoteOutput
                            }
                        }
                        else {
                            $NewObj = [PSCustomObject]@{
                                Message = "ERROR: You must run this using an account with administrator rights on the remote computer."
                                Type    = "Error"
                            }
                            $LogOutput.Add($NewObj)

                            $NewObj = [PSCustomObject]@{
                                Message = "==========[End Remote Logging]=========="
                                Type    = "Info"
                            }
                            $LogOutput.Add($NewObj)

                            $NewObj = [PSCustomObject]@{
                                LogOutput  = $LogOutput
                                ScanResult = "ERROR: You must run this using an account with administrator rights on the remote computer."
                            }
                            $RemoteOutput.Add($NewObj)
                            Return $RemoteOutput
                        }
                    }
                    Catch {
                        $NewObj = [PSCustomObject]@{
                            Message = "ERROR: $($_.Exception.Message)"
                            Type    = "Error"
                        }
                        $LogOutput.Add($NewObj)

                        $NewObj = [PSCustomObject]@{
                            LogOutput  = $LogOutput
                            ScanResult = "ERROR: Scan Failed. Suggest running locally to determine cause."
                        }
                        $RemoteOutput.Add($NewObj)
                        Return $RemoteOutput
                    }
                } -ArgumentList ($ESArgs) -ErrorAction SilentlyContinue -InformationAction Ignore
                $RemoteES.LogOutput | ForEach-Object {
                     If ($_.Type -eq "Error") {
                        $ErrorObj = @{
                            Source   = "Runspace"
                            Message = $_.Message
                        }
                        Throw $ErrorObj
                    }
                    Else {
                        Write-Log -Path $Remote_Log -Message $_.Message -Component $LogComponent -Type $_.Type -OSPlatform $OSPlatform
                    }
                }

                If ($SelectVuln) {
                    $NetBIOS = "_Partial_$($ConnectionResult.NETBIOS)"
                }
                Else {
                    $NetBIOS = $($ConnectionResult.NETBIOS)
                }

                If (($Output -split ",").Trim() -match "(^STIGManager$)") {
                    Try {
                        $SMObject = [System.Collections.Generic.List[System.Object]]::new()
                        $($RemoteES.ScanResult).$($($RemoteES.ScanResult).Keys).Values | Foreach-Object {$SMObject.Add($_)}

                        if ($SMPassphrase){
                            $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -SMPassphrase $SMPassphrase -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                        }
                        else{
                            $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                        }

                        Import-Asset @SMImport_Params

                    }
                    Catch {
                        Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                }
                If (($Output -split ",").Trim() -match "(^Splunk$)") {
                    Try {
                        $SplunkObject = [System.Collections.Generic.List[System.Object]]::new()
                        $($RemoteES.ScanResult).$($($RemoteES.ScanResult).Keys).Values | Foreach-Object {$SplunkObject.Add($_)}

                        $Splunk_Params = Get-SplunkParameters -SplunkHECName $SplunkHECName -ScanObject $SplunkObject -OutputPayload $OutputPayload -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log

                        Import-Event @Splunk_Params

                    }
                    Catch {
                        Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }

                }

                If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                    If (Invoke-Command -ScriptBlock { Return Test-Path "$($env:WINDIR)\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance\$($NetBIOS)" } -Session $Session) {
                        If ($SelectSTIG) {
                            $PreviousArgs = @{SelectedShortName = $SelectSTIG}
                            If (($Output -split ",").Trim() -match "(^CombinedCKL$)") {
                                $PreviousArgs.Add("SelectedCombinedCKL",$true)
                            }
                            If (($Output -split ",").Trim() -match "(^CombinedCKLB$)") {
                                $PreviousArgs.Add("SelectedCombinedCKLB", $true)
                            }
                            If (($Output -split ",").Trim() -match "(^CombinedCSV$)") {
                                $PreviousArgs.Add("SelectedCombinedCSV", $true)
                            }
                            If (($Output -split ",").Trim() -match "(^Summary$)") {
                                $PreviousArgs.Add("SelectedSummary", $true)
                            }
                            If (($Output -split ",").Trim() -match "(^OQE$)") {
                                $PreviousArgs.Add("SelectedOQE", $true)
                            }
                            Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep @PreviousArgs -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                        }
                        Else {
                            Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                        }

                        Initialize-FileXferFromRemote -NETBIOS $NetBIOS -RemoteTemp "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session
                    }
                    Else {
                        Write-Log -Path $Remote_Log -Message "No Evaluate-STIG results were found on $($ConnectionResult.FQDN)." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        $OfflineList.Add($ConnectionResult.FQDN)
                    }
                }

                # Clean up temp on remote
                If (Invoke-Command -ScriptBlock { Test-Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session) {
                    Invoke-Command -ScriptBlock { Remove-Item $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                }

                $TimeToComplete = New-TimeSpan -Start $RemoteStartTime -End (Get-Date)
                $FormatedTime = "{0:c}" -f $TimeToComplete
                Write-Log -Path $Remote_Log -Message "Total Time - $($FormatedTime)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                Remove-Item $Remote_Log

                $Session | Remove-PSSession
                $ProgressPreference = "Continue"
                Return $RemoteES.ScanResult
            }
            Catch {
                $RemoteFailCount["RemoteFail"]++
                If ($_.TargetObject.Source -eq "Runspace") {
                    Write-Log -Path $Remote_Log -Message $_.TargetObject.Message -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                }
                Else {
                    $ErrorData = $_ | Get-ErrorInformation
                    ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                        Write-Log -Path $Remote_Log -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                }
                Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                Remove-Item $Remote_Log

                If ($Session) {
                    $Session | Remove-PSSession
                }
                $ProgressPreference = "Continue"
            }
        }

        $RemoteFailCount = [hashtable]::Synchronized(@{})

        $Params = @{
            STIGLog_Remote   = $STIGLog_Remote
            LogComponent     = $LogComponent
            OSPlatform       = $OSPlatform
            RemoteWorkingDir = $RemoteWorkingDir
            ScanType         = $ScanType
            VulnTimeout      = $VulnTimeout
            AnswerKey        = $AnswerKey
            OutputPath       = $OutputPath
            ScriptRoot       = $ES_Path
        }

        If ($AltCredential) {
            $Params.AltCredential = $True
            $Params.CredentialCreds = $Credentialcreds
        }
        Else {
            $Params.AltCredential = $False
        }

        If ($Output) {
            $Params.Output = $Output

            If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                $Params.PreviousToKeep = $PreviousToKeep
            }

            If (($Output -split ",").Trim() -match "(^STIGManager)$") {
                if ($SMPassphrase){
                    $Params.SMPassphrase = $SMPassphrase
                }
                if ($SMCollection){
                    $Params.SMCollection = $SMCollection
                }
            }

            If (($Output -split ",").Trim() -match "(^Splunk$)") {
                if ($SplunkHECName){
                    $Params.SplunkHECName = $SplunkHECName
                }
            }

            If (($Output -Split ",").Trim() -match "(^CSV$|^CombinedCSV$|^Splunk$)"){
                If ($OutputPayload) {
                    $Params.OutputPayload = $OutputPayload
                }
            }
        }
        Else {
            $Params.Output = $False
        }

        If ($SelectSTIG) {
            $Params.SelectSTIG = $SelectSTIG
        }
        Else {
            $Params.SelectSTIG = $False
        }

        If ($SelectVuln) {
            $Params.SelectVuln = $SelectVuln
        }
        Else {
            $Params.SelectVuln = $False
        }

        If ($ExcludeVuln) {
            $Params.ExcludeVuln = $ExcludeVuln
        }
        Else {
            $Params.ExcludeVuln = $False
        }

        If ($ExcludeSTIG) {
            $Params.ExcludeSTIG = $ExcludeSTIG
        }
        Else {
            $Params.ExcludeSTIG = $False
        }

        If ($ForceSTIG) {
            $Params.ForceSTIG = $ForceSTIG
        }
        Else {
            $Params.ForceSTIG = $False
        }

        If ($Marking) {
            $Params.Marking = $Marking
        }
        Else {
            $Params.Marking = $False
        }

        If ($TargetComments) {
            $Params.TargetComments = $TargetComments
        }
        Else {
            $Params.TargetComments = $False
        }

        If ($ApplyTattoo) {
            $Params.ApplyTattoo = $ApplyTattoo
        }
        Else {
            $Params.ApplyTattoo = $False
        }

        If ($AllowDeprecated) {
            $Params.AllowDeprecated = $AllowDeprecated
        }
        Else {
            $Params.AllowDeprecated = $False
        }

        If ($AllowSeverityOverride) {
            $Params.AllowSeverityOverride = $AllowSeverityOverride
        }
        Else {
            $Params.AllowSeverityOverride = $False
        }

        If ($AllowIntegrityViolations) {
            $Params.AllowIntegrityViolations = $AllowIntegrityViolations
        }
        Else {
            $Params.AllowIntegrityViolations = $False
        }

        If ($AFPath) {
            $Params.AFPath = $AFPath
        }
        Else {
            $Params.AFPath = $False
        }

        If ($ThrottleLimit) {
            $MaxThreads = $ThrottleLimit
        }
        Else {
            $MaxThreads = 10
        }

        Write-Host "Executing scans"
        # https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/
        $runspaces = New-Object System.Collections.ArrayList
        $sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $sessionstate.variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'RemoteFailCount', $RemoteFailCount, ''))

        Get-ChildItem function:/ | ForEach-Object {
            $definition = Get-Content "Function:\$($_.Name)"
            $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $definition
            $sessionstate.Commands.Add($SessionStateFunction)
        }

        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionstate, $Host)
        $runspacepool.ApartmentState = "STA"
        $runspacepool.Open()
        $RunspaceResults = @{}

        # Create pipeline input and output (results) object
        $RSObject = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'

        Foreach ($ConnectionResult in $($ConnectionResults | Where-Object { ($_.Connected -ne "22") -and ($_.FQDN -notin $OfflineList) })) {
            $Job = [powershell]::Create().AddScript($RemoteScriptBlock).AddArgument($ConnectionResult).AddParameters($Params)
            $Job.Streams.ClearStreams()
            $Job.RunspacePool = $RunspacePool

            # Create a temporary collection for each runspace
            $temp = "" | Select-Object Job, Runspace, Hostname, FQDN
            $Temp.HostName = $ConnectionResult.NETBIOS
            $Temp.FQDN = $ConnectionResult.FQDN
            $temp.Job = $Job
            $temp.Runspace = [PSCustomObject]@{
                Instance = $Job
                State    = $Job.BeginInvoke($RSObject, $RSObject)
            }
            $null = $runspaces.Add($temp)
        }

        if (($runspaces | Measure-Object).count -gt 0) {
            Get-RunspaceData -Runspaces $Runspaces -Wait -Usage Remote
        }

        If (($Output -split ",").Trim() -match "(^Console$)") {
            # Add to results to be returned to console
            If ($RSObject) {
                ForEach ($Object in $RSObject.Keys) {
                    $RunspaceResults.Add($Object,$RSObject.$Object)
                }
            }
        }

        $RunspacePool.Close()
        $RunspacePool.Dispose()

        $RemoteLinuxFail = 0

        if (($LinuxList | Measure-Object).count -gt 0) {
            $SSHUsername = Read-Host "Enter username to SSH to $(($LinuxList | Measure-Object).count) Linux host(s)"

            Foreach ($LinuxHost in $LinuxList) {
                $Remote_Log = Join-Path -Path $RemoteWorkingDir -ChildPath "Remote_Evaluate-STIG_$($LinuxHost.NETBIOS).log"
                Write-Host ""

                If ($PowerShellVersion -ge [Version]"7.1") {
                    Try {
                        $RemoteStartTime = Get-Date

                        Write-Log -Path $Remote_Log -Message "Connection successful on port 22. Determined Linux OS." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Scanning : $($LinuxHost.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Try {
                            $Session = New-PSSession -HostName $LinuxHost.FQDN -UserName $SSHUsername -SSHTransport -ErrorAction Stop
                            $SessionUserName = $SSHUsername
                        }
                        Catch {
                            Write-Log -Path $Remote_Log -Message "WARNING: SSH Session failed for $($LinuxHost.FQDN). Requesting different SSH username" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            $AltSSHUsername = Read-Host "Enter username to SSH to $($LinuxHost.FQDN)"
                            $SessionUserName = $AltSSHUsername
                            Try {
                                $Session = New-PSSession -HostName $LinuxHost.FQDN -UserName $AltSSHUsername -SSHTransport -ErrorAction Stop
                            }
                            Catch {
                                Write-Log -Path $Remote_Log -Message "ERROR: SSH Session failed for $($LinuxHost.FQDN)." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                        }

                        If (Invoke-Command -ScriptBlock { Test-Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session) {
                            Write-Log -Path $Remote_Log -Message "Removing previous content found in /tmp/Evaluate-STIG_RemoteComputer" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Invoke-Command -ScriptBlock { Remove-Item /tmp/Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                        }
                        Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session
                        Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path /tmp/Evaluate-STIG_RemoteComputer/STIG_Compliance } -Session $Session

                        $DefaultOutputPath = "/tmp/Evaluate-STIG_RemoteComputer/STIG_Compliance"

                        $ESArgs = ""
                        If ($AllowDeprecated) {
                            $ESArgs += "-AllowDeprecated "
                        }

                        If ($SelectSTIG) {
                            If ($ForceSTIG) {
                                $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                            Else {
                                $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                        }
                        ElseIf ($ExcludeSTIG) {
                            If ($ForceSTIG) {
                                $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                            Else {
                                $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                        }
                        ElseIf ($ForceSTIG) {
                            $ESArgs = "-ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                        }
                        Else {
                            $ESArgs = "-ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                        }

                        If (($Output -split ",").Trim() -match "(^STIGManager$|^Splunk$)") {
                            $Output = "$($Output),Console" # Add 'Console' to $Output to ensure the object is returned to the host for processing
                        }
                        $OutputList = $(($Output -split ",").Trim() | Where-Object {$_ -notin @("STIGManager", "Splunk")})
                        If ($OutputList) {
                            $ESArgs = $ESArgs + " -Output $($OutputList -join ',') "
                            If ($OutputPayload) {
                                $ESArgs += " -OutputPayload $($OutputPayload -join ',') "
                            }
                        }

                        If ($PreviousToKeep) {
                            $ESArgs += " -PreviousToKeep $PreviousToKeep "
                        }

                        If ($SelectVuln) {
                            $ESArgs = $ESArgs + " -SelectVuln $($SelectVuln -join ',')"
                        }

                        If ($ExcludeVuln) {
                            $ESArgs = $ESArgs + " -ExcludeVuln $($ExcludeVuln -join ',')"
                        }

                        If ($Marking) {
                            $ESArgs = $ESArgs + " -Marking $Marking"
                        }

                        If ($TargetComments) {
                            $ESArgs = $ESArgs + " -TargetComments $TargetComments"
                        }

                        If ($ApplyTattoo) {
                            $ESArgs = $ESArgs + " -ApplyTattoo"
                        }

                        If ($AllowSeverityOverride) {
                            $ESArgs = $ESArgs + " -AllowSeverityOverride"
                        }

                        If ($AllowIntegrityViolations) {
                            $ESArgs += " -AllowIntegrityViolations"
                        }

                        $ProgressPreference = "SilentlyContinue"

                        Initialize-FileXferToRemote -NETBIOS $($LinuxHost.NETBIOS) -RemoteTemp "/tmp/Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -AFPath $AFPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ES_Path -Session $Session

                        Write-Log -Path $Remote_Log -Message "Invoking Evaluate-STIG on $($LinuxHost.FQDN)." -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Scan Arguments: $ESArgs and $AllowSeverityOverride" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Local logging of scan is stored at /tmp/Evaluate-STIG on $($LinuxHost.FQDN)" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        #Test for NOPASSWD
                        $NoPasswdTest = Invoke-Command -ScriptBlock { if ((sudo whoami) -ne "root") {
                                Return 2
                            } } -Session $Session -ErrorAction SilentlyContinue -InformationAction Ignore

                        $SudoFailCount = 1
                        if ($NoPasswdTest -eq 2) {
                            do {
                                $sudoPass = Read-Host "[sudo] password for $SessionUserName" -AsSecureString
                                $creds = New-Object System.Management.Automation.PSCredential($SessionUserName, $sudoPass)
                                $sudoPass = $creds.GetNetworkCredential().Password

                                $SudoCheck = Invoke-Command -ScriptBlock {
                                    param(
                                        [String]
                                        $SudoPass
                                    )
                                    if (($sudoPass | sudo -S whoami) -ne "root") {
                                        Write-Host "ERROR: sudo: incorrect password attempt" -ForegroundColor Red
                                        Return 2
                                    }
                                    else { return 0 }
                                } -Session $Session -ArgumentList $sudoPass -ErrorAction SilentlyContinue -InformationAction Ignore

                                $SudoFailCount++
                            }while ($SudoCheck -ne 0 -and $SudoFailCount -le 3)
                        }
                        else {
                            $null = $sudoPass
                        }

                        $RemoteES = Invoke-Command -Session $session {
                            param(
                                [String]
                                $SudoPass,

                                [String]
                                $ESArgs,

                                [string]
                                $DefaultOutputPath,

                                [string]
                                $SSHUsername
                            )

                            $LogOutput = [System.Collections.Generic.List[System.Object]]::new()
                            $RemoteOutput = [System.Collections.Generic.List[System.Object]]::new()

                            if ($null -ne $SudoPass) {
                                if (($sudoPass | sudo -S whoami) -ne "root") {
                                    $NewObj = [PSCustomObject]@{
                                        Message = "ERROR: sudo: incorrect password attempt"
                                        Type    = "Error"
                                    }
                                    $LogOutput.Add($NewObj)

                                    $NewObj = [PSCustomObject]@{
                                        Message = "==========[End Remote Logging]=========="
                                        Type    = "Info"
                                    }
                                    $LogOutput.Add($NewObj)

                                    $NewObj = [PSCustomObject]@{
                                        LogOutput  = $LogOutput
                                        ScanResult = "ERROR: sudo: incorrect password attempt"
                                    }
                                    $RemoteOutput.Add($NewObj)
                                    Return $RemoteOutput
                                }

                                if (-Not(Test-Path $DefaultOutputPath)) {
                                    $SudoPass | sudo -S mkdir $DefaultOutputPath
                                }
                            }
                            else {
                                if (-Not(Test-Path $DefaultOutputPath)) {
                                    sudo mkdir $DefaultOutputPath
                                }
                            }

                            # Now you have cached your sudo password you should be able to call it normally (up to whatever timeout you have configured)

                            $ESPath = "/tmp/Evaluate-STIG_RemoteComputer/Evaluate-STIG.ps1"

                            # Set PowerShell exe
                            $PS_Exe = "pwsh"

                            $ES_CmdLine = "$($ESPath) $($ESArgs)"
                            # If -Output is creating files, set -OutputPath
                            If ((($ESArgs -split "-Output ")[1] -split " ")[0] -split "," -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                                $ES_CmdLine = $ES_CmdLine + " -OutputPath $DefaultOutputPath"
                            }

                            $ClixmlOut = "/tmp/Evaluate-STIG/ScanResult.xml"
                            $Scriptblock = [scriptblock]::Create('
                                $Output = ' + $ES_CmdLine + '
                                $Output | Export-Clixml -Depth 2 -Path ' + $ClixmlOut + ' -Force
                            ')
                            $Command = "Start-Process $PS_Exe -ArgumentList '-Command $Scriptblock' -Wait;chown -R $SSHUsername`: /tmp/Evaluate-STIG_RemoteComputer /tmp/Evaluate-STIG"
                            Try {
                                $SudoPass | sudo -S pwsh -command $Command

                                $LogTail = Get-Content /tmp/Evaluate-STIG/Evaluate-STIG.log -Tail 10
                                $Pattern = "Exiting with exit code \d+"
                                $ExitCodeLine = ($LogTail | Select-String $Pattern).Matches
                                If ($ExitCodeLine) {
                                    $ExitCodeLine[0].Value -match "\d+" | Out-Null
                                    If ($Matches[0] -ne 0) {
                                        Throw "Scan failed with exit code $($Matches[0]).  Refer to tmp/Evaluate-STIG/Evaluate-STIG.log on $env:COMPUTERNAME"
                                    }
                                }

                                $NewObj = [PSCustomObject]@{
                                    Message = "Scan completed"
                                    Type    = "Info"
                                }
                                $LogOutput.Add($NewObj)

                                $NewObj = [PSCustomObject]@{
                                    LogOutput  = $LogOutput
                                    ScanResult = (Import-Clixml -Path $ClixmlOut)
                                }
                                $RemoteOutput.Add($NewObj)

                                Remove-Item -Path $ClixmlOut -Force

                                Return $RemoteOutput
                            }
                            Catch {
                                $NewObj = [PSCustomObject]@{
                                    Message = "ERROR: $($_.Exception.Message)"
                                    Type    = "Error"
                                }
                                $LogOutput.Add($NewObj)

                                $NewObj = [PSCustomObject]@{
                                    LogOutput  = $LogOutput
                                    ScanResult = "ERROR: Scan Failed. Suggest running locally to determine cause."
                                }
                                $RemoteOutput.Add($NewObj)
                                Return $RemoteOutput
                            }

                        } -ArgumentList ($sudoPass, $ESArgs, $DefaultOutputPath, $SessionUserName) -ErrorAction SilentlyContinue -InformationAction Ignore

                        $RemoteES.LogOutput | ForEach-Object {
                            If ($_.Type -eq "Error") {
                                $ErrorObj = @{
                                    Source   = "Runspace"
                                    Message = $_.Message
                                }
                                Throw $ErrorObj
                            }
                            Else {
                                Write-Log -Path $Remote_Log -Message $_.Message -Component $LogComponent -Type $_.Type -OSPlatform $OSPlatform
                            }
                        }

                        if ($SelectVuln) {
                            $NetBIOS = "_Partial_$($LinuxHost.NETBIOS)"
                        }
                        else {
                            $NetBIOS = $($LinuxHost.NETBIOS)
                        }

                        if ($RemoteES.ScanResult -match "ERROR:") {
                            $RemoteLinuxFail++
                        }

                        If (($Output -split ",").Trim() -match "(^STIGManager$)") {
                            Try {
                                $SMObject = [System.Collections.Generic.List[System.Object]]::new()
                                $($RemoteES.ScanResult).$($($RemoteES.ScanResult).Keys).Values | Foreach-Object {$SMObject.Add($_)}

                                if ($SMPassphrase){
                                    $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -SMPassphrase $SMPassphrase -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                                }
                                else{
                                    $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                                }

                                Import-Asset @SMImport_Params

                            }
                            Catch {
                                Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                        }
                        If (($Output -split ",").Trim() -match "(^Splunk$)") {
                            Try {
                                $SplunkObject = [System.Collections.Generic.List[System.Object]]::new()
                                $($RemoteES.ScanResult).$($($RemoteES.ScanResult).Keys).Values | Foreach-Object {$SplunkObject.Add($_)}

                                $Splunk_Params = Get-SplunkParameters -SplunkHECName $SplunkHECName -ScanObject $SplunkObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -Logpath $Remote_Log

                                Import-Event @Splunk_Params

                            }
                            Catch {
                                Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }

                        }

                        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                            If (Invoke-Command -ScriptBlock { param ($DefaultOutputPath, $NetBIOS)
                                                            $Path = "$DefaultOutputPath/$NetBIOS"
                                                            Return (pwsh -command "Test-Path $Path" )
                                                            } -Session $Session -ArgumentList ($DefaultOutputPath, $NetBIOS)) {
                                If ($SelectSTIG) {
                                    $PreviousArgs = @{SelectedShortName = $SelectSTIG}
                                    If (($Output -split ",").Trim() -match "(^CombinedCKL$)") {
                                        $PreviousArgs.Add("SelectedCombinedCKL",$true)
                                    }
                                    If (($Output -split ",").Trim() -match "(^CombinedCKLB$)") {
                                        $PreviousArgs.Add("SelectedCombinedCKLB", $true)
                                    }
                                    If (($Output -split ",").Trim() -match "(^CombinedCSV$)") {
                                        $PreviousArgs.Add("SelectedCombinedCSV", $true)
                                    }
                                    If (($Output -split ",").Trim() -match "(^Summary$)") {
                                        $PreviousArgs.Add("SelectedSummary", $true)
                                    }
                                    If (($Output -split ",").Trim() -match "(^OQE$)") {
                                        $PreviousArgs.Add("SelectedOQE", $true)
                                    }
                                    Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep @PreviousArgs -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                                }
                                Else {
                                    Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                                }

                                Initialize-FileXferFromRemote -NETBIOS $NetBIOS -RemoteTemp "/tmp/Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session
                            }
                            Else {
                                Write-Log -Path $Remote_Log -Message "No Evaluate-STIG results were found on $($LinuxHost.FQDN)." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                $OfflineList.Add($LinuxHost.NETBIOS)
                                $RemoteLinuxFail++
                            }

                            If (Invoke-Command -ScriptBlock { Test-Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session) {
                                #Invoke-Command -ScriptBlock { Remove-Item /tmp/Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                            }
                        }

                        If (($Output -split ",").Trim() -match "(^Console$)") {
                            # Add to results to be returned to console
                            $FormattedResult = @{}
                            ForEach ($Key in $RemoteES.ScanResult.Values.Keys) {
                                $FormattedResult.Add($Key, $RemoteES.ScanResult.Values.$Key)
                            }
                            $RunspaceResults.Add($NetBIOS, $FormattedResult)
                        }

                        $Session | Remove-PSSession

                        $TimeToComplete = New-TimeSpan -Start $RemoteStartTime -End (Get-Date)
                        $FormatedTime = "{0:c}" -f $TimeToComplete
                        Write-Log -Path $Remote_Log -Message "Total Time : $($FormatedTime)" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                        Remove-Item $Remote_Log

                        $ProgressPreference = "Continue"
                    }
                    Catch {
                        $RemoteLinuxFail++
                        If ($_.TargetObject.Source -eq "Runspace") {
                            Write-Log -Path $Remote_Log -Message $_.TargetObject.Message -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }
                        Else {
                            $ErrorData = $_ | Get-ErrorInformation
                            ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                                Write-Log -Path $Remote_Log -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                        }
                        Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                        Remove-Item $Remote_Log

                        If ($Session) {
                            $Session | Remove-PSSession
                        }
                        $ProgressPreference = "Continue"
                    }
                }
                Else {
                    $RemoteLinuxFail++
                    Write-Log -Path $Remote_Log -Message "ERROR: $($LinuxHost.FQDN) is running a Linux Operating System. PowerShell $($PowerShellVersion -join '.') detected. Evaluate-STIG requires PowerShell 7.1." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                }
            }
        }

        $RemoteTimeToComplete = New-TimeSpan -Start $StartTime -End (Get-Date)
        $FormatedTime = "{0:c}" -f $RemoteTimeToComplete
        Write-Host ""
        Write-Log -Path $STIGLog_Remote -Message "Done!" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "Total Time - $($FormatedTime)" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "Total Hosts - $(($ComputerList | Measure-Object).count)" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        if ($($RemoteLinuxFail + $(if ($RemoteFailCount.Values -ge 1) {
                        $($RemoteFailCount.Values)
                    }
                    else {
                        "0"
                    })) -gt 0) {
            Write-Log -Path $STIGLog_Remote -Message "Total Hosts with Error - $($RemoteLinuxFail + $(if ($RemoteFailCount.Values -ge 1){$($RemoteFailCount.Values)}else{"0"}))" -WriteOutToStream -FGColor Red -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Write-Log -Path $STIGLog_Remote -Message "Total Hosts Not Resolved - $RemoteUnresolveCount" -WriteOutToStream -FGColor Yellow -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "Total Hosts Offline - $(($OfflineList | Measure-Object).Count)" -WriteOutToStream -FGColor Yellow -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Host ""
        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
            Write-Host "Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$($OutputPath)" -ForegroundColor Cyan
        }
        Write-Host "Local logging of remote scan(s) stored at " -ForegroundColor Green -NoNewline; Write-Host "$($RemoteScanDir)" -ForegroundColor Cyan
        Write-Host "Offline Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$RemoteScanDir\Offline_Hosts.txt" -ForegroundColor Cyan

        if (($OfflineList | Measure-Object).Count -gt 0) {
            if (Test-Path "$RemoteScanDir\Offline_Hosts.txt") {
                Clear-Content "$RemoteScanDir\Offline_Hosts.txt"
            }
            $OfflineList | Sort-Object -Unique | ForEach-Object {
                Add-Content -Path "$RemoteScanDir\Offline_Hosts.txt" -Value $_
            }
        }

        If (Test-Path $RemoteWorkingDir\ESCONTENT.ZIP) {
            Remove-Item -Path $RemoteWorkingDir\ESCONTENT.ZIP -Force
        }
        If (Test-Path $RemoteWorkingDir\AFILES.ZIP) {
            Remove-Item -Path $RemoteWorkingDir\AFILES.ZIP -Force
        }

        Return $RunspaceResults
    }
    Catch {
        $ErrorData = $_ | Get-ErrorInformation
        ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
            Write-Log -Path $STIGLog_Remote -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        }
        Throw $_
    }
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDANI0hQluN6ylx
# QL/yim2kRvG0Q76y0v4wd7dMM07gtaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDI4dHuz6TZV764Bh6zJOL4G7RJ7X4/uuWhfXCp4k+XVTANBgkqhkiG9w0BAQEF
# AASCAQA7eSx0AF67EQd19hZNN8ilUIw/1ouSQf+sYgpVEuAc8KhRYoZNIYroGkKy
# SDuiy2WqP9lKWdBef7w0KKYxnjyhhPTw0gsZQXOBmG6o9KpdpDl21BAAL1oNK41N
# FOJvMpdP7efrwAF794wA+qeamqvCwkKqCfYECV+3Z1PR4nDB+Z/tTPgjFGca7mud
# 6mx6xDIaN/2hdyqYz7V4VZjrUAacPCInW5juaOX39YcbFRym4rgKF08GCYNm4sQ4
# E8jtvOIww7Ys0u9pzIsxLe2GOX6KGgq/oNR2+WJ9M72dUWjRcLqri89Tsz7JHK7e
# nC3GktiT04fS8B1uBreUNU1Lw0eJoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTYyOFowLwYJKoZIhvcNAQkEMSIEIH5YAY6lirL+1r9zYKHO/Dcij4NR
# XdelTIHo0z5eLAhKMA0GCSqGSIb3DQEBAQUABIICAEBxz/h21OKCOzcD6hkQ7hjm
# rOHSa3WUmeJNhrelPfuTLw3xBmPag5+Vy9YiRDW7WvXcy85XGAUkFfmDeXhQ19yf
# Ut/SDnBwVDBMLmOgZCQXC4q98ML+qnzj04hGxO7iDjxqDPzI3bRjSS0l/HtRpGue
# WL3X2r1TM90yzBL7T+uWF/JavSOn/LMg15L7GWZwU503u38I2M5BDxQy/kRd8L3u
# RD2CXk72XjjMOuXip7TVZl9NkxPx/G9Tz+a+ev6A1jwOdO3wdA6R3a8OLgQFPtIU
# 1YqftcDyYRhuzJ9usM3l+pdGHHG/pyjOBwAT0B2cZJ6ORx12sA1xnK9u5+Kbxq/C
# V9YZZ4xfRAWmJ21/6qDFtl57eZV2skwONqGH5h2tId693cstum/4+o6CYGeqDM4I
# Mh2ArhUPw356Wj36H7ZGtDkXbyapYmn/djscKzGbFFTIGSNdos/2HTh4NS2aCf0n
# m/IbNVOyZ+THEOECcxgHlvxquLsPjQlNm9QcQDZgDsxLWXzQxpWGX2fls2he67ml
# USTBbYyYXF9+zOf1OmM5HVBoWLTrhX+vne126xxzm6YjydTSz2zLQguUjLjDOpmc
# k4JrPCv+smaVgS7YAOIIJ7mTnGmJtYURInK3XaU+VW3anrPn9OLVfeUIXRSCGUDz
# Ps8DDKj9REm+MB8slUdX
# SIG # End signature block
