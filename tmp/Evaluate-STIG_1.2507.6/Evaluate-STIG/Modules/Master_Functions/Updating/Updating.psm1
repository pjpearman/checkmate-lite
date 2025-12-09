########################################
# Updating functions for Evaluate-STIG #
########################################

function Get-LogVariables {
    $LogComponent = "Evaluate-STIG Update  [PID: $(([System.Diagnostics.Process]::GetCurrentProcess()).ID)]"

    if ($IsLinux) {
        $OSPlatform = "Linux"
        $UpdateLogDir = "/tmp/Evaluate-STIG"
    }
    else {
        $OSPlatform = "Windows"
        $UpdateLogDir = Join-Path -Path (Get-Item $env:TEMP).FullName -ChildPath "Evaluate-STIG"
    }
    $UpdateLog = Join-Path -Path $UpdateLogDir -ChildPath "Evaluate-STIG_Update.log"

    $LogVars = [PSCustomObject]@{
        UpdateLog    = $UpdateLog
        LogComponent = $LogComponent
        OSPlatform   = $OSPlatform
    }

    return $LogVars
}

function Get-UpdatedModule {
    # Check for/download newer Updating.psd1 and Updating.psm1
    # Returns:
    #     $true (newer files exist and downloaded)
    #     $false (files are current)
    param (
        [Parameter(Mandatory = $false)]
        [String] $LocalSource,

        [Parameter(Mandatory = $false)]
        [String] $UpstreamRootURL,

        [Parameter(Mandatory = $false)]
        [psobject] $WebClient,

        [Parameter(Mandatory = $true)]
        [String] $PS_Path,

        [Parameter(Mandatory = $true)]
        [String] $Update_tmp
    )

    try {
        $UpdatedModuleDownloaded = $false

        if ($LocalSource) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $LocalSource -ChildPath (Join-Path -Path "xml" -ChildPath "FileList.xml")) -ErrorAction Stop
        }
        else {
            [XML]$FileListXML = $WebClient.DownloadString("$($UpstreamRootURL)/Src/Evaluate-STIG/xml/FileList.xml")
        }

        $ModuleFiles = @("Updating.psd1", "Updating.psm1")
        $ModuleRoot = Join-Path -Path "Modules" -ChildPath "Master_Functions" | Join-Path -ChildPath "Updating"
        foreach ($File in $ModuleFiles) {
            $FileListEntry = $FileListXML.FileList.File | Where-Object Name -EQ $File
            $ModuleFilePath = (Join-Path $ModuleRoot -ChildPath $FileListEntry.Name)
            # Check that the local file exists and has expected hash
            if (-not((Test-Path -Path (Join-Path -Path $PS_Path -ChildPath $ModuleFilePath)) -and ((Get-FileHash -Path (Join-Path -Path $PS_Path -ChildPath $ModuleFilePath) -Algorithm SHA256).Hash -eq $FileListEntry.SHA256Hash))) {
                $TmpModulePath = Join-Path -Path $Update_tmp -ChildPath "Updating"
                if (-not(Test-Path -Path $TmpModulePath)) {
                    # Create temp folder
                    $null = New-Item -Path $TmpModulePath -ItemType Directory -ErrorAction Stop
                }

                $TmpModule = Join-Path -Path $TmpModulePath -ChildPath $File
                if ($LocalSource) {
                    Copy-Item -Path (Join-Path -Path $LocalSource -ChildPath $ModuleFilePath) -Destination $TmpModule -ErrorAction Stop
                }
                else {
                    $WebClient.DownloadFile("$($UpstreamRootURL)/Src/Evaluate-STIG/$($ModuleFilePath)", $TmpModule)
                }

                if (Test-Path -Path $TmpModule) {
                    if (-Not($IsLinux)) {
                        Unblock-File $TmpModule
                    }
                }
                else {
                    throw "Failed to download $($File) from upstream.`r`n$($Error[0].Exception.Message)"
                }

                $UpdatedModuleDownloaded = $true
            }
        }

        return $UpdatedModuleDownloaded
    }
    catch {
        throw $Error[0]
    }
}

function Start-EvalSTIGUpdate {
    param (
        [Parameter(Mandatory = $true)]
        [String] $PS_Path,

        [Parameter(Mandatory = $false)]
        [String] $Proxy,

        [Parameter(Mandatory = $false)]
        [String] $LocalSource,

        [Parameter(Mandatory = $false)]
        [Switch] $ResumeUpdate
    )

    try {
        # Initialize
        $PS_Path = $PS_Path.TrimEnd("\", "/") # remove any trailing back or forward slashes
        $Update_tmp = Join-Path -Path $PS_Path -ChildPath "_Update.tmp"
        $Backup_tmp = Join-Path -Path $PS_Path -ChildPath "_Backup.tmp"
        $TmpFileList = Join-Path -Path $Update_tmp -ChildPath "FileList_tmp.xml"
        $TmpSourceFiles = Join-Path -Path $Update_tmp -ChildPath "SourceFiles"
        $LocalContentList = New-Object System.Collections.Generic.List[System.Object]
        $NeedsUpdateList = New-Object System.Collections.Generic.List[System.Object]
        $UpstreamRootURLs = @("https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/raw/master") # Making an array for future GitHub presence
        $WebClient = New-Object System.Net.WebClient
        if ($Proxy) {
            $WebProxy = New-Object System.Net.WebProxy($Proxy, $true)
            $WebClient.Proxy = $WebProxy
        }

        # If -NoWait is a valid parameter of Wait-FileUnlock, add it
        $NoWait = @{}
        if ("NoWait" -in (Get-Command -Name Wait-FileUnlock).Parameters.Keys) {
            # Add -NoWait parameter
            $NoWait.Add("NoWait", $true)
        }

        # Test upstream connectivity
        if ($LocalSource) {
            if (Test-Path -Path (Join-Path -Path $LocalSource -ChildPath (Join-Path -Path "xml" -ChildPath "FileList.xml")) -ErrorAction Stop) {
                # Do nothing.  LocalSource is accessible
            }
            else {
                throw "Filelist.xml not found in $($LocalSource)"
            }
        }
        else {
            foreach ($URL in $UpstreamRootURLs) {
                try {
                    $ConnectTest = $WebClient.DownloadString("$($URL)/Src/Evaluate-STIG/xml/FileList.xml")
                    break
                }
                catch {
                    # Do nothing
                }
            }
            if ($ConnectTest) {
                $UpstreamRootURL = $URL
            }
            else {
                throw $Error[0]
            }
        }

        # Prepare for logging
        $Log = Get-LogVariables
        $UpdateLogDir = Split-Path ($Log).UpdateLog -Parent
        if (-not(Test-Path $UpdateLogDir)) {
            $null = New-Item -Path $UpdateLogDir -ItemType Directory -ErrorAction Stop
        }

        if (Test-Path $Log.UpdateLog) {
            if ((Get-Item $Log.UpdateLog).Length -gt 1mb -and (-not($ResumeUpdate))) {
                # Remove the log if over 1 MB and start new
                Remove-Item $Log.UpdateLog -Force
            }
        }
        Write-Host "Logging to '$($Log.UpdateLog)'" -ForegroundColor Cyan
        Write-Host ""

        if (-not($ResumeUpdate)) {
            $UpdatedModuleDownloaded = $false
            Write-Log -Path $Log.UpdateLog -Message "Checking if upstream Updating module is newer" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform

            # Check if newer Updating module is needed
            if (Test-Path -Path $Update_tmp) {
                # Remove exiting $Update_tmp from older update process
                Write-Log -Path $Log.UpdateLog -Message "  Removing '$($Update_tmp)' as it was created by an older update process" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                foreach ($File in (Get-ChildItem -Path $Update_tmp -Recurse -File)) {
                    # Wait for any file locks to release
                    if (-not(Wait-FileUnlock -Path $File.FullName @NoWait)) {
                        Write-Log -Path $Log.UpdateLog -Message "  '$($File.FullName)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                        Wait-FileUnlock -Path $File.FullName -OutConsole -ErrorAction Stop
                    }
                }
                [System.IO.Directory]::Delete($Update_tmp, $true)
            }

            # Check upstream for newer files
            if ($LocalSource) {
                $UpdatedModuleDownloaded = Get-UpdatedModule -LocalSource $LocalSource -PS_Path $PS_Path -Update_tmp $Update_tmp
            }
            else {
                $UpdatedModuleDownloaded = Get-UpdatedModule -UpstreamRootURL $UpstreamRootURL -WebClient $WebClient -PS_Path $PS_Path -Update_tmp $Update_tmp
            }
            if ($UpdatedModuleDownloaded) {
                Write-Log -Path $Log.UpdateLog -Message "Newer Updating module found on upstream" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                Write-Log -Path $Log.UpdateLog -Message "Restarting update" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                # Build and return Result object
                $Result = [PSCustomObject]@{
                    UpdateRequired = $true
                    Message        = "Restarting update"
                }
                return $Result
            }
        }

        # Begin updating
        Write-Log -Path $Log.UpdateLog -Message "Begin Update" -TemplateMessage LineBreak-Text -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
        if ($LocalSource) {
            Write-Log -Path $Log.UpdateLog -Message "LocalSource: $($LocalSource)" -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
        }
        if ($Proxy) {
            Write-Log -Path $Log.UpdateLog -Message "Proxy: $($Proxy)" -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
        }

        # Clean up temp orphaned files
        if (Test-Path $Update_tmp) {
            Write-Log -Path $Log.UpdateLog -Message "Removing orphaned folder '$($Update_tmp)'" -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            foreach ($File in (Get-ChildItem -Path $Update_tmp -Recurse -File)) {
                # Wait for any file locks to release
                if (-not(Wait-FileUnlock -Path $File.FullName @NoWait)) {
                    Write-Log -Path $Log.UpdateLog -Message "  '$($File.FullName)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                    Wait-FileUnlock -Path $File.FullName -OutConsole -ErrorAction Stop
                }
                if (-not($IsLinux)) {
                    Unblock-File $File.FullName
                }
            }
            [System.IO.Directory]::Delete($Update_tmp, $true)
        }

        # Clean up backup orphaned files
        if (Test-Path $Backup_tmp) {
            Write-Log -Path $Log.UpdateLog -Message "Removing orphaned folder '$($Backup_tmp)'" -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            foreach ($File in (Get-ChildItem -Path $Backup_tmp -Recurse -File)) {
                # Wait for any file locks to release
                if (-not(Wait-FileUnlock -Path $File.FullName @NoWait)) {
                    Write-Log -Path $Log.UpdateLog -Message "  '$($File.FullName)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                    Wait-FileUnlock -Path $File.FullName -OutConsole -ErrorAction Stop
                }
                if (-Not($IsLinux)) {
                    Unblock-File $File.FullName
                }
            }
            [System.IO.Directory]::Delete($Backup_tmp, $true)
        }

        # Create $Update_tmp folder
        $null = New-Item -Path $Update_tmp -ItemType Directory -ErrorAction Stop

        if ($LocalSource) {
            # Validate LocalSource content
            $Verified = $true
            $LocalSource = $PSBoundParameters.LocalSource
            if (Test-Path (Join-Path -Path $LocalSource -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
                [XML]$FileListXML = Get-Content -Path (Join-Path -Path $LocalSource -ChildPath "xml" | Join-Path -ChildPath "FileList.xml") -Raw
                if ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                    throw "FileList.xml in '$LocalSource' failed authenticity check.  Unable to verify content integrity."
                }
                else {
                    foreach ($File in $FileListXML.FileList.File) {
                        $Path = (Join-Path -Path $LocalSource -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                        if (Test-Path $Path) {
                            if ((Get-FileHash -Path $Path -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                                $Verified = $false
                            }
                        }
                        else {
                            if ($File.ScanReq -ne "Optional") {
                                $Verified = $false
                            }
                        }
                    }
                    if ($Verified -eq $true) {
                        Write-Log -Path $Log.UpdateLog -Message "LocalSource '$($LocalSource)' file integrity check passed." -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform

                        # Copy FileList.xml to $Update_tmp
                        Write-Log -Path $Log.UpdateLog -Message "Copying LocalSource FileList.xml" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                        Copy-Item -Path (Join-Path -Path $LocalSource -ChildPath "xml" | Join-Path -ChildPath "FileList.xml") -Destination $TmpFileList -ErrorAction Stop
                        if (-not($IsLinux)) {
                            Unblock-File $TmpFileList
                        }
                    }
                    else {
                        throw "'$LocalSource' file integrity check failed."
                    }
                }
            }
            else {
                throw "FileList.xml in '$LocalSource' not found.  Unable to verify content integrity."
            }
        }
        else {
            # Download upstream FileList.xml
            Write-Log -Path $Log.UpdateLog -Message "Downloading upstream FileList.xml" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            $WebClient.DownloadFile("$($UpstreamRootURL)/Src/Evaluate-STIG/xml/FileList.xml", $TmpFileList)
            if (Test-Path -Path $TmpFileList) {
                if (-not($IsLinux)) {
                    Unblock-File $TmpFileList
                }
            }
            else {
                throw "Failed to download FileList.xml from upstream.`r`n$($Error[0].Exception.Message)"
            }
        }

        # Read in FileList.xml for expected file inventory and hashes
        $UpstreamFileListHash = (Get-FileHash -Path $TmpFileList -Algorithm SHA256).Hash
        [XML]$UpstreamFileListContent = Get-Content -Path $TmpFileList -Raw

        # Get local content inventory
        Write-Log -Path $Log.UpdateLog -Message "Getting local content inventory" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
        $LocalVersion = (Select-String -Path $(Join-Path -Path $PS_Path -ChildPath "Evaluate-STIG.ps1") -Pattern '\$EvaluateStigVersion = ' | ForEach-Object { $_.Line.Split(":") }).replace('$EvaluateStigVersion = ', '').Replace('"', '').Trim()
        $LocalContent = Get-ChildItem $PS_Path -Recurse | Where-Object {$_.FullName -match "((\\|/)AnswerFiles(\\|/)Template_AnswerFile.xml$|(\\|/)Manual(\\|/)ReadMe.txt$)" -or $_.FullName -notmatch "(powershell\.tar\.gz|(\\|/)Manual(\\|/)|AnswerFiles|_Update\.tmp|_Backup\.tmp)"}
        foreach ($Item in $LocalContent) {
            if ($Item.Name -in $UpstreamFileListContent.FileList.File.Name) {
                if ($Item.PSIsContainer -eq $true) {
                    $Hash = ""
                }
                else {
                    $OptXccdfPattern = "^CUI_.+V\dR\d.+xccdf\.xml$"
                    if ($Item.Name -match $OptXccdfPattern) {
                        $FileListAttributes = $UpstreamFileListContent.FileList.File | Where-Object Name -Match $OptXccdfPattern
                    }
                    else {
                        $FileListAttributes = $UpstreamFileListContent.FileList.File | Where-Object Name -EQ $Item.Name
                    }

                    if ($FileListAttributes.Path -match "Modules") {
                        $IsModule = $True
                    }
                    else {
                        $IsModule = $False
                    }
                    $ScanReq = $FileListAttributes.ScanReq
                    $Hash = (Get-FileHash $Item.FullName -Algorithm SHA256).Hash
                }
                $NewObj = [PSCustomObject]@{
                    PSIsContainer = $Item.PSIsContainer
                    Name          = $Item.Name
                    FullName      = $Item.FullName
                    IsModule      = $IsModule
                    ScanRequired  = $ScanReq
                    Hash          = $Hash
                }
                $LocalContentList.Add($NewObj)
            }
        }
        $LocalFileList = Join-Path -Path $PS_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml"
        if (Test-Path -Path $LocalFileList) {
            $LocalFileListHash = (Get-FileHash -Path $LocalFileList -Algorithm SHA256).Hash
        }

        # Begin compares
        $UpdateRequired = $false

        $UpstreamVersion = $UpstreamFileListContent.FileList.Version
        if ($UpstreamVersion -and ([Version]$UpstreamVersion -gt [Version]$LocalVersion)) {
            # Newer Evaluate-STIG version available so perform a full update
            Write-Log -Path $Log.UpdateLog -Message "Upstream version ($($UpstreamVersion)) is greater than local version ($($LocalVersion))" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            Write-Log -Path $Log.UpdateLog -Message "Performing full update" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            $UpdateRequired = $true
        }
        else {
            # Check individual files needing updated
            Write-Log -Path $Log.UpdateLog -Message "Checking for files that need updating" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            # Check for missing or outdated FileList.xml
            if (-not($LocalFileListHash)) {
                $FilePath = $LocalFileList.Replace($PS_Path, "")
                Write-Log -Path $Log.UpdateLog -Message "  Update required: $($FilePath) [missing]" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                    $NewObj = [PSCustomObject]@{
                        PSIsContainer = $true
                        Name          = "FileList.xml"
                        FullName      = $LocalFileList
                        ScanRequired  = "Required"
                        Reason        = "Missing from local content"
                        Detail        = ""
                    }
                    $NeedsUpdateList.Add($NewObj)
            }
            elseif ($LocalFileListHash -ne $UpstreamFileListHash) {
                $FilePath = $LocalFileList.Replace($PS_Path, "")
                Write-Log -Path $Log.UpdateLog -Message "  Update required: $($FilePath) [hash mismatch]" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                $NewObj = [PSCustomObject]@{
                    PSIsContainer = $false
                    Name          = "FileList.xml"
                    FullName      = $LocalFileList
                    ScanRequired  = "Required"
                    Reason        = "Hash mismatch"
                    Detail        = @("Upstream Hash: $($UpstreamFileListHash)", "Local Content Hash: $($LocalFileListHash)")

                }
                $NeedsUpdateList.Add($NewObj)
                foreach ($Entry in $NewObj.Detail) {
                    Write-Log -Path $Log.UpdateLog -Message "    $($Entry)" -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                }
            }

            # Check that folder structure is complete (exclude Optional files)
            foreach ($Folder in ($UpstreamFileListContent.FileList.File | Where-Object {$_.Path -and $_.ScanReq -ne "Optional"} | Select-Object Path -Unique).Path) {
                if ((Split-Path -Path $Folder -Leaf) -notin @(Split-Path -Path $LocalContentList.FullName -Parent | Split-Path -Leaf | Select-Object -Unique)) {
                    Write-Log -Path $Log.UpdateLog -Message "  Update required: $($Folder) [missing]" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                    $NewObj = [PSCustomObject]@{
                        PSIsContainer = $true
                        Name          = $Folder
                        FullName      = (Join-Path -Path $PS_Path -ChildPath $Folder)
                        ScanRequired  = $Folder.ScanReq
                        Reason        = "Missing from local content"
                        Detail        = ""
                    }
                    $NeedsUpdateList.Add($NewObj)
                }
            }

            # Check for missing or outdated files (excluding Optional)
            foreach ($File in ($UpstreamFileListContent.FileList.File | Where-Object ScanReq -NE "Optional")) {
                # Format path for output consistency
                if ($File.Path) {
                    $FilePath = Join-Path -Path $File.Path -ChildPath $File.Name
                }
                else {
                    $FilePath = Join-Path -Path "\" -ChildPath $File.Name
                }

                if (($File.Name -notin $LocalContentList.Name) -or ((Split-Path -Path ($LocalContentList | Where-Object Name -EQ $File.Name).FullName -Parent).replace($PS_Path, "").Replace("/", "\") -ne $File.Path)) {
                    Write-Log -Path $Log.UpdateLog -Message "  Update required: $($FilePath) [missing]" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                    $NewObj = [PSCustomObject]@{
                        PSIsContainer = $false
                        Name          = $File.Name
                        FullName      = (Join-Path -Path $PS_Path -ChildPath $FilePath)
                        ScanRequired  = $File.ScanReq
                        Reason        = "Missing from local content"
                        Detail        = ""

                    }
                    $NeedsUpdateList.Add($NewObj)
                }
                elseif ($File.SHA256Hash -ne ($LocalContentList | Where-Object Name -EQ $File.Name).Hash) {
                    Write-Log -Path $Log.UpdateLog -Message "  Update required: $($FilePath) [hash mismatch]" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                    $NewObj = [PSCustomObject]@{
                        PSIsContainer = $false
                        Name          = $File.Name
                        FullName      = (Join-Path -Path $PS_Path -ChildPath $FilePath)
                        ScanRequired  = $File.ScanReq
                        Reason        = "Hash mismatch"
                        Detail        = @("Upstream Hash: $($File.SHA256Hash)", "Local Content Hash: $(($LocalContentList | Where-Object Name -EQ $File.Name).Hash)")

                    }
                    $NeedsUpdateList.Add($NewObj)
                    foreach ($Entry in $NewObj.Detail) {
                        Write-Log -Path $Log.UpdateLog -Message "    $($Entry)" -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                    }
                }
            }

            # Check Optional files
            if ($LocalContentList | Where-Object ScanRequired -EQ "Optional") {
                foreach ($File in ($UpstreamFileListContent.FileList.File | Where-Object ScanReq -EQ "Optional")) {
                    # Format path for output consistency
                    if ($File.Path) {
                        $FilePath = Join-Path -Path $File.Path -ChildPath $File.Name
                    }
                    else {
                        $FilePath = Join-Path -Path "\" -ChildPath $File.Name
                    }

                    if (($File.Name -notin $LocalContentList.Name) -or ((Split-Path -Path ($LocalContentList | Where-Object Name -EQ $File.Name).FullName -Parent).replace($PS_Path, "").Replace("/", "\") -ne $File.Path)) {
                        Write-Log -Path $Log.UpdateLog -Message "  Update required: $($FilePath) [missing] [optional file requires manual update]" -WriteOutToStream -FGColor Yellow -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                        $NewObj = [PSCustomObject]@{
                            PSIsContainer = $false
                            Name          = $File.Name
                            FullName      = (Join-Path -Path $PS_Path -ChildPath $FilePath)
                            ScanRequired  = $File.ScanReq
                            Reason        = "Missing from local content"
                            Detail        = "Optional file requires manual updating."

                        }
                        $NeedsUpdateList.Add($NewObj)
                    }
                    elseif ($File.SHA256Hash -ne ($LocalContentList | Where-Object Name -EQ $File.Name).Hash) {
                        Write-Log -Path $Log.UpdateLog -Message "  Update required: $($FilePath) [hash mismatch] [optional file requires manual update]" -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                        $NewObj = [PSCustomObject]@{
                            PSIsContainer = $false
                            Name          = $File.Name
                            FullName      = (Join-Path -Path $PS_Path -ChildPath $FilePath)
                            ScanRequired  = $File.ScanReq
                            Reason        = "Hash mismatch"
                            Detail        = @("Upstream Hash: $($File.SHA256Hash)", "Local Content Hash: $(($LocalContentList | Where-Object Name -EQ $File.Name).Hash)")

                        }
                        $NeedsUpdateList.Add($NewObj)
                        foreach ($Entry in $NewObj.Detail) {
                            Write-Log -Path $Log.UpdateLog -Message "    $($Entry)" -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                        }
                    }
                }
            }

            # If $NeedsUpdateList contains objects, perform an incremental update
            if (($NeedsUpdateList | Measure-Object).Count -gt 0) {
                $UpdateRequired = $true
            }
        }

        # If update is required, do it.  Else, report everything is current.
        if ($UpdateRequired) {
            # Create $TmpSource directory
            $null = New-Item -Path $TmpSourceFiles -ItemType Directory

            # Copy or download/extract source files to $TmpSourceFiles
            if ($LocalSource) {
                Write-Log -Path $Log.UpdateLog -Message "Using LocalSource '$($LocalSource)'" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                Copy-Item -Path "$LocalSource\*" -Destination $TmpSourceFiles -Recurse
            }
            else {
                # Get ZIP file name and hash from upstream Evaluate-STIG_ZIP_Hashes.txt
                Write-Log -Path $Log.UpdateLog -Message "Getting distributable file name from upstream" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                $HashContent = $WebClient.DownloadString("$($UpstreamRootURL)/dist/UNCLASSIFIED/Evaluate-STIG_ZIP_Hashes.txt") -split "\r\n"
                if (-not($HashContent)) {
                    throw "Failed to download Evaluate-STIG_ZIP_Hashes.txt from upstream.`r`n$($Error[0].Exception.Message)"
                }
                $ZipFileName = ($HashContent -match "^Evaluate-STIG_\d\.\d{4}\.\d{1,2}\.zip$").Trim()
                $ZipFileHash = ($HashContent -match "SHA512\s*:\s*\w*$" -split ":")[1].Trim()

                # Download ZIP file
                Write-Log -Path $Log.UpdateLog -Message "Downloading $($ZipFileName) from upstream" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                $TmpZipPath = Join-Path -Path $Update_tmp -ChildPath $ZipFileName
                $WebClient.DownloadFile("$($UpstreamRootURL)/dist/UNCLASSIFIED/$($ZipFileName)", $TmpZipPath)

                # Verify downloaded ZIP file hash
                Write-Log -Path $Log.UpdateLog -Message "Verifying $($ZipFileName) hash" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                # Wait for any file locks to release
                if (-not(Wait-FileUnlock -Path $TmpZipPath @NoWait)) {
                    Write-Log -Path $Log.UpdateLog -Message "  '$($TmpZipPath)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                    Wait-FileUnlock -Path $TmpZipPath -OutConsole -ErrorAction Stop
                }
                if ((Get-FileHash -Path $TmpZipPath -Algorithm SHA512).Hash -ne $ZipFileHash) {
                    throw "Downloaded $($ZipFileName) failed hash check"
                }

                # load ZIP methods
                Add-Type -AssemblyName System.IO.Compression.FileSystem

                # Path filter inside ZIP to extract from
                $Filter = 'Evaluate-STIG/'

                # Extract downloaded ZIP and update
                Write-Log -Path $Log.UpdateLog -Message "Extracting $($ZipFileName)" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                $Zip = [IO.Compression.ZipFile]::OpenRead($TmpZipPath)
                $Zip.Entries | Where-Object {$_.FullName -match $Filter} | ForEach-Object {
                    $FileName = $_.Name
                    if ($Filename) {
                        $FolderPath = ($_.FullName).replace($Filter, "$($TmpSourceFiles)/").Replace($FileName, "")
                        if (-not(Test-Path -Path $FolderPath)) {
                            $null = New-Item -Path $FolderPath -ItemType Directory -Force
                        }
                        [IO.Compression.ZipFileExtensions]::ExtractToFile($_, (Join-Path -Path $FolderPath -ChildPath $FileName), $true)
                    }
                    else {
                        $FolderPath = ($_.FullName).replace("Evaluate-STIG", $TmpSourceFiles)
                        $null = New-Item -Path $FolderPath -ItemType Directory -Force
                    }
                }
                # Close ZIP file
                $Zip.Dispose()
            }

            # Unblock files in $TmpSourceFiles
            if (-not($IsLinux)) {
                Write-Log -Path $Log.UpdateLog -Message "Unblocking source files" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                foreach ($File in (Get-ChildItem -Path $TmpSourceFiles -Recurse -File)) {
                    # Wait for any file locks to release
                    if (-not(Wait-FileUnlock -Path $File.FullName @NoWait)) {
                        Write-Log -Path $Log.UpdateLog -Message "  '$($File.FullName)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                        Wait-FileUnlock -Path $File.FullName -OutConsole -ErrorAction Stop
                    }
                    if (-not($IsLinux)) {
                        Unblock-File $File.FullName
                    }
                }
            }

            # Get legacy version if needed
            if (-not($UpstreamVersion)) {
                $UpstreamVersion = (Select-String -Path $(Join-Path -Path $TmpSourceFiles -ChildPath "Evaluate-STIG.ps1") -Pattern '\$EvaluateStigVersion = ' | ForEach-Object { $_.Line.Split(":") }).replace('$EvaluateStigVersion = ', '').Replace('"', '').Trim()
            }

            # Back up current content
            $BackedUp = $false
            Write-Log -Path $Log.UpdateLog -Message "Backing up current content" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            $CurrentContent = Get-ChildItem $PS_Path | Where-Object Name -NotMatch "^(powershell\.tar\.gz|_Update\.tmp|_Backup\.tmp)$"
            if (-not(Test-Path $Backup_tmp)) {
                $null = New-Item -Path $Backup_tmp -ItemType Directory -ErrorAction Stop
            }
            $CurrentContent | ForEach-Object {Copy-Item $_.FullName -Recurse -Destination $Backup_tmp -ErrorAction Stop}
            $BackedUp = $true

            # Add Local Preferences configurations to Updated Preferences File
            Write-Log -Path $Log.UpdateLog -Message "Updating Preferences.xml" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            $LocalPreferences = (Select-Xml -Path $(Join-Path $PS_Path -ChildPath Preferences.xml) -XPath /).Node
            $UpstreamPreferences = (Select-Xml -Path $(Join-Path $TmpSourceFiles -ChildPath Preferences.xml) -XPath /).Node

            #Need to handle "duplicate" nodes where the name is different.  currently only handles a single node

            foreach ($RootNode in $LocalPreferences.SelectNodes("//node()")) {
                $RootNode.SelectNodes("./*[not(*)]") | ForEach-Object {
                    if ($null -ne $_.'#text') {
                        if ($($UpstreamPreferences.SelectSingleNode(".//$($_.Name)"))) {
                            ($UpstreamPreferences.SelectSingleNode(".//$($_.Name)")).InnerText = $_."#text"
                        }
                    }
                }
            }

            $LocalPreferences.GetElementsByTagName("SMImport_COLLECTION") | ForEach-Object {
                $Collection_ID = $_.SMImport_COLLECTION_ID
                ($UpstreamPreferences.GetElementsByTagName("SMImport_COLLECTION") | Where-Object {$_.SMImport_COLLECTION_ID -eq $Collection_ID}).SetAttribute("Name", $_.Name)
            }

            $LocalPreferences.GetElementsByTagName("Splunk_HECName") | ForEach-Object {
                $Collection_ID = $_.SMImport_COLLECTION_ID
                ($UpstreamPreferences.GetElementsByTagName("Splunk_HECName") | Where-Object {$_.SMImport_COLLECTION_ID -eq $Collection_ID}).SetAttribute("Name", $_.Name)
            }

            $UpstreamPreferences.Save($(Join-Path $TmpSourceFiles -ChildPath Preferences.xml))

            # Remove $CurrentContent
            Write-Log -Path $Log.UpdateLog -Message "Removing current content" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            foreach ($File in (Get-ChildItem -Path $CurrentContent -Recurse -File)) {
                # Wait for any file locks to release
                if (-not(Wait-FileUnlock -Path $File.FullName @NoWait)) {
                    Write-Log -Path $Log.UpdateLog -Message "  '$($File.FullName)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                    Wait-FileUnlock -Path $File.FullName -OutConsole -ErrorAction Stop
                }
            }
            foreach ($Item in $CurrentContent) {
                if ($Item.PSIsContainer) {
                    [System.IO.Directory]::Delete($Item.FullName, $true)
                }
                else {
                    Remove-Item -Path $Item.FullName -Force -ErrorAction Stop
                }
            }

            # Copy Evaluate-STIG files from upstream content
            Write-Log -Path $Log.UpdateLog -Message "Updating Evaluate-STIG files" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            Copy-Item $(Join-Path -Path $TmpSourceFiles -ChildPath "*") -Recurse -Destination $PS_Path -Force -ErrorAction Stop

            # Restore optional content if it exists
            if ($LocalContentList | Where-Object ScanRequired -EQ "Optional") {
                Write-Log -Path $Log.UpdateLog -Message "Restoring optional content" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                foreach ($File in ($LocalContentList | Where-Object ScanRequired -EQ "Optional")) {
                    if (-not(Test-Path -Path $File.FullName.Replace($File.Name, ""))) {
                        $null = New-Item -Path $File.FullName.Replace($File.Name, "") -ItemType Directory
                    }
                    Copy-Item -Path $File.FullName.Replace($PS_Path, $Backup_tmp) -Destination $File.FullName -Recurse -Force
                    Write-Log -Path $Log.UpdateLog -Message "  Restored: $($File.FullName.Replace($PS_Path, ''))" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                }
            }

            # Restore custom user content if it exists
            foreach ($Folder in @("AnswerFiles", "Manual")) {
                $UserFiles = ""
                switch ($Folder) {
                    "AnswerFiles" {
                        $StockContent = Get-ChildItem -Path (Join-Path $PS_Path -ChildPath "AnswerFiles")
                        $UserFiles = Get-ChildItem -Path (Join-Path -Path $Backup_tmp -ChildPath "AnswerFiles") -Recurse | Where-Object {$_.FullName.Replace($Backup_tmp, "") -notin $StockContent.FullName.Replace($PS_Path, "")}
                        if ($UserFiles) {
                            Write-Log -Path $Log.UpdateLog -Message "Restoring user answer files" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                            foreach ($File in $UserFiles) {
                                if (-not(Test-Path -Path $File.FullName.Replace($Backup_tmp, $PS_Path).Replace($File.Name, ""))) {
                                    $null = New-Item -Path $File.FullName.Replace($Backup_tmp, $PS_Path).Replace($File.Name, "") -ItemType Directory
                                }
                                Copy-Item -Path $File.FullName -Destination $File.FullName.Replace($Backup_tmp, $PS_Path) -Recurse -Force
                                Write-Log -Path $Log.UpdateLog -Message "  Restored: $($File.FullName.Replace($Backup_tmp, ''))" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                            }
                        }
                    }
                    "Manual" {
                        $StockContent = Get-ChildItem -Path (Join-Path $PS_Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual")
                        $UserFiles = Get-ChildItem -Path (Join-Path -Path $Backup_tmp -ChildPath "StigContent" | Join-Path -ChildPath "Manual") -Recurse | Where-Object {$_.FullName.Replace($Backup_tmp, "") -notin $StockContent.FullName.Replace($PS_Path, "")}
                        if ($UserFiles) {
                            Write-Log -Path $Log.UpdateLog -Message "Restoring user manual STIG files" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                            foreach ($File in $UserFiles) {
                                if (-not(Test-Path -Path $File.FullName.Replace($Backup_tmp, $PS_Path).Replace($File.Name, ""))) {
                                    $null = New-Item -Path $File.FullName.Replace($Backup_tmp, $PS_Path).Replace($File.Name, "") -ItemType Directory
                                }
                                Copy-Item -Path $File.FullName -Destination $File.FullName.Replace($Backup_tmp, $PS_Path) -Recurse -Force
                                Write-Log -Path $Log.UpdateLog -Message "  Restored: $($File.FullName.Replace($Backup_tmp, ''))" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                            }
                        }
                    }
                }
            }

            # Validate updated files
            $Verified = $true
            Write-Log -Path $Log.UpdateLog -Message "Validating updated files" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            [XML]$UpdatedFileListXML = Get-Content -Path (Join-Path -Path $PS_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml") -Raw -ErrorAction Stop
            if ((Test-XmlSignature -checkxml $UpdatedFileListXML -Force) -ne $true) {
                $Verified = $false
                Write-Log -Path $Log.UpdateLog -Message "  Failed: \xml\FileList.xml [authenticity check]" -WriteOutToStream -FGColor Red -Component $Log.LogComponent -Type "Error" -OSPlatform $Log.OSPlatform
            }
            else {
                foreach ($File in $UpdatedFileListXML.FileList.File) {
                    # Format path for output consistency
                    if ($File.Path) {
                        $FilePath = Join-Path -Path $File.Path -ChildPath $File.Name
                    }
                    else {
                        $FilePath = Join-Path -Path "\" -ChildPath $File.Name
                    }

                    $FullPath = Join-Path -Path $PS_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name
                    if (Test-Path -Path $FullPath) {
                        if ((Get-FileHash -Path $FullPath -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                            if ($File.ScanReq -eq "Optional") {
                                Write-Log -Path $Log.UpdateLog -Message "  Warning: $($FilePath) [hash mismatch] [optional file requires manual update]" -WriteOutToStream -FGColor Yellow -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                            }
                            else {
                                $Verified = $false
                                Write-Log -Path $Log.UpdateLog -Message "  Failed: $($FilePath) [hash mismatch]" -WriteOutToStream -FGColor Red -Component $Log.LogComponent -Type "Error" -OSPlatform $Log.OSPlatform
                            }
                        }
                    }
                    elseif (-not($File.ScanReq -eq "Optional")) {
                        $Verified = $false
                        Write-Log -Path $Log.UpdateLog -Message "  Failed: $($FilePath) [not found]" -WriteOutToStream -FGColor Red -Component $Log.LogComponent -Type "Error" -OSPlatform $Log.OSPlatform
                    }
                }
            }

            if ($Verified -eq $true) {
                $UpdateRequired = $false
                Write-Log -Path $Log.UpdateLog -Message "Successfully updated Evaluate-STIG core files to $($UpstreamVersion)" -WriteOutToStream -FGColor Green -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            }
            else {
                throw "'$PS_Path' file integrity check failed after update."
            }

            if ($IsLinux) {
                # Set owner of $TmpSourceFiles to owner of $PS_Path
                $Owner = & stat -c '%U' $PS_Path
                Write-Log -Path $Log.UpdateLog -Message "Resetting owner of '$($PS_Path)' to $($Owner)" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                & chown -R $Owner $PS_Path
            }
        }
        else {
            Write-Log -Path $Log.UpdateLog -Message "'$($PS_Path)' files are current with version $($UpstreamVersion)" -WriteOutToStream -FGColor Green -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
        }

        # Clean up
        Write-Log -Path $Log.UpdateLog -Message "Cleaning up" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
        foreach ($Folder in @($Update_tmp, $Backup_tmp)) {
            if (Test-Path -Path $Folder) {
                foreach ($File in (Get-ChildItem -Path $Folder -Recurse -File)) {
                    # Wait for any file locks to release
                    if (-not(Wait-FileUnlock -Path $File.FullName @NoWait)) {
                        Write-Log -Path $Log.UpdateLog -Message "  '$($File.FullName)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                        Wait-FileUnlock -Path $File.FullName -OutConsole -ErrorAction Stop
                    }
                }
                Write-Log -Path $Log.UpdateLog -Message "  Removing: $($Folder)" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                [System.IO.Directory]::Delete($Folder, $true)
            }
        }

        # End logging
        Write-Log -Path $Log.UpdateLog -Message "End Update" -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform

        # Build and return Result object
        $Result = [PSCustomObject]@{
            UpdateRequired  = $UpdateRequired
            LocalVersion    = $LocalVersion
            UpstreamVersion = $UpstreamVersion
            Message         = "Done"
        }
        return $Result
    }
    catch {
        Write-Log -Path $Log.UpdateLog -Message "Error Detected" -WriteOutToStream -FGColor Red -Component $Log.LogComponent -Type "Error" -OSPlatform $Log.OSPlatform

        # Get Error Data
        $ErrorData = $_ | Get-ErrorInformation
        if (Test-Path -Path $Log.UpdateLog) {
            foreach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                Write-Log -Path $Log.UpdateLog -Message "$($Prop) : $($ErrorData.$Prop)" -Component $Log.LogComponent -Type "Error" -OSPlatform $Log.OSPlatform
            }
        }

        # Restore from backup
        if ($BackedUp) {
            # Get inventories of bad update content and backup content
            Write-Log -Path $Log.UpdateLog -Message "Restoring backed up files" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
            $BadContent = Get-ChildItem $PS_Path | Where-Object Name -NotMatch "_Backup\.tmp"
            $BackupContent = Get-ChildItem $Backup_tmp

            # Remove bad content
            $BadContent | ForEach-Object {Remove-Item $_.FullName -Recurse -Force}

            # Restore from backup
            $BackupContent | ForEach-Object {Copy-Item $_.FullName -Recurse -Destination $PS_Path}
        }

        # Clean up
        Write-Log -Path $Log.UpdateLog -Message "Cleaning up" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
        foreach ($Folder in @($Update_tmp, $Backup_tmp)) {
            if (Test-Path -Path $Folder) {
                foreach ($File in (Get-ChildItem -Path $Folder -Recurse -File)) {
                    # Wait for any file locks to release
                    if (-not(Wait-FileUnlock -Path $File.FullName @NoWait)) {
                        Write-Log -Path $Log.UpdateLog -Message "  '$($File.FullName)' is currently locked by another process.  Waiting for release..." -WriteOutToStream -Component $Log.LogComponent -Type "Warning" -OSPlatform $Log.OSPlatform
                        Wait-FileUnlock -Path $File.FullName -OutConsole -ErrorAction Stop
                    }
                }
                Write-Log -Path $Log.UpdateLog -Message "  Removing: $($Folder)" -WriteOutToStream -Component $Log.LogComponent -Type "Info" -OSPlatform $Log.OSPlatform
                [System.IO.Directory]::Delete($Folder, $true)
            }
        }

        throw $_
    }
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDkS4jTvJKJq4GM
# wA9N0Yd905aB2P+UXOEbyqMdW17UKKCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDJII0BtGqfP0KFnCFO1jnx41Muv80CGR7aa9SbKz+esDANBgkqhkiG9w0BAQEF
# AASCAQAtYZgNPSl9o9zGUZje3b/cvmK9mbkuEC0OSBVG+cMS0o/9w8safgzzp5mf
# O3JlhWTwyzLPqkScXKE8tpvJZi9t9zKBojTL5gDx7hy9QMWG9hZYZuXs+lXHrDOY
# c5TZebLozpglOH2bd94yaKugD0gmvUhe8ndQ6qwnQXAyT7xGwXO6IhlfzENrusDV
# yPUT1SL7qSM4hIauozwYhSkszcp/7FyxoPjlmMTuIRA6gXRLozgB7cYrf5tTeWq5
# w5mvGYxjRm4um2V3V0Umnu6l1ByYQ4Qln51iYdGm/utwZ/zvfdQRbG6sNQkRaOlO
# MV1Ks/JZCv2u++gtWE1GTgpyiE/poYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTEwNDE2MDkzM1owLwYJKoZIhvcNAQkEMSIEIOQEfBY9tT3ljhPLxytgnyyx365V
# 8WyFHkfEea1y06FdMA0GCSqGSIb3DQEBAQUABIICABOFJB+5FYPB3jzxM5289ap1
# eZJUugbROX4FGOA511KhaCQteDaGUNjo7Tqe0At/sjmkRFvEtW6SST/awaqpYhQe
# 1u91h6GzhQJcM+s3XZdnFjUmOqyabfvj37DvAct9Qvc6y0NukmOZ1ZLGPZp/Rx7w
# Hg+sGVAyrjeFqQJZxrB7eKzsVfMKTv279xllhXfW6YhDBZEg4JMYiWQ9MhZOhJGp
# sWHO0NNsnP5gs/RQXOSNcw7GUdv9tZ3fo87UEgCDJXCcgUPrt6/7n/MvkPvZLm6x
# pGrw7pnaDXmy2PU3wzn05qEaD/ATIyGaf3cgFrSyxcwnwP5xjAHbzOMEhjsJ1AFv
# 8V3qXeEWa9iBjrs/bjsqNX5CqNoHoJUAugGaar4A26LpZXpgzg5aHh53I4kpLY4p
# gErATSuhZvzScPNsZ47ENzHv3gU4fsmARX2kCkrn0eiA20XbsAH02k3m6FUJCM4p
# leR1hECPKgh3uh7rBy0eG7HXroZxhU9DcTCVg/0PmDf0mGGHCqBjvw9elHTQCKwK
# qpqflRjxcWNZlLIeZWUQ9gAcaalfYyt2c8ayeSGpFPIzJMt7BGYZEZiTxSUvBJu7
# yU3AnX4NCv9phJMXj++QeHcqMsKvWzmB01Ed2LVxeRfl6ZiJAQDIGPu9a+vL5c2B
# IxI3vurFYkd+wOcWy+QK
# SIG # End signature block
