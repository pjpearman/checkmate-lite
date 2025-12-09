#####################################
# Cisco functions for Evaluate-STIG #
#####################################

Function Get-CiscoShowTechData {
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$ShowTech,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Inventory", "RunningConfig", "Version", "Trunk", "Vlan", "Logging")]
        [String]$DataType
    )

    Try {
        Switch ($DataType) {
            "Inventory" {
                #This pulls show inventory section from show tech config file
                $startSTR = "^-{18} show inventory -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "RunningConfig" {
                #This pulls show running-config section from show tech config file
                $startSTR = "^-{18} show running-config -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "Version" {
                #This pulls show version section from show tech config file
                Switch -Regex ($ShowTech) {
                    "^-{18} show version -{18}" {
                        $startSTR = "^-{18} show version -{18}"
                    }
                    # Maybe ASA here one day? {}
                }
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "Trunk" {
                #This pulls show interfaces trunk section from show tech config file
                $startSTR = "^-{18} show interfaces trunk -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "Vlan" {
                #This pulls show vlan from show tech config file
                $startSTR = "^-{18} show vlan -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "Logging" {
                #This pulls show logging from show tech config file
                $startSTR = "^-{18} show logging -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
        }

        Return $Result
    }
    Catch {
        Return "Unable to find 'show version' section"
    }
}

Function Get-CiscoDeviceInfo {
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$ShowTech,

        [Parameter(Mandatory = $false)]
        [String[]]$SelectDeviceType
    )

    Try {
        $Result = New-Object System.Collections.Generic.List[System.Object]

        # Get software information from Version data
        $ShowVersion = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version
        If ($ShowVersion) {
            # Determine software type
            Switch -Regex ($ShowVersion) {
                "^Cisco IOS[ -]XE [Ss]oftware, Copyright" {
                    $CiscoOS = "IOS-XE"
                }
                "^Cisco IOS [Ss]oftware," {
                    $CiscoOS = "IOS"
                }
            }
            If (-Not($CiscoOS)) {
                Throw "Unable to determine IOS type"
            }

            # Get software info
            $Pattern1 = "^Cisco IOS.*\(.*\), Version" # Pattern for line that has all of the info we need.
            ### $Pattern2 = ", Version .*\s{1}" # Pattern for Version
            $Pattern3 = "\w{0,}\s{0,}\w{1,}\s{1,}Software \(.*\)," # Pattern for Software
            $Pattern4 = "cisco C9.*" # Pattern for IOS XE 9k Model
            $StartLine = ($ShowVersion | Select-String $Pattern1).LineNumber - 1
            $DeviceSoftwareInfo = ($ShowVersion[$($StartLine)].Split(",")).Trim()
            If ($ShowVersion[$($StartLine)] -match $Pattern3) {
                $CiscoSoftware = ($matches[0] -replace ",", "" -replace "\s{2,}", " ").Trim()
            }
            Elseif ($CiscoOS -contains "IOS"){
                $CiscoSoftware = "IOS"
            }
            Else {
                Throw "Cisco.psm1:Get-CiscoDeviceInfo. -- Unable to determine Cisco software."
            }
            If (($CiscoOS -contains "IOS-XE") -and ($ShowVersion -match $Pattern4)) {
                $CiscoModel = "9K"
            }

            # Determine if Router Operating Mode exists
            If ($ShowVersion -match "Router Operating Mode") {
                $IsRouter = $true
            }

            # Get device type
            Switch -WildCard ($CiscoSoftware) {
                {($_ -like "*Switch*Software*")} {
                    $DeviceType = "Switch"
                }
                {($_ -like "*ASR*Software*") -or ($_ -like "*CSR*Software*") -or ($_ -like "*Virtual*XE*Software*") -or $IsRouter} {
                    $DeviceType = "Router"
                }
                {($_ -like "*ISR*Software*")} {
                    if ($SelectDeviceType){
                        $DeviceType = $SelectDeviceType -join ","
                    }
                    else {
                        $DeviceType = "Router,Switch"
                    }
                }
                {($CiscoOS -contains "IOS")} {
                    if ($SelectDeviceType){
                        $DeviceType = $SelectDeviceType -join ","
                    }
                    else {
                        $DeviceType = "Router,Switch"
                    }
                }
                {($CiscoModel -contains "9K")} {
                    #Switches are not conditionals. This must be last to overwrite previous successful switch cases.
                    if ($SelectDeviceType){
                        $DeviceType = $SelectDeviceType -join ","
                    }
                    else {
                        $DeviceType = "Router,Switch"
                    }
                }
                Default {
                    Throw "Cisco.psm1:Get-CiscoDeviceInfo: '$CiscoSoftware' does not match an expected CiscoSoftware output required to determine the Device Type. Try adding '-SelectDeviceType' <string> argument. "
                }
            }
        }
        Else {
            Throw "Unable to find 'Show Version' section"
        }

        # Get the serial number from Inventory data
        $Inventory = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Inventory
        If ($Inventory) {
            Switch -Regex ($Inventory) {
                "^Name:\s+`"{1}.*Stack`"{1}," {
                    $Model = ((($Inventory[($Inventory | Select-String "^Name:\s+`"{1}.*Stack`"{1}," | Select-Object -First 1).LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "^Name:\s+`"{1}.*Stack`"{1}," | Select-Object -First 1).LineNumber]) -Split "SN:")[1].Trim()
                }
                "^Name:\s+`"{1}.*Chassis`"{1}," {
                    $Model = ((($Inventory[($Inventory | Select-String "^Name:\s+`"{1}.*Chassis`"{1}," | Select-Object -First 1).LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "^Name:\s+`"{1}.*Chassis`"{1}," | Select-Object -First 1).LineNumber]) -Split "SN:")[1].Trim()
                }
                "^Name:\s+`"{1}.*Switch System`"{1}," {
                    $Model = ((($Inventory[($Inventory | Select-String "^Name:\s+`"{1}.*Switch System`"{1}," | Select-Object -First 1).LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "^Name:\s+`"{1}.*Switch System`"{1}," | Select-Object -First 1).LineNumber]) -Split "SN:")[1].Trim()
                }
            }
        }
        Else {
            Throw "unable to find 'Show Inventory' section"
        }

        # Get hostname
        $Hostname = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig | Select-String -Pattern "^hostname\s+" | Select-Object -First 1 | Out-String).Replace("hostname", "")).Trim().ToUpper()
        If (-Not($Hostname)) {
            # If 'hostname' not found, try Device Name in Show Version
            $Hostname = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version | Select-String -Pattern "^\s*Device name:" | Select-Object -First 1 | Out-String).Replace("Device name:", "")).Trim().ToUpper()
        }
        If (-Not($Hostname)) {
            # If 'hostname'STILL empty set static
            $Hostname = "NameNotFound"
        }

        # Get domain
        $DomainName = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig | Select-String -Pattern "^ip domain-name" | Select-Object -First 1 | Out-String).Replace("ip domain-name", "")).Trim()

        # Get MAC (if available)
        $MACAddress = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version | Select-String -Pattern "^Base Ethernet MAC Address\s*:" | Select-Object -First 1 | Out-String) -Replace "Base Ethernet MAC Address\s*:", "").Trim()

        # Put found data into an object and return it
        $NewObj = [PSCustomObject]@{
            Hostname      = $Hostname
            DomainName    = $DomainName
            MACAddress    = $MACAddress
            DeviceInfo    = $DeviceSoftwareInfo
            CiscoOS       = $CiscoOS
            CiscoOSVer    = $CiscoOSVer
            CiscoSoftware = $CiscoSoftware
            SerialNumber  = $SerialNumber
            Model         = $Model
            DeviceType    = $DeviceType
        }
        $Result.Add($NewObj)

        Return $Result
    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Get-Section {
    param(
        [String[]] $configData,
        [String] $sectionName
    )

    $pattern = '(?:^(!)\s*$)|(?:^[\s]+(.+)$)'
    $inSection = $false
    ForEach ($line in $configData) {
        # Skip empty lines
        If ($line -match '^\s*$') {
            Continue
        }
        If ($line -eq $sectionName) {
            $inSection = $true
            Continue
        }
        If ($inSection) {
            If ($line -match $pattern) {
                [Regex]::Matches($line, $pattern) | ForEach-Object {
                    If ($_.Groups[1].Success) {
                        $_.Groups[1].Value
                    }
                    Else {
                        $_.Groups[2].Value
                    }
                }
            }
            Else {
                $inSection = $false
            }
            If (-not($inSection)) {
                Break
            }
        }
    }
}

Function Invoke-ConfigFileScan {
    Param (
        # Evaluate-STIG parameters
        [Parameter(Mandatory = $true)]
        [String[]]$CiscoConfig,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Unclassified", "Classified")]
        [String]$ScanType = "Unclassified",

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
        [Int]$PreviousToKeep = 0,

        [Parameter(Mandatory = $false)]
        [SecureString]$SMPassphrase,

        [Parameter(Mandatory = $false)]
        [String]$SMCollection,

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
        [Int]$ThrottleLimit = 10,

        # Config file scan parameters
        [Parameter(Mandatory = $true)]
        [String]$ESVersion,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ES_Path,

        [Parameter(Mandatory = $true)]
        [String] $PowerShellVersion,

        [Parameter(Mandatory = $true)]
        [String] $CiscoScanDir,

        [Parameter(Mandatory = $true)]
        [String] $CiscoWorkingDir,

        #Optional argument for declaring layer-use state of device.
        [Parameter(Mandatory = $false)]
        [String[]]$SelectDeviceType
    )

    Try {
        $ConfigEvalStart = Get-Date
        $ProgressId = 1
        $ProgressActivity = "Evaluate-STIG (Version: $ESVersion | Scan Type: $ScanType | Answer Key: $AnswerKey)"

        $STIGLog_Cisco = Join-Path -Path $CiscoScanDir -ChildPath "Evaluate-STIG_Cisco.log"
        If (Test-Path $STIGLog_Cisco) {
            Remove-Item $STIGLog_Cisco -Force
        }
        $STIGLog_STIGManager = Join-Path -Path $CiscoScanDir -ChildPath "Evaluate-STIG_STIGManager.log"
        If (Test-Path $STIGLog_STIGManager) {
            Remove-Item $STIGLog_STIGManager -Force
        }
        $STIGLog_Splunk = Join-Path -Path $CiscoScanDir -ChildPath "Evaluate-STIG_Splunk.log"
        If (Test-Path $STIGLog_Splunk) {
            Remove-Item $STIGLog_Splunk -Force
        }

        # Reconstruct command line for logging purposes
        $ParamsNotForLog = @("ESVersion", "LogComponent", "OSPlatform", "ES_Path", "PowerShellVersion") # Parameters not be be written to log
        $CommandLine = Get-CommandLine -CommandName "Evaluate-STIG.ps1" -BoundParameters $PSBoundParameters -IgnoreParams $ParamsNotForLog

        # Begin logging
        Write-Log -Path $STIGLog_Cisco -Message "Executing: $($CommandLine)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

        # Verify Evaluate-STIG files integrity
        $FileIntegrityPass = $true
        $Verified = $true
        Write-Log -Path $STIGLog_Cisco -Message "Verifying Evaluate-STIG file integrity" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        If (Test-Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            If ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                $FileIntegrityPass = $false
                Write-Log -Path $STIGLog_Cisco -Message "ERROR: 'FileList.xml' failed authenticity check. Unable to verify content integrity." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            Else {
                foreach ($File in $FileListXML.FileList.File | Where-Object ScanReq -NE "NotRequired") {
                    $Path = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                    If (Test-Path $Path) {
                        If ((Get-FileHash -Path $Path -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                            $FileIntegrityPass = $false
                            $Verified = $false
                            Write-Log -Path $STIGLog_Cisco -Message "WARNING: '$($Path)' failed integrity check." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                    }
                    Else {
                        If ($File.ScanReq -eq "Required") {
                            $Verified = $false
                            Write-Log -Path $STIGLog_Cisco -Message "ERROR: '$($File.Name)' is a required file but not found. Scan results may be incomplete." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }
                    }
                }
                If ($Verified -eq $true) {
                    Write-Log -Path $STIGLog_Cisco -Message "Evaluate-STIG file integrity check passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                Else {
                    Write-Log -Path $STIGLog_Cisco -Message "WARNING: One or more Evaluate-STIG files failed integrity check." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
            }
        }
        Else {
            Throw "'FileList.xml' not found."
        }
        If ($FileIntegrityPass -ne $true) {
            If ($AllowIntegrityViolations -ne $true) {
                Write-Log -Path $STIGLog_Cisco -Message "File integrity checks failed - refer to $STIGLog_Cisco.  Aborting scan" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Return
            }
            Else {
                Write-Log -Path $STIGLog_Cisco -Message "-AllowIntegrityViolations specified so continuing with scan." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
            }
        }

        # Schema Files
        $STIGList_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "Schema_STIGList.xsd"
        $AnswerFile_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "Schema_AnswerFile.xsd"
        $Checklist_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "U_Checklist_Schema_V2.xsd"
        $Checklist_json = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "CKLB.schema.json"
        If (-Not(Test-Path $STIGList_xsd)) {
            Throw "'$STIGList_xsd' - file not found."
        }
        ElseIf (-Not(Test-Path $AnswerFile_xsd)) {
            Throw "'$AnswerFile_xsd' - file not found."
        }
        ElseIf (-Not(Test-Path $Checklist_xsd)) {
            Throw "'$Checklist_xsd' - file not found."
        }
        ElseIf (-Not(Test-Path $Checklist_json)) {
            Throw "'$Checklist_json' - file not found."
        }

        # STIGList.xml validation
        $XmlFile = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
        If (-Not(Test-Path $XmlFile)) {
            Throw "'$XmlFile' - file not found."
        }
        Else {
            $Result = Test-XmlValidation -XmlFile $XmlFile -SchemaFile $STIGList_xsd
            If ($Result -ne $true) {
                ForEach ($Item in $Result.Message) {
                    Write-Log -Path $STIGLog_Cisco -Message $Item -Component $LogComponent -Type "Error" -WriteOutToStream -OSPlatform $OSPlatform
                }
                Throw "'$($XmlFile)' failed XML validation"
            }
        }

        Write-Log -Path $STIGLog_Cisco -Message "Evaluate-STIG Version: $ESVersion" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Launching User: $([Environment]::Username)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "OS Platform: $OSPlatform" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "PS Version: $PowerShellVersion" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Scan Type: $ScanType" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Answer Key: $AnswerKey" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Answer File Path: $AFPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Output Path: $OutputPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

        # ++++++++++++++++++++++ Begin processing ++++++++++++++++++++++
        Write-Progress -Id $ProgressId -Activity $ProgressActivity -Status "Initializing and generating list of required STIGs"

        # --- Begin Answer File validation
        Write-Log -Path $STIGLog_Cisco -Message "Validating answer files" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        $AnswerFileList = New-Object System.Collections.Generic.List[System.Object]
        $XmlFiles = Get-ChildItem -Path $AFPath | Where-Object Extension -EQ ".xml"
        # Verify answer files for proper format
        ForEach ($Item in $XmlFiles) {
            $Validation = (Test-XmlValidation -XmlFile $Item.FullName -SchemaFile $AnswerFile_xsd)
            If ($Validation -eq $true) {
                Write-Log -Path $STIGLog_Cisco -Message "$($Item.Name) : Passed" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                [XML]$Content = Get-Content $Item.FullName
                If ($Content.STIGComments.Name) {
                    $NewObj = [PSCustomObject]@{
                        STIG          = $Content.STIGComments.Name
                        Name          = $Item.Name
                        FullName      = $Item.FullName
                        LastWriteTime = $Item.LastWriteTime
                    }
                    $AnswerFileList.Add($NewObj)
                }
            }
            Else {
                Write-Log -Path $STIGLog_Cisco -Message "ERROR: $($Item.Name) : Error - Answer file failed schema validation and will be ignored.  Please correct or remove." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $STIGLog_Cisco -Message "$($Validation.Message)" -Component $LogComponent -Type "Error" -WriteOutToStream -OSPlatform $OSPlatform
                Write-Host ""
            }
        }
        $AnswerFileList = $AnswerFileList | Sort-Object LastWriteTime -Descending
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        # --- End Answer File validation

        # Build list of valid configs to scan
        [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
        $STIGsToDetect = New-Object System.Collections.Generic.List[System.Object]

        If ($SelectSTIG) {
            ForEach ($Item in $SelectSTIG) {
                $Node = $STIGList.List.STIG | Where-Object ShortName -EQ $Item

                If ($Node) {
                    # Determine deprecation
                    $Deprecated = $false
                    If ($Node.DisaStatus -eq "Deprecated") {
                        $Deprecated = $true
                    }

                    $NewObj = [PSCustomObject]@{
                        Name           = $Node.Name
                        Shortname      = $Node.ShortName
                        StigContent    = $Node.StigContent
                        DetectionCode  = $Node.DetectionCode
                        PsModule       = $Node.PsModule
                        PsModuleVer    = $Node.PsModuleVer
                        CanCombine     = $Node.CanCombine
                        Classification = $Node.Classification
                        CklTechArea    = $Node.CklTechArea
                        Deprecated     = $Deprecated
                        Forced         = $false
                    }
                    $STIGsToDetect.Add($NewObj)
                }
            }
        }
        Else {
            ForEach ($Node in ($STIGList.List.STIG | Where-Object {($_.AssetType -in @("Cisco") -and $_.ShortName -notin $ExcludeSTIG)})) {
                # Determine deprecation
                $Deprecated = $false
                If ($Node.DisaStatus -eq "Deprecated") {
                    $Deprecated = $true
                }

                $NewObj = [PSCustomObject]@{
                    Name           = $Node.Name
                    Shortname      = $Node.ShortName
                    StigContent    = $Node.StigContent
                    DetectionCode  = $Node.DetectionCode
                    PsModule       = $Node.PsModule
                    PsModuleVer    = $Node.PsModuleVer
                    CanCombine     = $Node.CanCombine
                    Classification = $Node.Classification
                    CklTechArea    = $Node.CklTechArea
                    Deprecated     = $Deprecated
                    Forced         = $false
                }
                $STIGsToDetect.Add($NewObj)
            }
        }

        If ($ForceSTIG) {
            $ManualSTIGsToProcess = [System.Collections.Generic.List[System.Object]]::new()
            foreach ($ManualSTIG in $((Get-ChildItem $(Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual") | Where-Object Extension -EQ ".xml"))) {
                [xml]$Content = Get-Content $ManualSTIG.FullName
                $ManualSTIGName = $Content.Benchmark.ID
                $ManualSTIGShortname = "M_" + $($ManualSTIGName -replace "_", "" -replace "STIG", "")
                If ($ManualSTIGShortname -in $ForceSTIG){
                    if ($STIGList.List.STIG | Where-Object StigContent -EQ $ManualSTIG.Name){
                        Write-Log -Path $STIGLog_Cisco -Message "Manual scan for '$($ManualSTIGShortname)' requested with -ForceSTIG but is already supported. Ignoring." -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                    else{
                        Switch -Regex ($Content.'xml-stylesheet') {
                            'STIG_unclass.xsl' {
                                $Classification = "UNCLASSIFIED"
                            }
                            'STIG_cui.xsl' {
                                $Classification = "CUI"
                            }
                            DEFAULT {
                                $Classification = "No match in 'xml-stylesheet'."
                            }
                        }

                        If ($AnswerFileList | Where-Object {($_.STIG -eq $ManualSTIGShortname)}) {
                            $AFtoUse = ($AnswerFileList | Where-Object {($_.STIG -eq $ManualSTIGShortname)})[0]
                        }
                        Else {
                            $AFtoUse = ""
                        }
                        $NewObj = [PSCustomObject]@{
                            Name           = $ManualSTIGName
                            Shortname      = $ManualSTIGShortname
                            StigContent    = $ManualSTIG.Name
                            AnswerFile     = $AFtoUse
                            PsModule       = "Manual"
                            PsModuleVer    = "0.0.0.0"
                            UserSettings   = "false"
                            CanCombine     = "false"
                            Classification = $Classification
                            CklTechArea    = "Other Review"
                            Deprecated     = $false
                            Forced         = $true
                        }
                        $ManualSTIGsToProcess.Add($NewObj)
                        Write-Log -Path $STIGLog_Cisco -Message "Manual scan for '$($ManualSTIGShortname)' requested with -ForceSTIG. Adding to STIGs to process." -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                }
            }
            ForEach ($STIG in $ForceSTIG) {
                If ($STIG -notin $STIGsToProcess.ShortName) {
                    if ($STIGList.List.STIG | Where-Object ShortName -EQ $STIG){
                        $Node = $STIGList.List.STIG | Where-Object ShortName -EQ $STIG
                        If (($STIGList.List.STIG | Where-Object ShortName -EQ $STIG).AssetType -notin @('Other')) {
                            Write-Log -Path $STIGLog_Cisco -Message "WARNING: Scan for '$($Node.Name)' requested with -ForceSTIG but cannot be performed in this context. Ignoring." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                        Else {
                            If ($Node.ShortName -notin $DetectedSTIGs.ShortName) {
                                $Forced = $true
                                Write-Log -Path $STIGLog_Cisco -Message "WARNING: Scan for '$($Node.Name)' forced with -ForceSTIG.  Evaluate-STIG results are not guaranteed with this option.  Use at own risk." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            }
                            Else {
                                $Forced = $false
                            }
                            if ((Test-STIGDependencyFiles -RootPath $ES_Path -STIGData $Node -LogPath $STIGLog -OSPlatform $OSPlatform) -eq $true) {
                                If ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)}) {
                                    $AFtoUse = ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)})[0]
                                }
                                Else {
                                    $AFtoUse = ""
                                }

                                # Determine deprecation
                                $Deprecated = $false
                                If ($Node.DisaStatus -eq "Deprecated") {
                                    $Deprecated = $true
                                }

                                $NewObj = [PSCustomObject]@{
                                    Name           = $Node.Name
                                    Shortname      = $Node.ShortName
                                    StigContent    = $Node.StigContent
                                    AnswerFile     = $AFtoUse
                                    PsModule       = $Node.PsModule
                                    PsModuleVer    = $Node.PsModuleVer
                                    UserSettings   = $Node.UserSettings
                                    CanCombine     = $Node.CanCombine
                                    Classification = $Node.Classification
                                    CklTechArea    = $Node.CklTechArea
                                    Deprecated     = $Deprecated
                                    Forced         = $Forced
                                }
                                $STIGsToDetect.Add($NewObj)
                            }
                        }
                    }
                    else{
                        $NewObj = $ManualSTIGsToProcess | Where-Object {$_.Shortname -eq $STIG}
                        $STIGsToDetect.Add($NewObj)
                    }
                }
            }
        }
        If (-Not($STIGsToDetect)) {
            Throw "No config file based STIGs selected to scan."
        }
        $ConfigFiles = New-Object System.Collections.Generic.List[System.Object]
        Write-Log -Path $STIGLog_Cisco -Message "Looking for supported Cisco files" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Host "Refer to '$($CiscoScanDir)\Evaluate-STIG_Cisco.log' for info on detected files" -ForegroundColor DarkGray
        ForEach ($Item in $CiscoConfig) {
            [System.GC]::Collect()
            $CurrentSubStep = 1
            Write-Progress $ProgressId -Activity $ProgressActivity -Status "Looking for supported Cisco files in $Item"
            $Files = Get-ChildItem $Item -Recurse -File
            ForEach ($File in $Files.FullName) {
                $TCLOutput = $false
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity " " -Status $File -PercentComplete ($CurrentSubStep / $Files.Count * 100)
                $ShowTech = [System.IO.File]::OpenText($File).ReadToEnd() -split "`r`n" -split "`r" -split "`n"
                # If 'show running-config', and 'show version' sections do not exist then this file isn't a valid show tech-support file.
                If (-Not($ShowTech | Select-String "^-{18} show running-config -{18}")) {
                    If (-Not($ShowTech | Select-String -Pattern "\+\+ show running-config ")) {
                        # DISABLE TCL logging:  Write-Log -Path $STIGLog_Cisco -Message "ERROR: Unsupported file : $($File) [Not an output produced by Get-ESCiscoConfig.tcl or 'show tech-support'.]" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $STIGLog_Cisco -Message "WARNING: Unsupported file : $($File) [Missing configuration section 'show running-config']. Cancelling..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Continue
                    }
                }
                If (-Not($ShowTech | Select-String "^-{18} show version -{18}")) {
                    If (-Not($ShowTech | Select-String -Pattern "\+\+ show version ")) {
                        # DISABLE TCL logging:  Write-Log -Path $STIGLog_Cisco -Message "ERROR: Unsupported file : $($File) [Not an output produced by Get-ESCiscoConfig.tcl or 'show tech-support'.]" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $STIGLog_Cisco -Message "WARNING: Unsupported file : $($File) [Missing configuration section 'show version']. Cancelling..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Continue
                    }
                }
                If (-Not($ShowTech | Select-String "^-{18} show inventory -{18}")) {
                    # DISABLE TCL logging:  Write-Log -Path $STIGLog_Cisco -Message "ERROR: Unsupported file : $($File) [Not an output produced by Get-ESCiscoConfig.tcl or 'show tech-support'.]" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog_Cisco -Message "WARNING: Unsupported file : $($File) [Missing configuration section 'show inventory']. Some checks may fail resulting in incomplete ckl generation." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    #Continue
                }

                # If this is an Evaluate-STIG TCL output file, get just the Evaluate-STIG section.
                $startSTR = "^-{18} Show Evaluate-STIG Cisco .* -{18}$"
                $endSTR = "^-{18} End Evaluate-STIG Cisco Configuration -{18}$"
                If (($ShowTech | Select-String $startSTR) -and ($ShowTech | Select-String $endSTR)) {
                    $TCLOutput = $true
                    $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber
                    $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber
                    $ShowTech = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                }

                $DeviceInfoArgs = @{
                    ShowTech = $ShowTech
                }
                if ($SelectDeviceType) {
                    $DeviceInfoArgs.Add("SelectDeviceType", $SelectDeviceType)
                }
                $DeviceInfo = Get-CiscoDeviceInfo @DeviceInfoArgs
                If (($DeviceInfo).DeviceType -notin @("Router", "Switch","Switch,Router","Router,Switch")) {
                    Write-Log -Path $STIGLog_Cisco -Message "ERROR: Unsupported file : $($File) [File is not from a supported device. Refer to the supported STIGs list.]" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                }
                Else {
                    If ($File -notin $ConfigFiles.File) {
                        If ($TCLOutput -eq $true) {
                            Write-Log -Path $STIGLog_Cisco -Message "Supported TCL file : $($File)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        }
                        Else {
                            # DISABLE TCL logging:  Write-Log -Path $STIGLog_Cisco -Message "WARNING: Supported Non-TCL file : $($File) [Please consider generating output with Get-ESCiscoConfig.tcl for maximum compatibility.]" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                        $NewObj = [PSCustomObject]@{
                            ShowTech          = $ShowTech
                            DeviceInfo        = $DeviceInfo
                            ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
                            File              = $File
                        }
                        $ConfigFiles.Add($NewObj)
                    }
                }
                $CurrentSubStep++
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity " " -Completed
            }
        }
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Progress -Id $ProgressId -Activity $ProgressActivity -Completed

        # Create runspace pool to include required modules.
        $runspaces = New-Object System.Collections.ArrayList
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ImportPSModule($(Join-Path -Path $ES_Path -ChildPath Modules | Join-Path -ChildPath Master_Functions))
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $throttlelimit, $SessionState, $Host)
        $RunspacePool.Open()
        $RunspaceResults = @{}

        # Create pipeline input and output (results) object
        $RSObject = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'

        ForEach ($Item in $ConfigFiles) {
            # Build arguments hashtable
            $HashArguments = @{
                ShowTech          = $($Item.ShowTech)
                ShowRunningConfig = $($Item.ShowRunningConfig)
                DeviceInfo        = $($Item.DeviceInfo)
                CiscoConfig       = $($Item.File)
                ScanType          = $($ScanType)
                VulnTimeout       = $($VulnTimeout)
                AFPath            = $($AFPath)
                AnswerKey         = $($AnswerKey)
                OutputPath        = $($OutputPath)
                ESVersion         = $($ESVersion)
                LogComponent      = $($LogComponent)
                OSPlatform        = $($OSPlatform)
                ES_Path           = $($ES_Path)
                PowerShellVersion = $($PowerShellVersion)
                CiscoWorkingDir   = $($CiscoWorkingDir)
                Checklist_xsd     = $($Checklist_xsd)
                Checklist_json    = $($Checklist_json)
                STIGList          = $($STIGList)
                STIGsToDetect     = $($STIGsToDetect)
                STIGLog_Cisco     = $($STIGLog_Cisco)
                CiscoConfigLog    = $(Join-Path -Path $CiscoWorkingDir -ChildPath "Evaluate-STIG_Cisco_$(Split-Path $Item.File -Leaf).log")
            }
            If ($Marking) {
                $HashArguments.Add("Marking", $Marking)
            }
            If ($TargetComments) {
                $HashArguments.Add("TargetComments", $TargetComments)
            }
            If ($Output) {
                $HashArguments.Add("Output", $Output)

                If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                    $HashArguments.Add("PreviousToKeep", $PreviousToKeep)
                }

                If (($Output -split ",").Trim() -match "^STIGManager$") {
                    if ($SMPassphrase){
                        $HashArguments.SMPassphrase = $SMPassphrase
                    }
                    if ($SMCollection){
                        $HashArguments.SMCollection = $SMCollection
                    }
                }

                If (($Output -split ",").Trim() -match "^Splunk$") {
                    if ($SplunkHECName){
                        $HashArguments.SplunkHECName = $SplunkHECName
                    }
                }

                If (($Output -Split ",").Trim() -match "(^CSV$|^CombinedCSV$|^Splunk$)"){
                    If ($OutputPayload) {
                        $HashArguments.OutputPayload = $OutputPayload
                    }
                }
            }
            If ($AllowDeprecated) {
                $HashArguments.Add("AllowDeprecated", $true)
            }
            If ($AllowSeverityOverride) {
                $HashArguments.Add("AllowSeverityOverride", $true)
            }
            If ($AllowIntegrityViolations) {
                $HashArguments.Add("AllowIntegrityViolations", $true)
            }
            If ($SelectSTIG) {
                $HashArguments.Add("SelectSTIG", $SelectSTIG)
            }
            If ($SelectVuln) {
                $HashArguments.Add("SelectVuln", $SelectVuln)
            }
            If ($ExcludeVuln) {
                $HashArguments.Add("ExcludeVuln", $ExcludeVuln)
            }
            If ($ForceSTIG) {
                $HashArguments.Add("ForceSTIG", $ForceSTIG)
            }
            If ($AnswerFileList) {
                $HashArguments.Add("AnswerFileList", $AnswerFileList)
            }

            $CiscoBlock = {
                Param (
                    # Evaluate-STIG parameters
                    $ShowTech,
                    $ShowRunningConfig,
                    $DeviceInfo,
                    $ScanType,
                    $Marking,
                    $TargetComments,
                    $VulnTimeout,
                    $AFPath,
                    $AnswerKey,
                    $Output,
                    $OutputPath,
                    $PreviousToKeep,
                    $SMPassphrase,
                    $SMCollection,
                    $AllowDeprecated,
                    $AllowIntegrityViolations,
                    $SelectSTIG,
                    $SelectVuln,
                    $ExcludeVuln,
                    $OutputPayload,
                    $ForceSTIG,
                    $ThrottleLimit,
                    # Config file scan parameters
                    $ESVersion,
                    $LogComponent,
                    $OSPlatform,
                    $ES_Path,
                    $PowerShellVersion,
                    $Checklist_xsd,
                    $Checklist_json,
                    $CiscoWorkingDir,
                    $CiscoConfigLog,
                    $STIGLog_Cisco,
                    $CiscoConfig,
                    $STIGList,
                    $STIGsToDetect,
                    $AnswerFileList
                )

                Try {
                    $EvalStart = Get-Date
                    $ScanStartDate = (Get-Date -Format "MM/dd/yyyy")
                    If (Test-Path $CiscoConfigLog) {
                        Remove-Item $CiscoConfigLog -Force
                    }
                    Write-Log -Path $CiscoConfigLog -Message "Begin Config File Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    $ProgressPreference = "SilentlyContinue"
                    [int]$TotalMainSteps = 1
                    [int]$CurrentMainStep = 1

                    # Build list of required STIGs
                    $DetectedSTIGs = New-Object System.Collections.Generic.List[System.Object]
                    ForEach ($Node in $STIGList.List.STIG | Where-Object {$_.AssetType -in @("Cisco")}) {
                        If ($Node.DetectionCode -and (Invoke-Expression $Node.DetectionCode) -eq $true) {
                            $NewObj = [PSCustomObject]@{
                                Name       = $Node.Name
                                Shortname  = $Node.ShortName
                                DISAStatus = $Node.DISAStatus
                            }
                            $DetectedSTIGs.Add($NewObj)
                        }
                    }

                    $STIGsToProcess = New-Object System.Collections.Generic.List[System.Object]
                    ForEach ($Node in $STIGsToDetect) {
                        If ($Node.ShortName -in $DetectedSTIGs.ShortName) {
                            If ((Test-STIGDependencyFiles -RootPath $ES_Path -STIGData $Node -LogPath $CiscoConfigLog -OSPlatform $OSPlatform) -eq $true) {
                                If ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)}) {
                                    $AFtoUse = ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)})[0]
                                }
                                Else {
                                    $AFtoUse = ""
                                }

                                # Determine deprecation
                                $Deprecated = $false
                                If ($Node.DisaStatus -eq "Deprecated") {
                                    $Deprecated = $true
                                }

                                $NewObj = [PSCustomObject]@{
                                    Name           = $Node.Name
                                    Shortname      = $Node.ShortName
                                    StigContent    = $Node.StigContent
                                    AnswerFile     = $AFtoUse
                                    PsModule       = $Node.PsModule
                                    PsModuleVer    = $Node.PsModuleVer
                                    CanCombine     = $Node.CanCombine
                                    Classification = $Node.Classification
                                    CklTechArea    = $Node.CklTechArea
                                    Deprecated     = $Deprecated
                                    Forced         = $false
                                }
                                $STIGsToProcess.Add($NewObj)
                            }
                        }
                        ElseIf ($Node.Forced -eq $true -and $Node.PsModule -ne "Manual") {
                            Write-Log -Path $CiscoConfigLog -Message "WARNING: Scan for '$($Node.Name)' forced with -ForceSTIG. Evaluate-STIG results are not guaranteed with this option. Use at own risk." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            If ((Test-STIGDependencyFiles -RootPath $ES_Path -STIGData $Node -LogPath $CiscoConfigLog -OSPlatform $OSPlatform) -eq $true) {
                                If ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)}) {
                                    $AFtoUse = ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)})[0]
                                }
                                Else {
                                    $AFtoUse = ""
                                }

                                # Determine deprecation
                                $Deprecated = $false
                                If ($Node.DisaStatus -eq "Deprecated") {
                                    $Deprecated = $true
                                }

                                $NewObj = [PSCustomObject]@{
                                    Name           = $Node.Name
                                    Shortname      = $Node.ShortName
                                    StigContent    = $Node.StigContent
                                    AnswerFile     = $AFtoUse
                                    PsModule       = $Node.PsModule
                                    PsModuleVer    = $Node.PsModuleVer
                                    CanCombine     = $Node.CanCombine
                                    Classification = $Node.Classification
                                    CklTechArea    = $Node.CklTechArea
                                    Deprecated     = $Deprecated
                                    Forced         = $true
                                }
                                $STIGsToProcess.Add($NewObj)
                            }
                        }
                        elseif ($Node.PsModule -eq "Manual") {
                            If ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)}) {
                                $AFtoUse = ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName)})[0]
                            }
                            Else {
                                $AFtoUse = ""
                            }

                            # Determine deprecation
                            $Deprecated = $false
                            If ($Node.DisaStatus -eq "Deprecated") {
                                $Deprecated = $true
                            }

                            $NewObj = [PSCustomObject]@{
                                Name           = $Node.Name
                                Shortname      = $Node.ShortName
                                StigContent    = $Node.StigContent
                                AnswerFile     = $AFtoUse
                                PsModule       = $Node.PsModule
                                PsModuleVer    = $Node.PsModuleVer
                                CanCombine     = $Node.CanCombine
                                Classification = $Node.Classification
                                CklTechArea    = $Node.CklTechArea
                                Deprecated     = $Deprecated
                                Forced         = $true
                            }
                            $STIGsToProcess.Add($NewObj)
                        }
                    }
                    $CurrentSubStep++
                    [int]$TotalMainSteps = $TotalMainSteps + $STIGsToProcess.Count

                    $MachineName = $DeviceInfo.Hostname
                    $WorkingDir = Join-Path -Path $CiscoWorkingDir -ChildPath $MachineName
                    If (Test-Path $WorkingDir) {
                        Remove-Item $WorkingDir -Recurse -Force
                    }
                    $null = New-Item -Path $WorkingDir -ItemType Directory -ErrorAction Stop

                    If ($OutputPath) {
                        If ($SelectVuln) {
                            $ResultsPath = Join-Path -Path $OutputPath -ChildPath "_Partial_$MachineName"
                        }
                        Else {
                            $ResultsPath = Join-Path -Path $OutputPath -ChildPath $MachineName
                        }
                    }

                    Write-Log -Path $CiscoConfigLog -Message "Hostname: $MachineName" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $CiscoConfigLog -Message "File: $($CiscoConfig)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $CiscoConfigLog -Message "Executing scan" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    # Get AssetData
                    $AssetData = Get-AssetData -OSPlatform Cisco -ShowRunningConfig $ShowRunningConfig -DeviceInfo $DeviceInfo

                    $STIGLog = Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG.log"
                    If ($Marking) {
                        Write-Log -Path $STIGLog -Message "                                                                                          $Marking                                                                                          " -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                    Write-Log -Path $STIGLog -Message "Begin Local Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Evaluate-STIG Version: $ESVersion" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Launching User: $([Environment]::Username)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "File: $($CiscoConfig)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Hostname: $MachineName" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Manufacturer: $($AssetData.Manufacturer)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Model: $($AssetData.Model)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Operating System: Cisco" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Operating System Name: $($AssetData.OSName)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Operating System Version: $($AssetData.OSVersion)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Cisco Software: $($DeviceInfo.CiscoSoftware)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Device Type: $($DeviceInfo.DeviceType)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    # Write list of STIGs that will be evaluated to log
                    ForEach ($STIG in ($STIGsToProcess | Where-Object Forced -EQ $true)) {
                        Write-Log -Path $STIGLog -Message "WARNING: Scan for '$($Node.Name)' forced with -ForceSTIG. Evaluate-STIG results are not guaranteed with this option. Use at own risk." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                    }

                    # Note ApplicableSTIGs in log (deprecated are not considered applicable given they no longer exist on cyber.mil)
                    Write-Log -Path $STIGLog -Message "The following STIGs are determined applicable:" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    ForEach ($STIG in ($DetectedSTIGs | Where-Object DISAStatus -NE "Deprecated") | Sort-Object Name) {
                        Write-Log -Path $STIGLog -Message "STIG: $($STIG.Name)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                    Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    $ApplicableSTIGs = @()
                    ForEach ($Item in ($DetectedSTIGs | Where-Object DISAStatus -NE "Deprecated")) {
                        $ApplicableSTIGs += ($STIGList.List.STIG | Where-Object ShortName -EQ $Item.ShortName)
                    }

                    # If no supported STIGs are applicable, log it and continue
                    If (($STIGsToProcess | Measure-Object).Count -eq 0) {
                        Write-Log -Path $STIGLog -Message "WARNING: $($CiscoConfig) : No Evaluate-STIG supported STIGs are applicable to this system." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "WARNING: No Evaluate-STIG supported STIGs are applicable to this system." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "End Config File Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Cisco -Value $(Get-Content $CiscoConfigLog)
                        Remove-Item $CiscoConfigLog

                        $TempFiles = Get-Item -Path $WorkingDir
                        If ($TempFiles) {
                            ForEach ($Item in $TempFiles) {
                                Try {
                                    $null = Remove-Item -Path $Item.FullName -Recurse -ErrorAction Stop
                                }
                                Catch {
                                    Write-Log -Path $STIGLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                    Write-Log -Path $CiscoConfigLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                }
                            }
                        }
                    }
                    Else {
                        # Write list of STIGs that will be evaluated to log
                        Write-Log -Path $STIGLog -Message "The following STIGs will be evaluated:" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        ForEach ($STIG in $STIGsToProcess | Sort-Object Name) {
                            $AnswerFileMsg = ""
                            If ($STIG.AnswerFile) {
                                $AnswerFileMsg = "  |  AnswerFile: $($STIG.AnswerFile.Name) (Modified: $(Get-Date (Get-ChildItem $STIG.AnswerFile.FullName).LastWriteTime -Format "dd MMM yyyy HH:mm:ss"))"
                            }

                            If ($STIG.Deprecated -eq $true) {
                                Write-Log -Path $STIGLog -Message "STIG: $($STIG.Name) [Deprecated]$($AnswerFileMsg)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            }
                            Else {
                                Write-Log -Path $STIGLog -Message "STIG: $($STIG.Name)$($AnswerFileMsg)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            }
                        }
                        Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        # Test connectivity to OutputPath and create folder for computer
                        Try {
                            If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                                If (-Not(Test-Path $ResultsPath)) {
                                    $null = New-Item $ResultsPath -ItemType Directory -ErrorAction Stop
                                    Start-Sleep 5
                                }
                            }
                        }
                        Catch {
                            Write-Log -Path $STIGLog -Message "ERROR: Failed to create output path $($ResultsPath)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            Throw $_
                        }

                        # =========== Run the scans ===========
                        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                            # $tmpResultsPath is needed for all filetype Outputs needed for all filetype Outputs
                            $tmpResultsPath = $(Join-Path -Path $WorkingDir -ChildPath "Results")
                            If (-Not(Test-Path $tmpResultsPath)) {
                                $null = New-Item -Path $tmpResultsPath -ItemType Directory
                            }
                        }

                        $ApplicableSTIGsCount = [System.Collections.Generic.List[System.Object]]::new()
                        $ProcessedSTIGs = [System.Collections.Generic.List[System.Object]]::new()
                        $ScanObjects = [System.Collections.Generic.List[System.Object]]::new()
                        $ScanJobs = [System.Collections.Generic.List[System.Object]]::new()
                        # Get STIG instance counts and build list of jobs to be ran
                        $STIGsToDetect = [System.Collections.Generic.List[System.Object]]::new()
                        ForEach ($Item in $STIGsToProcess) {
                            $STIGsToDetect.Add($Item)
                        }
                        ForEach ($Item in $ApplicableSTIGs) {
                            If ($Item.ShortName -notin $STIGsToDetect.ShortName) {
                                $NewObj = [PSCustomObject]@{
                                    Name           = $Item.Name
                                    Shortname      = $Item.ShortName
                                    StigContent    = $Item.StigContent
                                    AnswerFile     = ""
                                    PsModule       = $Item.PsModule
                                    PsModuleVer    = $Item.PsModuleVer
                                    UserSettings   = $Item.UserSettings
                                    CanCombine     = $Item.CanCombine
                                    Classification = $Item.Classification
                                    CklTechArea    = $Item.CklTechArea
                                    Deprecated     = $Deprecated
                                    Forced         = $false
                                }
                                $STIGsToDetect.Add($NewObj)
                            }
                        }

                        Write-Log -Path $STIGLog -Message "Getting instance counts and building job list" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        ForEach ($Item in ($STIGsToDetect | Sort-Object Name)) {
                            Try {
                                # Create subjobs object for STIGs that may apply multiple times (IIS, SQL, etc.)
                                $SubJobs = [System.Collections.Generic.List[System.Object]]::new()

                                # Set path to STIG .xccdf.xml and get needed data from it
                                if (Test-Path $(Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Item.StigContent)) {
                                    # Temporarily import scan module for access to custom functions
                                    If ($PowerShellVersion -lt [Version]"7.0") {
                                        Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Item.PsModule)) -ErrorAction Stop
                                    }
                                    Else {
                                        Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Item.PsModule)) -SkipEditionCheck -ErrorAction Stop
                                    }
                                    $StigXmlPath = $(Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Item.StigContent)
                                }
                                else {
                                    $StigXmlPath = $(Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath "Manual" | Join-Path -ChildPath $Item.StigContent)
                                }
                                $STIGID = ((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.id).Trim()
                                $STIGTitle = ((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.Title).Trim()
                                $STIGVer = ((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.Version).Trim()
                                $STIGRel = ((((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Benchmark')[0].Trim() -split ' ')[1].Trim()
                                $STIGDate = (((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Date:')[1].Trim()
                                $STIGVersion = "V$($STIGVer)R$($STIGRel)"
                                $STIGStyleSheet = ((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).'xml-stylesheet').Trim()
                                # Set STIG Classification
                                Switch -Regex ($STIGStyleSheet) {
                                    'STIG_unclass.xsl' {
                                        $Classification = "UNCLASSIFIED"
                                    }
                                    'STIG_cui.xsl' {
                                        $Classification = "CUI"
                                    }
                                    DEFAULT {
                                        $Classification = "No match in 'xml-stylesheet'."
                                    }
                                }

                                $STIGTargetKey = (Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.Group[0].Rule.reference.identifier

                                # Build STIGInfo Object
                                $STIGInfo = [ordered]@{
                                    STIGID         = $STIGID
                                    Title          = $STIGTitle
                                    Version        = $STIGVer
                                    Release        = $STIGRel
                                    ReleaseDate    = $STIGDate
                                    Classification = $Classification
                                    EvalScore      = 0
                                    CATI_OpenNRTotal   = 0
                                    CATII_OpenNRTotal  = 0
                                    CATIII_OpenNRTotal = 0
                                }

                                # Build TargetData Object
                                Switch -Regex ($AssetData.Role) {
                                    "Workstation" {
                                        $Role = "Workstation"
                                    }
                                    "Server" {
                                        $Role = "Member Server"
                                    }
                                    "Domain Controller" {
                                        $Role = "Domain Controller"
                                    }
                                    DEFAULT {
                                        $Role = $AssetData.Role
                                    }
                                }

                                $PrimaryIpAddress = ""
                                $PrimaryMacAddress = ""
                                If ($AssetData.ActiveAdapters) {
                                    $PrimaryAdapter = ($AssetData.ActiveAdapters | Sort-Object InterfaceIndex)[0]
                                    $PrimaryIpAddress = $($PrimaryAdapter[0]).IPv4Address
                                    $PrimaryMacAddress = $($PrimaryAdapter[0]).MacAddress
                                }
                                $TargetData = [ordered]@{
                                    Marking        = $Marking
                                    Hostname       = $AssetData.HostName
                                    IpAddress      = $PrimaryIpAddress
                                    MacAddress     = $PrimaryMacAddress
                                    FQDN           = $AssetData.FQDN
                                    TargetComments = $TargetComments
                                    Role           = $Role
                                    CklTechArea    = $Item.CklTechArea
                                }
                                $TargetData.Add("TargetKey", $STIGTargetKey)
                                $TargetData.Add("WebOrDatabase", $false) # Initialize 'WebOrDatabase'.  If required, set below.
                                $TargetData.Add("Site", "")              # Initialize 'Site'.  If required, set below.
                                $TargetData.Add("Instance", "")          # Initialize 'Instance'.  If required, set below.

                                $STIGData = @{
                                    StigXmlPath = $StigXmlPath
                                    StigVersion = $STIGVersion
                                    Name        = $Item.Name
                                    ShortName   = $Item.ShortName
                                    PsModule    = $Item.PsModule
                                    CanCombine  = $Item.CanCombine
                                }

                                # Reset WebOrDatabase, Site, and Instance for each STIG.
                                $TargetData.WebOrDatabase = $false
                                $TargetData.Site = ""
                                $TargetData.Instance = ""

                                # Set parameters for Invoke-STIGScan
                                $ScanArgs = @{
                                    StigXmlPath           = $StigXmlPath
                                    VulnTimeout           = $VulnTimeout
                                    Deprecated            = $Item.Deprecated
                                    AllowSeverityOverride = $AllowSeverityOverride
                                    SelectVuln            = $SelectVuln
                                    ExcludeVuln           = $ExcludeVuln
                                    Forced                = $Item.Forced
                                    ModulesPath           = $(Join-Path -Path $ES_Path -ChildPath "Modules")
                                    PsModule              = $Item.PsModule
                                    LogPath               = $STIGLog
                                    LogComponent          = $LogComponent
                                    OSPlatform            = $OSPlatform
                                    ProgressId            = $ProgressId
                                    ModuleArgs            = @{} # Initialze ModuleArgs object
                                }

                                # Set common arguments for scan module.  Additional variables and parameters may be added.
                                $ScanArgs.ModuleArgs.Add("ScanType", $ScanType)
                                if ($Item.AnswerFile.FullName) {
                                    $ScanArgs.ModuleArgs.Add("AnswerFile", "'$($Item.AnswerFile.FullName)'")
                                }
                                else {
                                    $ScanArgs.ModuleArgs.Add("AnswerFile", "")
                                }
                                $ScanArgs.ModuleArgs.Add("AnswerKey", $AnswerKey)
                                $ScanArgs.ModuleArgs.Add("Username", "NA")
                                $ScanArgs.ModuleArgs.Add("UserSID", "NA")
                                $ScanArgs.ModuleArgs.Add("ESVersion", $ESVersion)
                                $ScanArgs.ModuleArgs.Add("LogPath", $STIGLog)
                                $ScanArgs.ModuleArgs.Add("OSPlatform", $OSPlatform)
                                $ScanArgs.ModuleArgs.Add("LogComponent", $LogComponent)

                                # Build list of variables to be exposed to answer files.  Additional variables can be added per STIG when required.
                                $AnswerFileVars = @{
                                    ESPath   = $ES_Path
                                    Hostname = $AssetData.HostName
                                    Username = "NA"
                                    UserSID  = "NA"
                                    Instance = ""
                                    Database = ""
                                    Site     = ""
                                }
                                $ScanArgs.ModuleArgs.Add("AnswerFileVars", $AnswerFileVars)

                                # Add additional module arguments
                                $ScanArgs.ModuleArgs.Add("DeviceInfo", $DeviceInfo)
                                $ScanArgs.ModuleArgs.Add("ShowTech", $ShowTech)
                                $ScanArgs.ModuleArgs.Add("ShowRunningConfig", $ShowRunningConfig)

                                Try {
                                    # Set output filename
                                    $BaseFileName = Format-BaseFileName -Hostname $TargetData.HostName -STIGShortName $STIGData.ShortName -STIGVersion $STIGData.StigVersion

                                    # Build and add sub job
                                    $NewObj = [PSCustomObject]@{
                                        BaseFileName = $BaseFileName
                                        STIGInfo     = $STIGInfo
                                        TargetData   = $TargetData
                                        ScanArgs     = $ScanArgs
                                    }
                                    $SubJobs.Add($NewObj)
                                }
                                Catch {
                                    Throw $_
                                }

                                # Add instance count(s) for STIG if deemed applicable
                                If ($Item.ShortName -in $ApplicableSTIGs.ShortName) {
                                    $NewObj = [PSCustomObject]@{
                                        ShortName        = $Item.ShortName
                                        Total            = ($SubJobs | Measure-Object).Count
                                        DetectionSuccess = $true
                                    }
                                    $ApplicableSTIGsCount.Add($NewObj)
                                }

                                # Add scan job if selected for scanning
                                If ($Item.Shortname -in $STIGsToProcess.ShortName) {
                                    Write-Log -Path $STIGLog -Message "Creating scan job(s) for $($Item.ShortName)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                    $NewObj = [PSCustomObject]@{
                                        STIGData = $STIGData
                                        SubJobs  = $SubJobs
                                    }
                                    $ScanJobs.Add($NewObj)
                                }

                                # Add STIG to ProcessedSTIGs for AssetData.ScanSummary
                                If ($Item.ShortName -in $STIGsToProcess.ShortName) {
                                    $Flags = @()
                                    If ($Item.Deprecated) {
                                        $Flags += "[Deprecated]"
                                    }
                                    If ($Item.Forced) {
                                        $Flags += "[Forced]"
                                    }
                                    $NewObj = [PSCustomObject]@{
                                        ShortName = $Item.ShortName
                                        Flags     = $Flags
                                    }
                                    $ProcessedSTIGs.Add($NewObj)
                                }
                            }
                            Catch {
                                Write-Log -Path $STIGLog -Message "Unable to process $($Item.ShortName) - skipping" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                $ErrorData = $_ | Get-ErrorInformation
                                If ($STIGLog -and (Test-Path $STIGLog)) {
                                    ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                                        Write-Log -Path $STIGLog -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                    }
                                }

                                # Add a single instance count for STIG if deemed applicable
                                If ($Item.ShortName -in $ApplicableSTIGs.ShortName) {
                                    $NewObj = [PSCustomObject]@{
                                        ShortName        = $Item.ShortName
                                        Total            = 1
                                        DetectionSuccess = $false
                                    }
                                    $ApplicableSTIGsCount.Add($NewObj)
                                }
                            }
                        }

                        # Execute the scans
                        $FailedCheck = $false
                        ForEach ($Job in $ScanJobs) {
                            Try {
                                Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                $CurrentMainStep++

                                Write-Log -Path $STIGLog -Message "Invoking scan" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                $ModError = ""
                                Try {
                                    if ($Job.STIGData.PsModule -ne "Manual") {
                                        Write-Log -Path $STIGLog -Message "Importing scan module: $($Job.STIGData.PsModule)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                        If ($PowerShellVersion -lt [Version]"7.0") {
                                            Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Job.STIGData.PsModule)) -ErrorAction Stop
                                        }
                                        Else {
                                            Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Job.STIGData.PsModule)) -SkipEditionCheck -ErrorAction Stop
                                        }
                                        $PsModule = (Get-Module $Job.STIGData.PsModule)
                                        Write-Log -Path $STIGLog -Message "Module Version: $($PsModule.Version)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                    }
                                    else {
                                        Write-Log -Path $STIGLog -Message "$($Job.STIGData.Name) added manually. No module to import." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                    }
                                }
                                Catch {
                                    $ModError = $_.Exception.Message
                                }

                                If ($ModError) {
                                    # If module failed to import, display reason and continue to next STIG.
                                    Write-Log -Path $STIGLog -Message "ERROR: $($ModError)" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                }
                                Else {
                                    # Build ESData Object
                                    if ($Job.STIGData.ShortName -match "^M_") {
                                        $IsManualSTIG = $true
                                    }
                                    else {
                                        $IsManualSTIG = $false
                                    }

                                    $ESData = [Ordered]@{
                                        ESVersion     = $ESVersion
                                        StartTime     = (Get-Date -Format 'o')
                                        ModuleName    = $PsModule.Name
                                        ModuleVersion = $PsModule.Version
                                        STIGName      = $Job.STIGData.Name
                                        STIGShortName = $Job.STIGData.ShortName
                                        CanCombine    = $Job.STIGData.CanCombine
                                        STIGXMLName   = $($Job.STIGData.StigXmlPath | Split-Path -Leaf)
                                        IsManualSTIG  = $IsManualSTIG
                                        FileName      = ""
                                    }

                                    # Set filename and additional requirements
                                    ForEach ($SubJob in $Job.SubJobs) {
                                        # Update BaseFileName if -SelectVuln is used
                                        If ($SelectVuln) {
                                            $SubJob.BaseFileName = "Partial_$($SubJob.BaseFileName)"
                                        }

                                        # Write Site/Intance info to log
                                        If ($SubJob.TargetData.Site) {
                                            Write-Log -Path $STIGLog -Message "Site: $($SubJob.TargetData.Site)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                        }
                                        If ($SubJob.TargetData.Instance) {
                                            Write-Log -Path $STIGLog -Message "Instance: $($SubJob.TargetData.Instance)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                        }

                                        # Execute scan
                                        $ScanArgs = $SubJob.ScanArgs
                                        $VulnResults = Invoke-STIGScan @ScanArgs

                                        # Look for any failed checks
                                        If ($VulnResults | Where-Object CheckError -EQ $true) {
                                            $FailedCheck = $true
                                        }

                                        # Calculate Score and add to STIGInfo : (NF + NA) / Total Checks * 100
                                        $EvalScore = [System.Math]::Round((($VulnResults | Where-Object Status -In @("NotAFinding", "Not_Applicable") | Measure-Object).Count / ($VulnResults | Measure-Object).Count * 100), 2)
                                        $SubJob.STIGInfo.EvalScore = $EvalScore
                                        Write-Log -Path $STIGLog -Message "EvalScore: $($EvalScore)%" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                                        
                                        $SubJob.STIGInfo.CATI_OpenNRTotal = (($VulnResults | where-Object {$_.Status -in ("Not_Reviewed", "Open") -and $_.Severity -eq "High"}) | Measure-Object).count
                                        $SubJob.STIGInfo.CATII_OpenNRTotal = (($VulnResults | where-Object {$_.Status -in ("Not_Reviewed", "Open") -and $_.Severity -eq "Medium"}) | Measure-Object).count
                                        $SubJob.STIGInfo.CATIII_OpenNRTotal = (($VulnResults | where-Object {$_.Status -in ("Not_Reviewed", "Open") -and $_.Severity -eq "Low"}) | Measure-Object).count

                                        Write-Log -Path $STIGLog -Message "CATI Open/NR: $($SubJob.STIGInfo.CATI_OpenNRTotal)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                        Write-Log -Path $STIGLog -Message "CATII Open/NR: $($SubJob.STIGInfo.CATII_OpenNRTotal)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                        Write-Log -Path $STIGLog -Message "CATIII Open/NR: $($SubJob.STIGInfo.CATIII_OpenNRTotal)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                                        # Build ScanObject
                                        $ScanObject = [System.Collections.Generic.List[System.Object]]::new()
                                        $NewObj = [PSCustomObject]@{
                                            AssetData   = $AssetData
                                            ESData      = $ESData
                                            STIGInfo    = $SubJob.STIGInfo
                                            TargetData  = $SubJob.TargetData
                                            VulnResults = $VulnResults
                                        }
                                        $ScanObject.Add($NewObj)

                                        # Send ScanObject to outputs (CKL, CKLB, CSV, XCCDF)
                                        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$)") {
                                            $tmpChecklistPath = Join-Path -Path $tmpResultsPath -ChildPath "Checklist"
                                            If (-Not(Test-Path $tmpChecklistPath)) {
                                                $null = New-Item -Path $tmpChecklistPath -ItemType Directory
                                            }
                                            $GenerateSingleCKL = $false
                                            $GenerateSingleCKLB = $false
                                            $GenerateSingleCSV = $false
                                            If ("CKL" -in $Output) {
                                                $GenerateSingleCKL = $true
                                            }
                                            If ("CombinedCKL" -in $Output) {
                                                If ($ScanObject.ESData.CanCombine -ne $true) {
                                                    $GenerateSingleCKL = $true
                                                }
                                            }
                                            If ("CKLB" -in $Output) {
                                                $GenerateSingleCKLB = $true
                                            }
                                            If ("CombinedCKLB" -in $Output) {
                                                If ($ScanObject.ESData.CanCombine -ne $true) {
                                                    $GenerateSingleCKLB = $true
                                                }
                                            }
                                            If ("CSV" -in $Output) {
                                                $GenerateSingleCSV = $true
                                            }
                                            If ("CombinedCSV" -in $Output) {
                                                If ($ScanObject.ESData.CanCombine -ne $true) {
                                                    $GenerateSingleCSV = $true
                                                }
                                            }
                                            If ("XCCDF" -in $Output) {
                                                $GenerateSingleXCCDF = $true
                                            }

                                            If ($GenerateSingleCKL) {
                                                Write-Log -Path $STIGLog -Message "Creating CKL file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                Write-Log -Path $STIGLog -Message "ESPath : $ES_Path" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($SubJob.BaseFileName)_$(Get-Date -Format yyyyMMdd-HHmmss).ckl")
                                                $ChecklistValid = Format-CKL -SchemaPath $Checklist_xsd -ScanObject $ScanObject -OutputPath $SaveFile -Marking $Marking -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent

                                                # Action for validation result
                                                If ($ChecklistValid) {
                                                    $ScanObject.ESData.FileName = $(Split-Path $SaveFile -Leaf)
                                                }
                                            }

                                            If ($GenerateSingleCKLB) {
                                                Write-Log -Path $STIGLog -Message "Creating CKLB file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($SubJob.BaseFileName)_$(Get-Date -Format yyyyMMdd-HHmmss).cklb")
                                                $ChecklistValid = Format-CKLB -SchemaPath $Checklist_json -ScanObject $ScanObject -OutputPath $SaveFile -Marking $Marking -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent

                                                # Action for validation result
                                                If ($ChecklistValid) {
                                                    $ScanObject.ESData.FileName = $(Split-Path $SaveFile -Leaf)
                                                }
                                            }

                                            if ($GenerateSingleCSV){
                                                Write-Log -Path $STIGLog -Message "Creating CSV file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($SubJob.BaseFileName)_$(Get-Date -Format yyyyMMdd-HHmmss).csv")
                                                Format-Object -ScanObject $ScanObject -OutputPayload $OutputPayload | Export-CSV -NoTypeInformation -Path $SaveFile

                                                $ScanObject.ESData.FileName = $(Split-Path $SaveFile -Leaf)
                                            }

                                            If ($GenerateSingleXCCDF) {
                                                Write-Log -Path $STIGLog -Message "Creating XCCDF file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($SubJob.BaseFileName)_$(Get-Date -Format yyyyMMdd-HHmmss).xccdf.xml")
                                                $XCCDF = Format-XCCDF -ScanObject $ScanObject -OutputPath $SaveFile -Marking $Marking -ESPath $ES_Path

                                                # Action for validation result
                                                If ($XCCDF -eq $true) {
                                                    $ScanObject.ESData.FileName = $(Split-Path $SaveFile -Leaf)
                                                }
                                                Else {
                                                    $ErrorData = $XCCDF | Get-ErrorInformation
                                                    ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                                                        Write-Log -Path $STIGLog -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                                    }
                                                }
                                            }
                                        }
                                        # Add to ScanObjects object console or combined checklist output
                                        $ScanObjects.Add($ScanObject)
                                    }

                                    Write-Log -Path $STIGLog -Message "Removing scan module from memory" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                    Remove-Module $Job.STIGData.PsModule -Force
                                    [System.GC]::Collect()
                                }
                            }
                            Catch {
                                $ErrorData = $_ | Get-ErrorInformation
                                If ($STIGLog -and (Test-Path $STIGLog)) {
                                    ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                                        Write-Log -Path $STIGLog -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                    }
                                }
                                Write-Log -Path $STIGLog -Message "Continuing Processing" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                [System.GC]::Collect()
                            }
                        }

                        # Create combined checklists
                        If (($Output -split ",").Trim() -match "(^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$)") {
                            Write-Log -Path $STIGLog -Message "-" -TemplateMessage  LineBreak-Dash  -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            If ("CombinedCKL" -in $Output) {
                                Write-Log -Path $STIGLog -Message "Creating combined CKL file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                # Set combined checklist filename
                                If ($SelectVuln) {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "Partial_$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).ckl")
                                }
                                Else {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).ckl")
                                }
                                Format-CKL -SchemaPath $Checklist_xsd -ScanObject $ScanObjects -OutputPath $SaveFile -Marking $Marking -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent
                            }
                            If ("CombinedCKLB" -in $Output) {
                                Write-Log -Path $STIGLog -Message "Creating combined CKLB file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                # Set combined checklist filename
                                If ($SelectVuln) {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "Partial_$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).cklb")
                                }
                                Else {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).cklb")
                                }
                                Format-CKLB -SchemaPath $Checklist_json -ScanObject $ScanObjects -OutputPath $SaveFile -Marking $Marking -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent
                            }
                            If (($Output -split ",").Trim() -match "(^CombinedCSV$)") {
                                Write-Log -Path $STIGLog -Message "Creating combined CSV file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                # Set combined checklist filename
                                If ($SelectVuln) {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "Partial_$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).csv")
                                }
                                Else {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).csv")
                                }
                                Format-Object -ScanObject $ScanObjects -OutputPayload $OutputPayload | Export-CSV -NoTypeInformation -Path $SaveFile
                            }
                        }

                        If ($FailedCheck -eq $true) {
                            Write-Log -Path $STIGLog -Message "Please report issues to https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/issues" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }

                        # Send results to STIG Manager
                        If (($Output -split ",").Trim() -match "(^STIGManager$)") {
                            Write-Log -Path $STIGLog -Message "-" -TemplateMessage  LineBreak-Dash  -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Try {
                                if ($SMPassphrase){
                                    $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -SMPassphrase $SMPassphrase -ScanObject $ScanObjects -ScriptRoot $ES_Path -WorkingDir $WorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -Logpath $STIGLog
                                }
                                else{
                                    $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -ScanObject $ScanObjects -ScriptRoot $ES_Path -WorkingDir $WorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -Logpath $STIGLog
                                }

                                Import-Asset @SMImport_Params

                                # Copy Evaluate-STIG_STIGManager.log to results path
                                Copy-Item $(Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG_STIGManager.log") -Destination $ResultsPath -Force -ErrorAction Stop
                            }
                            Catch {
                                Write-Log -Path $STIGLog -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                        }

                        # Send results to Splunk
                        If (($Output -split ",").Trim() -match "(^Splunk$)") {
                            Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Write-Progress -Id $ProgressId -Activity $ProgressActivity -Status "Importing to Splunk" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                            $CurrentMainStep++
                            Try {
                                $Splunk_Params = Get-SplunkParameters -SplunkHECName $SplunkHECName -OutputPayload $OutputPayload -ScanObject $ScanObjects -ScriptRoot $PsScriptRoot -WorkingDir $WorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -Logpath $STIGLog

                                Import-Event @Splunk_Params
                            }
                            Catch {
                                Write-Log -Path $STIGLog -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                        }

                        Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        # Get RiskScore
                        Write-Log -Path $STIGLog -Message "Calculating risk score..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        $RiskScoreObject = Get-RiskScore -ES_Path $ES_Path -ApplicableSTIGsCount $ApplicableSTIGsCount -ScanObjects $ScanObjects
                        $ScoreDataObject = [ordered]@{}
                        ForEach ($Key in $RiskScoreObject.Keys) {
                            Switch ($Key) {
                                "CountRetrievalSuccess" {
                                    If ($RiskScoreObject.$Key -ne 1) {
                                        Write-Log -Path $STIGLog -Message "Failed to get full CAT counts for grading.  Scoring will be inaccurate." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                    }
                                }
                                "WeightedAvg" {
                                    Write-Log -Path $STIGLog -Message "$($Key): $($RiskScoreObject.$Key)%" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                }
                                DEFAULT {
                                    Write-Log -Path $STIGLog -Message "$($Key): $($RiskScoreObject.$Key)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                }
                            }
                            $ScoreDataObject.Add($Key, $RiskScoreObject.$Key)
                        }
                        Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        # Determine FullScan
                        $FullScan = $true
                        If ($SelectVuln -or $ExcludeVuln) {
                            # SelectVuln|ExcludeVuln automatically disqualifies as a full scan
                            $FullScan = $false
                        }
                        ForEach ($STIG in $ApplicableSTIGs.ShortName) {
                            If (-Not($ProcessedSTIGs.ShortName -match $STIG)) {
                                # Applicable STIG was not processed.  Not a full scan
                                $FullScan = $false
                            }
                        }

                        # Build ScanSummary object and add to AssetData
                        $ScanSummaryObject = [ordered]@{
                            ApplicableSTIGs = $ApplicableSTIGsCount | Sort-Object ShortName
                            ProcessedSTIGs  = $ProcessedSTIGs | Sort-Object Shortname
                            FullScan        = $FullScan
                            Score           = $ScoreDataObject
                        }
                        $AssetData.Add("ScanSummary", $ScanSummaryObject)

                        If (($Output -split ",").Trim() -match "(^Summary$)") {
                            # Collect AssetData from $ScanObjects
                            If (($ScanObjects.AssetData | Group-Object).Count -gt 1) {
                                $AssetData = $ScanObjects.AssetData[0]
                            }
                            Else {
                                $AssetData = $ScanObjects.AssetData
                            }

                            # Create summary report
                            Write-Log -Path $STIGLog -Message "Generating summary report" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            If ($Marking) {
                                Write-SummaryReport -AssetData $AssetData -RiskScoreObject $RiskScoreObject -ScanResult $ScanObjects -OutputPath $tmpResultsPath -ProcessedUser "NA" -Detail -Platform "Cisco" -ScanStartDate $ScanStartDate -ScanType $ScanType -Marking $Marking
                            }
                            Else {
                                Write-SummaryReport -AssetData $AssetData -RiskScoreObject $RiskScoreObject -ScanResult $ScanObjects -OutputPath $tmpResultsPath -ProcessedUser "NA" -Detail -Platform "Cisco" -ScanStartDate $ScanStartDate -ScanType $ScanType
                            }

                            # Create Summary HTML
                            $SummaryFile = Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.xml
                            [xml]$TempSR = New-Object xml

                            $null = $TempSR.AppendChild($TempSR.CreateElement('Summaries'))
                            $summary = New-Object xml
                            $Summary.Load($SummaryFile)
                            $ImportedSummary = $TempSR.ImportNode($Summary.DocumentElement, $true)
                            $null = $TempSR.DocumentElement.AppendChild($ImportedSummary)

                            $TempSR.Summaries.Summary.Results.Result | ForEach-Object {
                                #Build STIG name
                                $STIGName = [String]"$($_.STIG -replace '_', ' ') V$($_.Version)R$($_.Release)"
                                If ($_.Site) {
                                    $STIGName = $STIGName + " ($($_.Site))"
                                }
                                If ($_.Instance) {
                                    $STIGName = $STIGName + " ($($_.Instance))"
                                }
                                $_.SetAttribute("STIG", $STIGName)
                                $_.SetAttribute("StartTime", [String]($_.StartTime -replace "\.\d+", ""))
                                $CurrentScoreNode = $_.AppendChild($TempSR.CreateElement('CurrentScore'))
                                $CurrentScore = ([int]$_.CAT_I.NotAFinding + [int]$_.CAT_II.NotAFinding + [int]$_.CAT_III.NotAFinding + [int]$_.CAT_I.Not_Applicable + [int]$_.CAT_II.Not_Applicable + [int]$_.CAT_III.Not_Applicable) / ([int]$_.CAT_I.Total + [int]$_.CAT_II.Total + [int]$_.CAT_III.Total)
                                $CurrentScoreNode.SetAttribute("Score", $CurrentScore)
                            }
                            $TempSR.Save($(Join-Path -Path $WorkingDir -ChildPath TempSR.xml))

                            $SummaryReportXLST = New-Object System.XML.Xsl.XslCompiledTransform
                            $SummaryReportXLST.Load($(Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath SummaryReport.xslt))
                            $SummaryReportXLST.Transform($(Join-Path -Path $WorkingDir -ChildPath TempSR.xml), $(Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.html))

                            if ($Marking) {
                                #Add Marking Header and Footer
                                $SRHTML = $(Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.html)
                                (Get-Content $SRHTML) -replace "<body>", "<body>`n    <header align=`"center`">$Marking</header>" | Set-Content $SRHTML

                                Add-Content $(Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.html) "<footer align=`"center`">$Marking</footer>"
                            }
                        }

                        # Manage previous results and move results to ResultsPath
                        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
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
                                Initialize-PreviousProcessing -ResultsPath $ResultsPath -PreviousToKeep $PreviousToKeep @PreviousArgs -LogPath $STIGLog -LogComponent $LogComponent -OSPlatform $OSPlatform
                            }
                            Else {
                                Initialize-PreviousProcessing -ResultsPath $ResultsPath -PreviousToKeep $PreviousToKeep -LogPath $STIGLog -LogComponent $LogComponent -OSPlatform $OSPlatform
                            }

                            # Move results to ResultsPath
                            Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Write-Log -Path $STIGLog -Message "Copying output files to $ResultsPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            if (-not(Test-Path $ResultsPath)) {
                                # Create $ResultsPath
                                $null = New-Item -Path $ResultsPath -ItemType Directory
                            }
                            Get-ChildItem $tmpResultsPath -Recurse | ForEach-Object {
                                If ($_.PSIsContainer) {
                                    If (-Not(Test-Path $(Join-Path $ResultsPath -ChildPath $_.Name))) {
                                        $null = New-Item -Path $(Join-Path $ResultsPath -ChildPath $_.Name) -ItemType Directory
                                    }
                                }
                                Else {
                                    Copy-Item -Path $_.FullName -Destination $(Join-Path -Path $ResultsPath -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($tmpResultsPath), ""))
                                }
                            }
                        }

                        # Clean up
                        Invoke-ScanCleanup -WorkingDir $WorkingDir -Logpath $STIGLog -OSPlatform $OSPlatform -LogComponent $LogComponent

                        # Finalize log and get totals
                        $TimeToComplete = New-TimeSpan -Start $EvalStart -End (Get-Date)
                        $FormatedTime = "{0:c}" -f $TimeToComplete
                        Write-Log -Path $STIGLog -Message "Done!" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $STIGLog -Message "Total Time : $($FormatedTime)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$)") {
                            $TotalChecklists = (Get-ChildItem -Path "$ResultsPath\Checklist" | Where-Object {($_.Extension -In @(".ckl", ".cklb", ".csv") -or $_.Name -like "*.xccdf.xml")} | Measure-Object).Count
                            Write-Log -Path $STIGLog -Message "Total checklists in Results Directory : $($TotalChecklists)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        }
                        Write-Log -Path $STIGLog -Message "End Local Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        If ($Marking) {
                            Write-Log -Path $STIGLog -Message "                                                                                          $Marking                                                                                          " -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        }
                        Write-Log -Path $CiscoConfigLog -Message "Scan completed" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "Total Time : $($FormatedTime)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "End Config File Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Cisco -Value $(Get-Content $CiscoConfigLog)
                        Remove-Item $CiscoConfigLog

                        # Copy Evaluate-STIG.log to results path
                        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$|^Summary$|^OQE$)") {
                            Copy-Item $STIGLog -Destination $ResultsPath -Force -ErrorAction Stop
                        }

                        # Remove temporary files
                        $TempFiles = Get-Item -Path $WorkingDir\* -Exclude Evaluate-STIG.log, Bad_CKL
                        If ($TempFiles) {
                            ForEach ($Item in $TempFiles) {
                                Try {
                                    $null = Remove-Item -Path $Item.FullName -Recurse -ErrorAction Stop
                                }
                                Catch {
                                    Write-Log -Path $STIGLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                    Write-Log -Path $CiscoConfigLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                }
                            }
                        }

                        $ProgressPreference = "Continue"

                        # Build ScanResult
                        $ScanResult = @{}
                        $ScanResult.Add($MachineName, $ScanObjects)

                        Return $ScanResult
                    }
                }
                Catch {
                    $ErrorData = $_ | Get-ErrorInformation
                    If ($STIGLog -and (Test-Path $STIGLog)) {
                        ForEach ($Prop in ($ErrorData.PSObject.Properties).Name) {
                            Write-Log -Path $STIGLog -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            Write-Log -Path $CiscoConfigLog -Message "$($Prop) : $($ErrorData.$Prop)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }
                    }
                }
            }

            $Job = [powershell]::Create().AddScript($CiscoBlock).AddParameters($HashArguments)
            $Job.Streams.ClearStreams()
            $Job.RunspacePool = $RunspacePool

            # Create a temporary collection for each runspace
            $temp = "" | Select-Object Job, Runspace, Hostname
            $Temp.Hostname = $Item.DeviceInfo.Hostname
            $temp.Job = $Job
            $temp.Runspace = [PSCustomObject]@{
                Instance = $Job
                State    = $Job.BeginInvoke($RSObject, $RSObject)
            }
            $null = $runspaces.Add($temp)
        }

        if (($runspaces | Measure-Object).count -gt 0) {
            Get-RunspaceData -Runspaces $Runspaces -Wait -Usage Cisco
        }

        If (($Output -split ",").Trim() -match "(^Console$)") {
            # Add to results to be returned to console
            If ($RSObject) {
                ForEach ($Object in $RSObject.Keys) {
                    If ($Object -in $RunspaceResults.Keys) {
                        Write-Log -Path $STIGLog_Cisco -Message "ERROR: Results for '$Object' are already added.  Cannot create multiple results for assets with the same name." -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Host "ERROR: Results for '$Object' are already added.  Cannot create multiple results for assets with the same name." -ForegroundColor Red
                    }
                    Else {
                        Write-Log -Path $STIGLog_Cisco -Message "Adding results for '$Object'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        $RunspaceResults.Add($Object,$RSObject.$Object)
                    }
                }
            }
        }

        $RunspacePool.Close()
        $RunspacePool.Dispose()

        $TimeToComplete = New-TimeSpan -Start $ConfigEvalStart -End (Get-Date)
        $FormatedTime = "{0:c}" -f $TimeToComplete
        Write-Host "Done!" -ForegroundColor Green
        Write-Host "Total Time : $($FormatedTime)" -ForegroundColor Green
        Write-Host ""
        If (($Output -split ",").Trim() -match "(^CKL$|^CKLB$|^CSV$|^XCCDF$|^CombinedCKL$|^CombinedCKLB$|^CombinedCSV$)") {
            Write-Host "Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$($OutputPath)" -ForegroundColor Cyan
            Write-Host ""
        }

        Return $RunspaceResults
    }
    Catch {
        Throw $_
    }
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACcYO2w0Y2ka1a
# cMglY9wlokNfrasWW/j1PReJl7hTT6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDzSquVYqsjKUf4jJE6F6hG5G5DF4h+NzLNDkZcDS0TLjANBgkqhkiG9w0BAQEF
# AASCAQAJfDYTItEk2mmVrO1/ARyrMK9yKdmRP4BArbTm5uR0rBEITWQhVmC8Aict
# WvN9HHhiVXJl4IFxJOfeu/2apujxjXeEoi08s7O9KQlcM3N24vDW45xSWzhp1//W
# zi//gM7BgXtw9Mx9UPArO6e/UpPPxWZ+8h2UUQyZ8tm4kx6E74HyTB1bMTCFGy3Q
# 8wgqN+MlBbScnimv5O2OQNtDJLOhi5kdZ1JTbla+SvfP35mUNVXWNOzEpda9H3DQ
# x3gwECrobL6cDzD/Rktn+43z9Ye+HaATTtH9SvYyIKTHdLe1PcxJVDJsKfmg0gIe
# TbEyBC6HklrNAHzdCg4+9QcmCRWDoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTAwN1owLwYJKoZIhvcNAQkEMSIEIB5oXfrBpNm2jPW1dHB+vbirTvMQ
# 9YM+gP1/EpsZ/th7MA0GCSqGSIb3DQEBAQUABIICAJGcUWGB2WHdMzP3mVdzmLax
# cGWoGydXylFbcsquF1oKfa7xbNPiN/l1Ftyu14q+dRDRg/ei+7FpPNda1VADbAgg
# ztj5kcIXS4pJ9VaDZWgT3vAmPNmVHmmb9PwZpyrLbDbw37myeQjXkllanbbRWXno
# PsRHw5PDRBhNMDVTa+ehqhkNqqDFwqvZSUysadIR82HszFe8KnDkGoiBGfSaCpes
# Lt/CyKtux2mEPHbkKhlVr5Xq+Vm010AZX1Lg29iVavi+qCXdbVpnbx9IusfMUStr
# 3LFvcrjqZl75VVdtiddQbesQ9+KKEBz3kJNf9bRVwp0iTLf46WMnyrPQYpbxQyoh
# x3VVq1yGHjRJkIy3/B+3ZSJRg+pjZ31erzX3jj82VlTLAlQbBx6nmY0v+3TPjqfi
# X0PK/1fFRkVJwRcIRJQ3vjgpej0OgEt+rvrBBu4WLZyj6OZ+BG/brNGRZnJIDV0p
# 2W1H/RjbsnGJ45yjL8gJkygQyN+x5/ePBYNNIdstdPj9dRJXMMIpNlOxfLcNJbdu
# BTJ9J3hfKK/PFkKCAMDosttknMayu2ZHHYYVwmT+HKYp/EccdXHwfeZxBU+17EgC
# d+9QeX4PTz/Agjo8Kwr5obG25S3EiwieaGLC+guFj2gbfIHa1PQqonhao7tftBH2
# C7DQ9DtDBdYGvWshKGyZ
# SIG # End signature block
