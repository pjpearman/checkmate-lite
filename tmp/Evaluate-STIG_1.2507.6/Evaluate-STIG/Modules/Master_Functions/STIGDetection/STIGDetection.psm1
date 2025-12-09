##############################################
# STIG detection functions for Evaluate-STIG #
##############################################

Function Test-IsActiveDirectoryInstalled {
    # Active Directory detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("Domain", "Forest")]
        [string]$Level
    )

    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            Switch ($Level) {
                "Domain" {
                    If ((Get-DomainRoleStatus -ExpectedRole "Primary Domain Controller").BoolMatchExpected) {
                        $STIGRequired = $true
                    }
                }
                "Forest" {
                    If ((Get-DomainRoleStatus -ExpectedRole "Primary Domain Controller").BoolMatchExpected -and ((Get-ADDomain).DNSRoot -eq (Get-ADDomain).Forest)) {
                        $STIGRequired = $true
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsAdobeProReaderInstalled {
    # Adobe Acrobat Pro and Reader detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("Pro", "Reader")]
        [string]$Edition,

        [Parameter(Mandatory)]
        [ValidateSet("XI", "Classic", "Continuous")]
        [string]$Track
    )

    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            Switch ($Edition) {
                "Pro" {
                    Switch ($Track) {
                        "XI" {
                            If (Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Version -eq "XI"}) {
                                $STIGRequired = $true
                            }
                        }
                        "Classic" {
                            If (Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic" -and $_.Version -in @("2015", "2017", "2020")}) {
                                $STIGRequired = $true
                            }
                        }
                        "Continuous" {
                            If (Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Continuous" -and $_.Version -eq "DC"}) {
                                $STIGRequired = $true
                            }
                        }
                    }
                }
                "Reader" {
                    Switch ($Track) {
                        "Classic" {
                            If (Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic" -and $_.Version -in @("2015", "2017", "2020")}) {
                                $STIGRequired = $true
                            }
                        }
                        "Continuous" {
                            If (Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Continuous" -and $_.Version -eq "DC"}) {
                                $STIGRequired = $true
                            }
                        }
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsApacheInstalled {
    # Apache 2.4 detection
    Param (
        [Parameter(Mandatory)]
        [string] $OnOS
    )

    $STIGRequired = $false
    Try {
        If ($OnOS -eq "Unix") {
            If (-not ($IsLinux)) {
                Return $STIGRequired
            }

            $ExecutablePids = Get-ApacheUnixExecutablePids
            If (($ExecutablePids | Measure-Object).Count -gt 0) {
                $STIGRequired = $True
            }

            Return $STIGRequired
        }
        ElseIf ($OnOS -eq "Windows") {
            If ($IsLinux) {
                Return $STIGRequired
            }

            $Services = Get-CimInstance -ClassName win32_service
            If ($null -eq $Services) {
                Return $STIGRequired
            }

            $stoppedServices = @()

            Foreach ($service in $Services) {
                $PathName = $service.PathName
                $Path = ($PathName -split '"')[1]
                If ($null -eq $Path -or $Path -eq "") {
                    # If a path can't be parsed (because we know what it looks like) ignore.
                    Continue
                }

                If (-not (Test-Path -Path $Path -PathType Leaf)) {
                    # If a path is parsed and it doesn't lead to a file, ignore.
                    Continue
                }

                $Extension = (Get-ItemProperty -Path $Path -Name Extension).Extension
                If ($Extension -ne '.exe') {
                    # If the file is not an .exe, ignore.
                    Continue
                }

                $VersionInfo = (Get-Item -Path $Path).VersionInfo;
                $FileDescription = $VersionInfo.FileDescription;
                If ($FileDescription -notlike "*Apache*HTTP*Server") {
                    # If the file descriptor is not anything related to apache server, ignore.
                    Continue
                }

                $Param = '-v'
                $VersionOutput = (& "$($Path)" $Param)
                If ($VersionOutput | Select-String -Pattern '2.4' -Quiet) {
                    # If we get no version as output or if the version is incorrect, ignore.

                    if ($service.State -notmatch 'Running') {
                        # If service is not running, ignore.
                        $stoppedServices += $service.DisplayName
                    }
                    else {
                        $STIGRequired = $true
                    }
                }
            }
            if ($stoppedServices.Length -gt 0) {
                Write-Host "ERROR: Apache detected, but service(s) ($($stoppedServices -join ", ")) are not running. Please start service and scan again." -ForegroundColor Red -BackgroundColor Black
            }
        }
        Return $STIGRequired
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsTomcatInstalled {
    # Apache Tomcat Application Server detection
    $STIGRequired = $false
    Try {
        If ($IsLinux) {
            $IsTomcatRunning = 0

            If ((Get-Process).ProcessName -match "tomcat") {
                $IsTomcatRunning += 1
            }

            Get-Process | ForEach-Object {
                If (($_.Name -match "^java\d{0,}\b") -and ($_.CommandLine -match "catalina.base|catalina.home")) {
                    $IsTomcatRunning += 1
                }
            }

            If ($IsTomcatRunning -gt 0) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsArcGISInstalled {
    # ArcGIS Server 10.3 detection
    $STIGRequired = $false
    Try {
        If (($PsVersionTable.PSVersion).ToString() -match "5.*") {
            $IsArcGISInstalled = (Get-WmiObject Win32_Process -Filter "Name= 'ArcGISServer.exe'" | ForEach-Object {Write-Output "$($_.Name)"})
        }
        Else {
            $IsArcGISInstalled = ((Get-Process).ProcessName -Match "ArcGIS\s?Server" )
        }

        If ($IsArcGISInstalled) {
            $STIGRequired = $true
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsCisco {
    # Cisco detection
    Param (
        [Parameter(Mandatory)]
        [psobject]$DeviceInfo,

        [Parameter(Mandatory)]
        [ValidateSet("Router", "Switch")]
        [string]$DeviceType,

        [Parameter(Mandatory)]
        [ValidateSet("IOS-XE", "XE", "IOS")]
        [string]$CiscoOS
    )

    $STIGRequired = $false
    Try {
        $DualLayerTypes = @("Router,Switch", "Switch,Router")
        if ($DeviceInfo | Where-Object {($_.CiscoOS -eq $CiscoOS)}) {
            if ($DeviceInfo | Where-Object {($_.DeviceType -eq $DeviceType)}) {
                $STIGRequired = $true
            }
            elseif ($DualLayerTypes -contains $DeviceInfo.DeviceType) {
                $STIGRequired = $true
            }
            else {
                $STIGRequired = $false
            }
        }
        else {
            $STIGRequired = $false
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsChromeInstalled {
    # Google Chrome detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If ((Get-InstalledSoftware | Where-Object DisplayName -EQ "Google Chrome") -or (Get-ChildItem -Path $env:ProgramFiles\Google\Chrome -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "chrome.exe") -or (Get-ChildItem -Path ${env:ProgramFiles(x86)}\Google\Chrome -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "chrome.exe")) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsCitrixWorkspaceInstalled {
    # Citrix Workspace detection
    $STIGRequired = $false
    try {
        $include = 'Citrix\s+(Workspace|Receiver|HDX RealTime Media Engine|Self-Service Plug-in)'
        $exclude = 'Endpoint|XenMobile|Provisioning|Director|VDA|WEM|Licensing|Authentication|App Layering|Management'

        if (-not($IsLinux)) {
            $matchingSoftware = Get-InstalledSoftware | Where-Object {
                ($_.DisplayName -match $include) -and
                ($_.DisplayName -notmatch $exclude) -and
                ([Version]$_.DisplayVersion -le [Version]"19.12")
            }
            if ($matchingSoftware) {
                $STIGRequired = $true
            }
        }
    }
    catch {
        return $STIGRequired
    }

    return $STIGRequired
}

Function Test-IsIISInstalled {
    # Microsoft IIS detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("10.0", "8.5")]
        [string]$Version
    )

    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If (Get-WindowsFeatureState | Where-Object {$_.Name -in @("Web-WebServer", "IIS-WebServer") -and $_.Enabled -eq $true}) {
                Switch ($Version) {
                    "10.0" {
                        If (Test-Path "HKLM:\SOFTWARE\Microsoft\InetStp") {
                            $InetStp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp"
                            [Version]$IISVersion = "$(($InetStp).MajorVersion).$(($InetStp).MinorVersion)"
                            If ($IISVersion -ge [Version]"10.0") {
                                $STIGRequired = $true
                            }
                        }
                    }
                    "8.5" {
                        If (Test-Path "HKLM:\SOFTWARE\Microsoft\InetStp") {
                            $InetStp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp"
                            [Version]$IISVersion = "$(($InetStp).MajorVersion).$(($InetStp).MinorVersion)"
                            If ($IISVersion -ge [Version]"8.5" -and $IISVersion -lt [Version]"10.0") {
                                $STIGRequired = $true
                            }
                        }
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsIE11Installed {
    # Internet Explorer 11 detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            $Paths = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}")
            ForEach ($Path in $Paths) {
                If ([Version](Get-ChildItem "$Path\Internet Explorer\iexplore.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion -ge "11.0") {
                    $STIGRequired = $true
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsJBossInstalled {
    # JBoss EAP 6.3 detection
    $STIGRequired = $false
    Try {
        If ($IsLinux) {
            $IsJBossInstalled = (ps -ef | grep -i jboss.home.dir | grep -v grep)
            If ($IsJBossInstalled) {
                $STIGRequired = $true
            }
        }
        Else {
            If (($PsVersionTable.PSVersion).ToString() -match "5.*") {
                $IsJBossInstalled = (Get-WmiObject Win32_Process -Filter "Name= 'java.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
                        If ($_.CommandLine | Select-String -Pattern "jboss.home.dir") {
                            Write-Output "$($_.CommandLine)}"
                        }})
            }
            Else {
                $IsJBossInstalled = (Get-Process -Name "java" -ErrorAction SilentlyContinue | ForEach-Object {
                        If ($_.CommandLine | Select-String -Pattern "jboss.home.dir") {
                            Write-Output "$($_.Id) $($_.CommandLine)}"
                        }})
            }

            If ($IsJBossInstalled) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsMcAfeeVS88Installed {
    # McAfee VirusScan 8.8 Local Client detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            Switch ((Get-CimInstance Win32_OperatingSystem).OSArchitecture) {
                "64-bit" {
                    If ((Get-InstalledSoftware | Where-Object {($_.DisplayName -eq "McAfee VirusScan Enterprise") -and ([Version]$_.DisplayVersion -ge "8.8")}) -and ((Get-RegistryResult -Path "HKLM:\SOFTWARE\WOW6432Node\Network Associates\ePolicy Orchestrator\Agent" -ValueName "ePOServerList").Value -in @("(blank)", "(NotFound)"))) {
                        $STIGRequired = $true
                    }
                }
                "32-bit" {
                    If ((Get-InstalledSoftware | Where-Object {($_.DisplayName -eq "McAfee VirusScan Enterprise") -and ([Version]$_.DisplayVersion -ge "8.8")}) -and ((Get-RegistryResult -Path "HKLM:\SOFTWARE\Network Associates\ePolicy Orchestrator\Agent" -ValueName "ePOServerList").Value -in @("(blank)", "(NotFound)"))) {
                        $STIGRequired = $true
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsDotNET4Installed {
    # Microsoft .NET Framework 4 detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If (((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client" -ErrorAction SilentlyContinue).Install -eq 1) -or ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Install -eq 1)) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsMSOfficeInstalled {
    # Microsoft Office detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("2013", "2016", "O365")]
        [string]$Version,

        [ValidateSet("Common", "Access", "Excel", "Groove", "InfoPath", "Lync", "OneNote", "Outlook", "PowerPoint", "Project", "Publisher", "Skype", "Visio", "Word")]
        [array]$Component
    )

    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            Switch ($Version) {
                "2013" {
                    $MinVer = [Version]"15.0.4420.1017"
                    $NextVer = [Version]"16.0.4229.1003"
                    $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\15.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0")
                }
                "2016" {
                    $MinVer = [Version]"16.0.4229.1003"
                    $NextVer = [Version]"16.0.10336.20039"
                    $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0")
                }
                "O365" {
                    $MinVer = [Version]"16.0.10336.20039"
                    If ($Component) {
                        $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0")
                    }
                    Else {
                        $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration")
                        ForEach ($Path in $RegPaths) {
                            [Version]$VersionToReport = (Get-ItemProperty -Path "$Path" -Name "VersionToReport" -ErrorAction SilentlyContinue).VersionToReport
                            If ($VersionToReport -ge $MinVer) {
                                $STIGRequired = $true
                            }
                        }
                        If ($STIGRequired -eq $true) {
                            Return $STIGRequired
                        }
                        Else {
                            $Component = @("Access", "Excel", "Lync", "Outlook", "PowerPoint", "Publisher", "Word", "Visio", "Project")
                            $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0")
                        }
                    }
                }
            }
            ForEach ($Item in $Component) {
                Switch ($Item) {
                    "Common" {
                        $Executable = "CLVIEW.EXE"
                    }
                    "Access" {
                        $Executable = "MSACCESS.EXE"
                    }
                    "Excel" {
                        $Executable = "EXCEL.EXE"
                    }
                    "Groove" {
                        $Executable = "GROOVE.EXE"
                    }
                    "InfoPath" {
                        $Executable = "INFOPATH.EXE"
                    }
                    {$_ -in @("Lync", "Skype")} {
                        $Executable = "LYNC.EXE"
                        If ($Version -ne "O365") {
                            ForEach ($Path in $RegPaths) {
                                If (Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.PsChildName -eq "Lync" -and $_.Property -eq "InstallationDirectory")}) {
                                    $ExecutablePath = $(Join-Path -Path (Get-ItemProperty -Path $(Join-Path -Path $Path -ChildPath "Lync")).InstallationDirectory -ChildPath $Executable)
                                    [Version]$ProductVersion = (Get-Item $ExecutablePath).VersionInfo.ProductVersion
                                    If ($NextVer) {
                                        If ($ProductVersion -ge $MinVer -and $ProductVersion -lt $NextVer) {
                                            $STIGRequired = $true
                                        }
                                    }
                                }
                            }
                            Return $STIGRequired
                        }
                    }
                    "OneNote" {
                        $Executable = "ONENOTE.EXE"
                    }
                    "Outlook" {
                        $Executable = "OUTLOOK.EXE"
                    }
                    "PowerPoint" {
                        $Executable = "POWERPNT.EXE"
                    }
                    "Project" {
                        $Executable = "WINPROJ.EXE"
                    }
                    "Publisher" {
                        $Executable = "MSPUB.EXE"
                    }
                    "Visio" {
                        $Executable = "VISIO.EXE"
                    }
                    "Word" {
                        $Executable = "WINWORD.EXE"
                    }
                }

                ForEach ($Path in $RegPaths) {
                    If (Get-ChildItem -Path "$Path\$Item" -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.PsChildName -eq "InstallRoot" -and $_.Property -eq "Path")}) {
                        $ExecutablePath = $(Join-Path -Path (Get-ItemProperty -Path $(Join-Path -Path $Path -ChildPath $Item | Join-Path -ChildPath "InstallRoot")).Path -ChildPath $Executable)
                        If (Test-Path -Path $ExecutablePath) {
                            [Version]$ProductVersion = (Get-Item $ExecutablePath).VersionInfo.ProductVersion
                            If ($NextVer) {
                                If ($ProductVersion -ge $MinVer -and $ProductVersion -lt $NextVer) {
                                    $STIGRequired = $true
                                }
                            }
                            Else {
                                If ($ProductVersion -ge $MinVer) {
                                    $STIGRequired = $true
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }
    Return $STIGRequired
}

Function Test-IsMSOneDriveInstalled {
    # Microsoft OneDrive detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            if ((Test-Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe") -or (Test-Path "$(${env:ProgramFiles(x86)})\Microsoft OneDrive\OneDrive.exe") -or (Test-Path "$((Get-UsersToEval -ProvideSingleUser).LocalPath)\AppData\Local\Microsoft\OneDrive\OneDrive.exe")) {
                $STIGRequired = $true
            }

            if ($STIGRequired -eq $false) {
                $ProductKey = "Groove"
                $Executable = "GROOVE.EXE"
                $MinVer = [Version]"16.0.4229.1003"
                $NextVer = [Version]"16.0.10336.20039"
                $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0")
                ForEach ($Path in $RegPaths) {
                    If (Get-ChildItem -Path "$Path\$ProductKey" -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.PsChildName -eq "InstallRoot" -and $_.Property -eq "Path")}) {
                        $ExecutablePath = $(Join-Path -Path (Get-ItemProperty -Path $(Join-Path -Path $Path -ChildPath $ProductKey | Join-Path -ChildPath "InstallRoot")).Path -ChildPath $Executable)
                        If (Test-Path -Path $ExecutablePath) {
                            [Version]$ProductVersion = (Get-Item $ExecutablePath).VersionInfo.ProductVersion
                            If ($ProductVersion -ge $MinVer -and $ProductVersion -lt $NextVer) {
                                $STIGRequired = $true
                            }
                        }
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsSharePointDesignerInstalled {
    # Microsoft SharePoint Designer 2013 detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If (Get-InstalledSoftware | Where-Object DisplayName -Like "Microsoft SharePoint Designer 2013*") {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsSharePoint2013Installed {
    # Microsoft SharePoint Server 2013+ detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If (Get-InstalledSoftware | Where-Object {$_.DisplayName -Match "SharePoint Server" -and $_.DisplayVersion -ge [Version]"15.0"}) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsMSDefenderInstalled {
    # Microsoft Defender Antivirus detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If (Get-Service WinDefend -ErrorAction Stop) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsMSEdgeInstalled {
    # Microsoft Edge detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If ((Get-InstalledSoftware | Where-Object DisplayName -EQ "Microsoft Edge") -or (Get-ChildItem -Path $env:ProgramFiles\Microsoft\Edge -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "msedge.exe") -or (Get-ChildItem -Path ${env:ProgramFiles(x86)}\Microsoft\Edge -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "msedge.exe")) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsMSExchangeRoleInstalled {
    # Microsoft Exchange detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("2016", "2019")]
        [string]$Version,

        [Parameter(Mandatory)]
        [ValidateSet("Edge", "Mailbox")]
        [string]$Role
    )

    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            Switch ($Version) {
                "2016" {
                    $MinVer = [Version]"15.1"
                    $NextVer = [Version]"15.2"
                }
                "2019" {
                    $MinVer = [Version]"15.2"
                }
            }

            Switch ($Role) {
                "Edge" {
                    $RegPath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\V15\EdgeTransportRole"
                }
                "Mailbox" {
                    $RegPath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\V15\MailboxRole"
                }
            }

            [Version]$Version = (Get-ItemProperty $RegPath -ErrorAction SilentlyContinue).ConfiguredVersion
            If ($NextVer) {
                If ($Version -ge $MinVer -and $Version -lt $NextVer) {
                    $STIGRequired = $true
                }
            }
            Else {
                If ($Version -ge $MinVer) {
                    $STIGRequired = $true
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsMSSQLInstalled {
    # Microsoft SQL Server detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("2014", "2016", "2022")]
        [string]$Version
    )

    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server")
            ForEach ($Path in $RegPaths) {
                $Instances = (Get-ItemProperty $Path -ErrorAction SilentlyContinue).InstalledInstances
                ForEach ($Instance in $Instances) {
                    $InstanceName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue).$Instance
                    $InstanceInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceName\Setup" -ErrorAction SilentlyContinue
                    Switch ($Version) {
                        "2014" {
                            If (($InstanceInfo).Edition -notlike "*Express*" -and [Version]($InstanceInfo).Version -like "12.*") {
                                $STIGRequired = $true
                            }
                        }
                        "2016" {
                            If ([Version]($InstanceInfo).Version -like "1[345].*") {
                                $STIGRequired = $true
                            }
                        }
                        "2022" {
                            If ([Version]($InstanceInfo).Version -ge "16.0") {
                                $STIGRequired = $true
                            }
                        }
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsMongoDB3Installed {
    # MongoDB 3.x detection
    $STIGRequired = $false
    Try {
        $MongoProcess = Get-Process -Name 'mongo?'
        If ($null -ne $MongoProcess.Path) {
            $MongoDBVersionInfo = (& $MongoProcess.Path --version)
            $IsDB3 = $MongoDBVersionInfo | Select-String -Pattern "db\s*version\s*v3.*"
            $IsEnterprise = $MongoDBVersionInfo | Select-String -Pattern "modules:\s*enterprise"
            If ($null -ne $IsDB3 -and $null -ne $IsEnterprise) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsFirefoxInstalled {
    # Mozilla Firefox detection
    $STIGRequired = $false
    Try {
        If ($IsLinux) {
            $FirefoxCheck = Get-Firefox
            if ($FirefoxCheck | Where-Object {$_.Exists -eq $true}) {
                $STIGRequired = $true
            }
        }
        Else {
            if (Get-InstalledSoftware | Where-Object DisplayName -Match "^(Mozilla Firefox|Firefox Developer)") {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsJavaJRE8Installed {
    # Oracle Java JRE 8 detection
    $STIGRequired = $false
    Try {
        If ($IsLinux) {
            $Command = "java -version 2$([Char]62)$([Char]38)1 | Out-String"
            $JavaVer = Invoke-Expression $Command -ErrorAction SilentlyContinue
            If ($JavaVer -like "java*SE Runtime Environment*1.8.0*") {
                $STIGRequired = $true
            }
        }
        Else {
            If ((Get-DomainRoleStatus -ExpectedRole "Standalone Workstation", "Member Workstation").BoolMatchExpected -and (Get-InstalledSoftware | Where-Object DisplayName -Like "Java 8*")) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsPostgresInstalled {
    # PostgreSQL detection
    $STIGRequired = $false

    Try {
        if ($IsLinux) {
            $PostgresProcesses = (ps f -opid','ppid','cmd -C 'postgres,postmaster' --no-headers)
            if ($null -ne $PostgresProcesses) {
                if (grep Ubuntu /etc/os-release) {
                    $PGInstalls = (apt list 2>/dev/null | grep postgres | grep -v Crunchy | grep -v edb)
                }
                else {
                    $PGInstalls = (rpm -qa 2> /dev/null | grep postgres | grep -v Crunchy | grep -v edb)
                }
                if ($null -ne $PGInstalls) {
                    $STIGRequired = $true
                }
            }
        }
        else {
            If (Get-InstalledSoftware | Where-Object {$_.DisplayName -match "^PostgreSQL" -and $_.Publisher -match "PostgreSQL Global Development Group" -and [int]($_.DisplayVersion -Replace "[^\d\.]", "" -split "\.")[0] -ge 9}) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsRKE2Installed {
    # Rancher Government Solutions RKE2 detection
    $STIGRequired = $false
    Try {
        If ($IsLinux) {
            If ((Get-Process).ProcessName -match "rke2 agent|rke2 server") {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsTrellixInstalled {
    # Trellix ENS 10x Local detection
    $STIGRequired = $false
    Try {
        If ($IsLinux) {
            $IsTrellixInstalled = ((Get-TrellixOptDirs | Measure-Object).Count -ge 1)
            $IsENSInstalled = (((find /opt -type d -name ens) | Measure-Object).Count -ge 1)
            If ($IsTrellixInstalled -eq $true -and $IsENSInstalled -eq $true) {
                $Parameters = "-i"
                $Exec = (find /opt -type f -name cmdagent)
                $AgentModeString = (Invoke-Expression "$($Exec) $($Parameters)") | Select-String -Pattern AgentMode -Raw
                If ($null -ne $AgentModeString -and $AgentModeString -ne "") {
                    $AgentMode = ($AgentModeString.Split(":")[1]).Trim()
                    If ($AgentMode -eq "0") {
                        $STIGRequired = $true
                    }
                }
            }
        }
        Else {
            $RegistryPath = "HKLM:\SOFTWARE\McAfee\Endpoint\Common"
            $RegistryValueName = "ProductVersion"
            $IsVersionTenPlus = ((Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value -Like "10.*")
            If ($IsVersionTenPlus -eq $true) {
                $RegistryPath = "HKLM:\SOFTWARE\WOW6432Node\McAfee\Agent"
                $RegistryValueName = "AgentMode"
                $AgentMode = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value
                If ($null -eq $AgentMode -or $AgentMode -eq "(NotFound)") {
                    $STIGRequired = $true
                }
                Else {
                    $IsAgentModeZero = ($AgentMode -eq "0")
                    If ($IsAgentModeZero -eq $true) {
                        $STIGRequired = $true
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsVMwareHorizonInstalled {
    # VMware Horizon 7.13 detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("Agent", "Client", "ConnectionServer")]
        [string]$Component
    )

    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            Switch ($Component) {
                "Agent" {
                    $DisplayName = "VMware Horizon Agent"
                    $DisplayVersion = "7"
                }
                "Client" {
                    $DisplayName = "VMware Horizon Client"
                    $DisplayVersion = "5"
                }
                "ConnectionServer" {
                    $DisplayName = "VMware Horizon 7 Connection Server"
                    $DisplayVersion = "7"
                }
            }
            If (Get-InstalledSoftware | Where-Object {$_.DisplayName -eq $DisplayName -and $_.DisplayVersion -like "$($DisplayVersion).*"}) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsWinDNSServer {
    # Windows DNS Server detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If ((Get-Service DNS -ErrorAction SilentlyContinue) -and ((Test-IsRunningOS -Version WinServer2016) -or (Test-IsRunningOS -Version WinServer2019) -or (Test-IsRunningOS -Version WinServer2022) -or (Test-IsRunningOS -Version WinServer2025))) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Test-IsWinFirewallInstalled {
    # Windows Firewall detection
    $STIGRequired = $false
    Try {
        If (-Not($IsLinux)) {
            If ([Version](Get-CimInstance Win32_OperatingSystem).Version -ge [Version]"6.1") {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

function Test-IsContainerProcess {
    param (
        [Parameter(Mandatory = $True)]
        [int]$ProcessId
    )

    $IsContainer = $false

    if ($ProcessId -gt 1) {
        $ProcessCommandLine = Get-ProcessCommandLine -ProcessId $ProcessId
        $ContainerProcess = $ProcessCommandLine -match '\bcontainerd-shim\b|\bconmon\b'

        if ($null -ne $ContainerProcess -and $ContainerProcess -ne "") {
            $IsContainer = $true
        }
    }

    return $IsContainer
}

Function Test-IsRunningOS {
    # Operating system detection
    Param (
        [Parameter(Mandatory)]
        [ValidateSet("Oracle7", "Oracle8", "Oracle9", "RHEL7", "RHEL8", "RHEL9", "Ubuntu16", "Ubuntu18", "Ubuntu20", "Ubuntu22", "Ubuntu24", "AL2023", "Win7", "Win10", "Win11", "WinServer2008R2", "WinServer2012", "WinServer2016", "WinServer2019", "WinServer2022", "WinServer2025")]
        [string]$Version
    )

    # Expose addtional dynamic parameters
    DynamicParam {
        $ParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        If ($Version.Trim() -match "^WinServer") {
            # Expose -IsDC
            $Attributes = New-Object System.Management.Automation.ParameterAttribute
            $Attributes.Mandatory = $false
            $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $AttributeCollection.Add($Attributes)
            $IsDCParam = New-Object System.Management.Automation.RuntimeDefinedParameter("IsDC", [Switch], $AttributeCollection)
            $ParamDictionary.Add("IsDC", $IsDCParam)
        }

        Return $ParamDictionary
    }

    Process {
        $STIGRequired = $false
        Try {
            If ($IsLinux) {
                $OSRelease = Get-Content /etc/os-release -ErrorAction SilentlyContinue
                Switch ($Version) {
                    "Oracle7" {
                        If ($OSRelease -like '*NAME="Oracle Linux*' -and $OSRelease -like '*VERSION_ID="7.*') {
                            $STIGRequired = $true
                        }
                    }
                    "Oracle8" {
                        If ($OSRelease -like '*NAME="Oracle Linux*' -and $OSRelease -like '*VERSION_ID="8.*') {
                            $STIGRequired = $true
                        }
                    }
                    "Oracle9" {
                        If ($OSRelease -like '*NAME="Oracle Linux*' -and $OSRelease -like '*VERSION_ID="9.*') {
                            $STIGRequired = $true
                        }
                    }
                    "RHEL7" {
                        If ($OSRelease -like '*NAME="Red Hat Enterprise Linux*' -and $OSRelease -like '*VERSION_ID="7.*') {
                            $STIGRequired = $true
                        }
                        ElseIf ($OSRelease -like '*NAME="CentOS Linux*' -and $OSRelease -like '*VERSION_ID="7*') {
                            $STIGRequired = $true
                        }
                        ElseIf ($OSRelease -like '*NAME="RedHawk Linux*' -and $OSRelease -like '*VERSION_ID="7.*') {
                            If ($(Get-Content /etc/redhat-release) -like "Red Hat Enterprise Linux*") {
                                $STIGRequired = $true
                            }
                        }
                    }
                    "RHEL8" {
                        If ($OSRelease -like '*NAME="Red Hat Enterprise Linux*' -and $OSRelease -like '*VERSION_ID="8.*') {
                            $STIGRequired = $true
                        }
                        ElseIf ($OSRelease -like '*NAME="RedHawk Linux*' -and $OSRelease -like '*VERSION_ID="8.*') {
                            If ($(Get-Content /etc/redhat-release) -like "Red Hat Enterprise Linux*") {
                                $STIGRequired = $true
                            }
                        }
                    }
                    "RHEL9" {
                        If ($OSRelease -like '*NAME="Red Hat Enterprise Linux*' -and $OSRelease -like '*VERSION_ID="9.*') {
                            $STIGRequired = $true
                        }
                        ElseIf ($OSRelease -like '*NAME="RedHawk Linux*' -and $OSRelease -like '*VERSION_ID="9.*') {
                            If ($(Get-Content /etc/redhat-release) -like "Red Hat Enterprise Linux*") {
                                $STIGRequired = $true
                            }
                        }
                    }
                    "Ubuntu16" {
                        If ($OSRelease -like '*NAME="Ubuntu*' -and $OSRelease -like '*VERSION_ID="16.*') {
                            $STIGRequired = $true
                        }
                    }
                    "Ubuntu18" {
                        If ($OSRelease -like '*NAME="Ubuntu*' -and $OSRelease -like '*VERSION_ID="18.*') {
                            $STIGRequired = $true
                        }
                    }
                    "Ubuntu20" {
                        If ($OSRelease -like '*NAME="Ubuntu*' -and $OSRelease -like '*VERSION_ID="20.*') {
                            $STIGRequired = $true
                        }
                    }
                    "Ubuntu22" {
                        If ($OSRelease -like '*NAME="Ubuntu*' -and $OSRelease -like '*VERSION_ID="22.*') {
                            $STIGRequired = $true
                        }
                    }
                    "Ubuntu24" {
                        If ($OSRelease -like '*NAME="Ubuntu*' -and $OSRelease -like '*VERSION_ID="24.*') {
                            $STIGRequired = $true
                        }
                    }
                    "AL2023" {
                        If ($OSRelease -like '*NAME="Amazon Linux*' -and $OSRelease -like '*VERSION_ID="2023*') {
                            $STIGRequired = $true
                        }
                    }
                }
            }
            Else {
                If ($PsBoundParameters.IsDC) {
                    $IsDC = "{0}" -f $PsBoundParameters.IsDC
                }
                $Caption = (Get-CimInstance Win32_OperatingSystem).Caption
                Switch ($Version) {
                    "Win7" {
                        If ($Caption -Like "*Windows 7*") {
                            $STIGRequired = $true
                        }
                    }
                    "Win10" {
                        If ($Caption -Like "*Windows 10*") {
                            $STIGRequired = $true
                        }
                    }
                    "Win11" {
                        If ($Caption -Like "*Windows 11*") {
                            $STIGRequired = $true
                        }
                    }
                    "WinServer2008R2" {
                        If ($IsDC) {
                            If ($Caption -Like "*Windows*Server 2008 R2*" -and (Get-DomainRoleStatus -ExpectedRole "Backup Domain Controller", "Primary Domain Controller").BoolMatchExpected) {
                                $STIGRequired = $true
                            }
                        }
                        ElseIf ($Caption -Like "*Windows*Server 2008 R2*") {
                            $STIGRequired = $true
                        }
                    }
                    "WinServer2012" {
                        If ($IsDC) {
                            If ($Caption -Like "*Windows*Server 2012*" -and (Get-DomainRoleStatus -ExpectedRole "Backup Domain Controller", "Primary Domain Controller").BoolMatchExpected) {
                                $STIGRequired = $true
                            }
                        }
                        ElseIf ($Caption -Like "*Windows*Server 2012*") {
                            $STIGRequired = $true
                        }
                    }
                    "WinServer2016" {
                        If ($IsDC) {
                            If ($Caption -Like "*Windows*Server 2016*" -and (Get-DomainRoleStatus -ExpectedRole "Backup Domain Controller", "Primary Domain Controller").BoolMatchExpected) {
                                $STIGRequired = $true
                            }
                        }
                        ElseIf ($Caption -Like "*Windows*Server 2016*") {
                            $STIGRequired = $true
                        }
                    }
                    "WinServer2019" {
                        If ($IsDC) {
                            If ($Caption -Like "*Windows*Server 2019*" -and (Get-DomainRoleStatus -ExpectedRole "Backup Domain Controller", "Primary Domain Controller").BoolMatchExpected) {
                                $STIGRequired = $true
                            }
                        }
                        ElseIf ($Caption -Like "*Windows*Server 2019*") {
                            $STIGRequired = $true
                        }
                    }
                    "WinServer2022" {
                        If ($IsDC) {
                            If ($Caption -Like "*Windows*Server 2022*" -and (Get-DomainRoleStatus -ExpectedRole "Backup Domain Controller", "Primary Domain Controller").BoolMatchExpected) {
                                $STIGRequired = $true
                            }
                        }
                        ElseIf ($Caption -Like "*Windows*Server 2022*") {
                            $STIGRequired = $true
                        }
                    }
                    "WinServer2025" {
                        If ($IsDC) {
                            If ($Caption -Like "*Windows*Server 2025*" -and (Get-DomainRoleStatus -ExpectedRole "Backup Domain Controller", "Primary Domain Controller").BoolMatchExpected) {
                                $STIGRequired = $true
                            }
                        }
                        ElseIf ($Caption -Like "*Windows*Server 2025*") {
                            $STIGRequired = $true
                        }
                    }
                }
            }
        }
        Catch {
            Return $STIGRequired
        }

        Return $STIGRequired
    }
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZ2s8/inPnRzka
# Io7Oz1sG81pfTxeAp2RBa2yS6md7YaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCDWFfoKrD8Ql8i4Xk42nFWK/pBQsoG1vNKWabPdYtXhJTANBgkqhkiG9w0BAQEF
# AASCAQAmaEJhqlIGmmpC+W+mlAfulYWRgsfQv7nmzwZ+wiMnYBfgyTnD13Vscpru
# VAXH1VKxKrUJ08+II2KJmPg5lLZJo3aHRJP3gQFdmAjXcK2oXIHPSRghi+Fq66mJ
# 8tDt3hwgapK1mmKmjJe3eFhhVTcEtxnwM047OTxx802gYApft1R+iUjly5FjCMeL
# jVaRAwxpznsXzYmGpBmjS9xnvlbgvMdHJ29Uk5nzN5SJrlBFrQAGnWZXwPnUmhqz
# 9DfGDp0Uw3SWrG5lVD3S+FzIHwaYH6oZUEA2WnhtDIZ+UgxzlC+CyonE5m4aKv5l
# zgJ8M1akJkzVNWScJaS1c3dCuAQ5oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTYyOFowLwYJKoZIhvcNAQkEMSIEIHGdlKZRqRCYlGnxhyhC1UPR4cbA
# uVI+1qP0hSoqQDBXMA0GCSqGSIb3DQEBAQUABIICAKcKwzjFFQQuvKlrp2i1hvDw
# jgxaSkwotKqELxn7KYBXVWPc/Mvqfnxw94lAa4BY1G6tI3lqi6ul/H2pP1QNFgRL
# I6+fKWck/Njg3mmrOJavcvNa59M8EVjMP1enu2GTToKH9vqL9UoKri4AF9QI9juY
# mLhuCx0/burgLUAt/ZCbauQ/cIlUYL9yfUiuKsZbl+CflQ7P4zDjChkiMg3Lf9UG
# JcWBXW245+YnPbGnpN3adqgVyBItmg0M0S2WwaToNzUjnX5G7D6uZEERLORVMqBU
# bwd4T3ztKAqJzGwBeZ92t/2agFHPUBfZ2/rX7b+MQoQqojBA5/9FI1s/xJnpuhsp
# 64ibDrmp4HL1lkaDjBvdwg+hw80HwZKXOHs/qUynxtsW8UjFGFdPzNQNep/jqSYu
# Cam1PWEqlE7ZMi+zBZFaSQMEmbFKycwzadPI/8XLLTOf61jfO2OM0Bh/V6/ix7+2
# qgXCNzFOlPfNedBI26eMmz5geHYlWIhwBHI2en3PpCvvxYJqvCVc58gj8g1DrfNA
# n4OR0ef7dXe4q6KHeW8YZ8JpXavCdpOite46qO0jRnJjmHIVAk0RRoDYkyhf1y1k
# AqDYxocwWJTv4nKfigcxtF/C/bABtbEbtVUy+QtywEzMaHJluPUtZkXzE9EXDg7e
# yqJwfylhPl4qnr03/UNG
# SIG # End signature block
