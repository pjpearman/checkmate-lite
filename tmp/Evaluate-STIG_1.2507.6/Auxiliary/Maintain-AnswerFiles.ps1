<#
    .Synopsis
    Performs maintenance on Evaluate-STIG answer files.
    .DESCRIPTION
    Performs simple maintenance on Evaluate-STIG Answer Files.  Updates Vuln IDs to new STIGs that have been converted to DISA's new conten management system.  It also identifies and optionally removes answers for Vuln IDs that have been removed from the STIG.  Finally, it will convert answer files from previous format to new format compatible with 1.2507.2 and greater.

    Unless -NoBackup is specified, a backup of an answer file that is determined to need updating is automatically created with a .bak extension and stored in the same path as the answer file.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG'

    This will analyze all answer files found in ESPath\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be noted but not changed.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG' -RemoveMissingVulnIDs

    This will analyze all answer files found in ESPath\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be omitted from the updated answer file.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG' -RemoveMissingVulnIDs -NoBackup

    This will analyze all answer files found in ESPath\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be omitted from the updated answer file.  Disables backup of answer files that are updated.
    .EXAMPLE
    PS C:\> .\Maintain-AnswerFiles.ps1 -ESPath 'C:\Evaluate-STIG' -AFPath '\\Server1\AnswerFiles' -RemoveMissingVulnIDs -NoBackup

    This will analyze all answer files found in \\Server1\AnswerFiles and update Vuln IDs to new STIG Vuln IDs if required.  Answers for Vuln IDs no longer in the STIG will be omitted from the updated answer file.  Disables backup of answer files that are updated.
    .INPUTS
    -ESPath
    Path to the Evaluate-STIG directory.  This is a required parameter.

    -AFPath
    Path that contains XML answer files.  If not specified, defaults to <ESPath>\AnswerFiles.

    -NoBackup
    Disables the creation of a backup file (.bak) for answer files that are updated.

    -RemoveMissingVulnIDs
    When specified, will automatically omit any vuln IDs in the current Answer File that is not in the STIG from the new Answer File.  Useful for cleaning up answers for STIG items that have been removed.  This parameter is optional.

    -UpdateChangedRuleIDs
    If Rule IDs are used in the answer file, will automatically update the <Vuln ID> attribute with the new Rule ID.

    -HostnameRegEx
    Regular expression to match hostname pattern in legacy <AnswerKey Name>.  Example: ^PC\d{1,4}$

    -StatusFormat
    Format to use for ExpectedStatus, ValidTrueStatus, and ValidFalseStatus.  Must be "EvalSTIG", "CKL", "CKLB", or "XCCDF".  Default is "EvalSTIG"

    -ForceUpdate
    Forces the answer file(s) to be updated even if no required updating is detected.

    .LINK
    Evaluate-STIG
    https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig
#>
[CmdletBinding(DefaultParameterSetName = 'None')]
param (
    [Parameter(Mandatory = $true)]
    [String]$ESPath,

    [Parameter(Mandatory = $false)]
    [String]$AFPath,

    [Parameter(Mandatory = $false)]
    [Switch]$NoBackup,

    [Parameter(Mandatory = $false)]
    [Switch]$RemoveMissingVulnIDs,

    [Parameter(Mandatory = $false)]
    [Switch]$UpdateChangedRuleIDs,

    [Parameter(Mandatory = $false)]
    [String]$HostnameRegEx,

    [Parameter(Mandatory = $false)]
    [ValidateSet('EvalSTIG', 'CKL', 'CKLB', 'XCCDF')]
    [String]$StatusFormat = "EvalSTIG",

    [Parameter(Mandatory = $false)]
    [Switch]$ForceUpdate
)

# <==== Begin Custom Functions ====>
function Convert-AnswerFileToObject {
    param (
        [Parameter(Mandatory = $true)]
        [String]$XmlFile,

        [Parameter(Mandatory = $false)]
        [Switch]$IsLegacy,

        [Parameter(Mandatory = $true)]
        [String]$StatusFormat
    )

    [XML]$XMLContent = (Get-Content $XmlFile -Raw)

    $Result = [ordered]@{ }
    foreach ($Node in $XMLContent.SelectNodes("//STIGComments")) {
        # STIGComment Name attribute
        $Result.Add($Node.Name, [ordered]@{ '_Comment' = ($Node.'#Comment' | Out-String).Trim() })
        foreach ($Vuln in $Node.Vuln) {
            $VulnObj = [ordered]@{
                # Comment if it exists
                _Comment = ($Vuln.'#comment' | Out-String).Trim()
            }
            foreach ($KeyName in ($Node.Vuln | Where-Object { $_ -eq $Vuln }).AnswerKey) {
                $KeyNameObj = [ordered]@{
                    # Comment if it exists
                    _Comment = ($KeyName.'#comment' | Out-String).Trim()
                }
                if ($IsLegacy) {
                    # Collect data from legacy answer file format
                    $KeyNameObj.Add("ExpectedStatus", (Convert-Status -InputObject $KeyName.ExpectedStatus -Output $script:StatusFormat))

                    # Format ValidationCode
                    $KeyNameObj.Add("ValidationCode", $KeyName.ValidationCode.Trim())

                    # Format ValidTrueStatus
                    if ($KeyName.ValidTrueStatus -notin @($null, "")) {
                        $KeyNameObj.Add("ValidTrueStatus", (Convert-Status -InputObject $KeyName.ValidTrueStatus -Output $script:StatusFormat))
                    }
                    else {
                        $KeyNameObj.Add("ValidTrueStatus", "")
                    }

                    # Format ValidFalseStatus
                    $KeyNameObj.Add("ValidTrueComment", $KeyName.ValidTrueComment)
                    if ($KeyName.ValidFalseStatus -notin @($null, "")) {
                        $KeyNameObj.Add("ValidFalseStatus", (Convert-Status -InputObject $KeyName.ValidFalseStatus -Output $script:StatusFormat))
                    }
                    else {
                        $KeyNameObj.Add("ValidFalseStatus", "")
                    }
                    $KeyNameObj.Add("ValidFalseComment", $KeyName.ValidFalseComment)
                }
                else {
                    foreach ($Index in $KeyName.Answer.Index) {
                        foreach ($Item in ($KeyName.Answer | Where-Object Index -EQ $Index)) {
                            # Format ValidTrueStatus element
                            if ($Item.ValidTrueStatus -notin @($null, "")) {
                                $ObjValidTrueStatus = Convert-Status -InputObject $Item.ValidTrueStatus -Output $script:StatusFormat
                            }
                            else {
                                $ObjValidTrueStatus = ""
                            }

                            # Format ValidFalseStatus element
                            if ($Item.ValidFalseStatus -notin @($null, "")) {
                                $ObjValidFalseStatus = Convert-Status -InputObject $Item.ValidFalseStatus -Output $script:StatusFormat
                            }
                            else {
                                $ObjValidFalseStatus = ""
                            }

                            $IndexObj = [ordered]@{
                                _Comment          = ($Item.'#comment' | Out-String).Trim() # Comment if it exists
                                ExpectedStatus    = (Convert-Status -InputObject $Item.ExpectedStatus -Output $script:StatusFormat) # ExpectedStatus attribute
                                Hostname          = (($Item.Hostname -split ",").Trim() -join ",") # Hostname attribute
                                Instance          = (($Item.Instance -split ",").Trim() -join ",") # Instance attribute
                                Database          = (($Item.Database -split ",").Trim() -join ",") # Database attribute
                                Site              = (($Item.Site -split ",").Trim() -join ",") # Site attribute
                                ResultHash        = (($Item.ResultHash -split ",").Trim() -join ",")
                                ValidationCode    = $Item.ValidationCode.Trim() # ValidationCode element
                                ValidTrueStatus   = $ObjValidTrueStatus # Formatted ValidTrueStatus element
                                ValidTrueComment  = $Item.ValidTrueComment # ValidTrueComment element
                                ValidFalseStatus  = $ObjValidFalseStatus # Formatted ValidFalseStatus element
                                ValidFalseComment = $Item.ValidFalseComment # ValidFalseComment element
                            }
                        }
                        $KeyNameObj.Add($Index, $IndexObj) # Create Index subobject for Answer element
                    }
                }
                $VulnObj.Add($KeyName.Name, $KeyNameObj) # Create Name subobject for AnsweKey element
            }
            $Result.($Node.Name).Add($Vuln.ID, $VulnObj) # Create ID subobject for Vuln element
        }
    }

    return $Result
}

function Convert-LegacyAFObject {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$LegacyObject,

        [Parameter(Mandatory = $false)]
        [String]$HostnamePattern
    )

    $LegacyList = [ordered]@{
        'Active Directory Domain'                       = 'ADDomain'
        'Active Directory Forest'                       = 'ADForest'
        'Adobe Acrobat Pro XI'                          = 'AdobeAcrobatProXI'
        'Adobe Acrobat Professional DC Classic'         = 'AdobeAcrobatProDCClassic'
        'Adobe Acrobat Professional DC Continuous'      = 'AdobeAcrobatProDCContinuous'
        'Adobe Reader DC Classic'                       = 'AdobeReaderDCClassic'
        'Adobe Reader DC Continuous'                    = 'AdobeReaderDCContinuous'
        'Apache 2.4 Server Unix'                        = 'Apache24SvrUnix'
        'Apache 2.4 Server Windows'                     = 'Apache24SvrWin'
        'Apache 2.4 Site Unix'                          = 'Apache24SiteUnix'
        'Apache 2.4 Site Windows'                       = 'Apache24SiteWin'
        'Apache Tomcat Application Server'              = 'ApacheTomcatAS'
        'ArcGIS Server 10.3'                            = 'ArcGIS'
        'Cisco IOS XE Router NDM'                       = 'CiscoXERtrNDM'
        'Cisco IOS XE Switch L2S'                       = 'CiscoXESwtchL2S'
        'Cisco IOS XE Switch NDM'                       = 'CiscoXESwtchNDM'
        'Citrix VAD 7.x Workspace App'                  = 'CitrixWorkspace'
        'Google Chrome'                                 = 'Chrome'
        'IIS 10.0 Server'                               = 'IIS10Server'
        'IIS 10.0 Site'                                 = 'IIS10Site'
        'IIS 8.5 Server'                                = 'IIS85Server'
        'IIS 8.5 Site'                                  = 'IIS85Site'
        'Internet Explorer 11'                          = 'IE11'
        'JBoss EAP 6.3'                                 = 'JBoss'
        'McAfee VirusScan 8.8 Local Client'             = 'McAfeeVS88'
        'Microsoft .NET Framework 4'                    = 'DotNET4'
        'Microsoft Access 2013'                         = 'MSAccess2013'
        'Microsoft Access 2016'                         = 'MSAccess2016'
        'Microsoft Defender Antivirus'                  = 'MSDefender'
        'Microsoft Edge'                                = 'MSEdge'
        'Microsoft Excel 2013'                          = 'MSExcel2013'
        'Microsoft Excel 2016'                          = 'MSExcel2016'
        'Microsoft Exchange 2016 Edge Transport Server' = 'MSExchange2016EdgeTP'
        'Microsoft Exchange 2016 Mailbox Server'        = 'MSExchange2016MB'
        'Microsoft Exchange 2019 Edge Server'           = 'MSExchange2019Edge'
        'Microsoft Exchange 2019 Mailbox Server'        = 'MSExchange2019MB'
        'Microsoft Groove 2013'                         = 'MSGroove2013'
        'Microsoft InfoPath 2013'                       = 'MSInfoPath2013'
        'Microsoft Lync 2013'                           = 'MSLync2013'
        'Microsoft Office 365'                          = 'MSOffice365'
        'Microsoft Office System 2013'                  = 'MSOfficeSystem2013'
        'Microsoft Office System 2016'                  = 'MSOfficeSystem2016'
        'Microsoft OneDrive'                            = 'MSOneDrive'
        'Microsoft OneNote 2013'                        = 'MSOneNote2013'
        'Microsoft OneNote 2016'                        = 'MSOneNote2016'
        'Microsoft Outlook 2013'                        = 'MSOutlook2013'
        'Microsoft Outlook 2016'                        = 'MSOutlook2016'
        'Microsoft PowerPoint 2013'                     = 'MSPowerPoint2013'
        'Microsoft PowerPoint 2016'                     = 'MSPowerPoint2016'
        'Microsoft Project 2013'                        = 'MSProject2013'
        'Microsoft Project 2016'                        = 'MSProject2016'
        'Microsoft Publisher 2013'                      = 'MSPublisher2013'
        'Microsoft Publisher 2016'                      = 'MSPublisher2016'
        'Microsoft SharePoint 2013'                     = 'SharePoint2013'
        'Microsoft SharePoint Designer 2013'            = 'MSSPDesigner2013'
        'Microsoft Skype for Business 2016'             = 'MSSkype2016'
        'Microsoft SQL Server 2014 Database'            = 'SQL2014DB'
        'Microsoft SQL Server 2014 Instance'            = 'SQL2014Instance'
        'Microsoft SQL Server 2016 Database'            = 'SQL2016DB'
        'Microsoft SQL Server 2016 Instance'            = 'SQL2016Instance'
        'Microsoft Visio 2013'                          = 'MSVisio2013'
        'Microsoft Visio 2016'                          = 'MSVisio2016'
        'Microsoft Word 2013'                           = 'MSWord2013'
        'Microsoft Word 2016'                           = 'MSWord2016'
        'MS SQL Server 2022 Database'                   = 'SQL2022DB'
        'MS SQL Server 2022 Instance'                   = 'SQL2022Instance'
        'MongoDB 3.x'                                   = 'MongoDB3'
        'Mozilla Firefox'                               = 'Firefox'
        'Oracle Java JRE 8 for Unix'                    = 'JavaJRE8Unix'
        'Oracle Java JRE 8 for Windows'                 = 'JavaJRE8Windows'
        'Oracle Linux 7'                                = 'Oracle7'
        'Oracle Linux 8'                                = 'Oracle8'
        'Oracle Linux 9'                                = 'Oracle9'
        'PostgreSQL 9.x'                                = 'PgSQL9x'
        'Rancher Government Solutions RKE2'             = 'RGSRKE2'
        'Red Hat Enterprise Linux 7'                    = 'RHEL7'
        'Red Hat Enterprise Linux 8'                    = 'RHEL8'
        'Red Hat Enterprise Linux 9'                    = 'RHEL9'
        'Trellix ENS 10x Local'                         = 'TrellixENS10xLocal'
        'Ubuntu 16.04'                                  = 'Ubuntu16'
        'Ubuntu 18.04'                                  = 'Ubuntu18'
        'Ubuntu 20.04'                                  = 'Ubuntu20'
        'Ubuntu 22.04'                                  = 'Ubuntu22'
        'Ubuntu 24.04'                                  = 'Ubuntu24'
        'VMware Horizon 7.13 Agent'                     = 'HorizonAgent'
        'VMware Horizon 7.13 Client'                    = 'HorizonClient'
        'VMware Horizon 7.13 Connection Server'         = 'HorizonConnectionServer'
        'Windows 10'                                    = 'Win10'
        'Windows 11'                                    = 'Win11'
        'Windows 7'                                     = 'Win7'
        'Windows Firewall'                              = 'WinFirewall'
        'Windows Server 2008 R2 MS'                     = 'WinServer2008R2MS'
        'Windows Server 2012 DC'                        = 'WinServer2012DC'
        'Windows Server 2012 MS'                        = 'WinServer2012MS'
        'Windows Server 2016'                           = 'WinServer2016'
        'Windows Server 2019'                           = 'WinServer2019'
        'Windows Server 2022'                           = 'WinServer2022'
        'Windows Server DNS'                            = 'WinServerDNS'
    }

    $Log = @("Converting legacy answer file")

    if (($LegacyObject.Keys | Select-Object -First 1) -in $LegacyList.Keys) {
        $STIGName = $LegacyList.$($LegacyObject.Keys | Select-Object -First 1)
        if (($LegacyObject.Keys | Select-Object -First 1) -ne $STIGName) {
            $Log += " Renaming STIGComments Name '$($LegacyObject.Keys | Select-Object -First 1)' to ShortName '$($STIGName)'."
        }
    }
    else {
        $STIGName = $LegacyObject.Keys | Select-Object -First 1
    }

    # Create ordered hashtable of answer file data
    $NewAFObject = [ordered]@{
        $STIGName = [ordered]@{
            _Comment = "Answer file migrated with Maintain-AnswerFiles.ps1 on $(Get-Date -Format MM/dd/yyyy)"
        }
    }

    $STIGKey = $LegacyObject.Keys | Select-Object -First 1
    foreach ($Vuln in ($LegacyObject.$($STIGkey).Keys | Where-Object { $_ -ne "_Comment" })) {
        $Log += " Migrating <Vuln ID> '$($Vuln)'"
        $VulnObj = [ordered]@{
            # Comment if it exists
            _Comment = ($LegacyObject.$($STIGkey).$($Vuln)._Comment | Out-String).Trim()
        }

        foreach ($AnswerKey in ($LegacyObject.$($STIGkey).$($Vuln).Keys | Where-Object { $_ -ne "_Comment" })) {
            $Log += "  Migrating <AnswerKey Name> '$($AnswerKey)'"
            $KeyNameObj = [ordered]@{
                # Comment if it exists
                _Comment = ($LegacyObject.$($STIGkey).$($Vuln).$($AnswerKey)._Comment | Out-String).Trim()
            }

            if ($HostnamePattern) {
                # Check for $HostnamePattern matches
                $Hostname = ($AnswerKey -split ",").Trim() | Where-Object { $_ -match $HostnamePattern }
                if ($Hostname) {
                    $Hostname = $Hostname -join ","
                    $NewKeyName = "Migrated_$(Get-Random)"
                    $Log += "   Hostname detected in legacy <AnswerKey Name>"
                    $Log += "   Moving key Name to Hostname and renaming to '$NewKeyName'.  Please update with desired key Name before use."
                }
                else {
                    $Hostname = ""
                    $NewKeyName = $AnswerKey
                }
            }
            else {
                $Hostname = ""
                $NewKeyName = $AnswerKey
            }

            $IndexObj = [ordered]@{
                _Comment          = "Index created by Maintain-AnswerFiles.ps1 during legacy migration on $(Get-Date -Format MM/dd/yyyy)"
                ExpectedStatus    = $LegacyObject.$($STIGkey).$($Vuln).$($AnswerKey).ExpectedStatus
                Hostname          = $Hostname
                Instance          = ""
                Database          = ""
                Site              = ""
                ResultHash        = ""
                ValidationCode    = $LegacyObject.$($STIGkey).$($Vuln).$($AnswerKey).ValidationCode
                ValidTrueStatus   = $LegacyObject.$($STIGkey).$($Vuln).$($AnswerKey).ValidTrueStatus
                ValidTrueComment  = $LegacyObject.$($STIGkey).$($Vuln).$($AnswerKey).ValidTrueComment
                ValidFalseStatus  = $LegacyObject.$($STIGkey).$($Vuln).$($AnswerKey).ValidFalseStatus
                ValidFalseComment = $LegacyObject.$($STIGkey).$($Vuln).$($AnswerKey).ValidFalseComment
            }

            $KeyNameObj.Add("1", $IndexObj) # Create Index subobject for Answer element
            $VulnObj.Add($NewKeyName, $KeyNameObj) # Create Name subobject for AnswerKey element
        }

        # Add $VulnObj to $TempObj
        $NewAFObject.$($STIGName).Add($Vuln, $VulnObj)
    }

    $Result = @{
        Log    = $Log
        Object = $NewAFObject
    }

    return $Result
}

function Convert-Status {
    # Super simple function to save space. Converts freely between Status for Evaluate-STIG, CKL, CKLB, XCCDF.
    [cmdletbinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [ValidateSet(
            'NR', 'NF', 'NA', 'O', # Evaluate-STIG
            'Not_Reviewed', 'NotAFinding', 'Not_Applicable', 'Open', # CKL/CKLB (except 'NotAFinding')
            'not_a_finding', # CKLB only
            'notchecked', 'pass', 'notapplicable', 'fail' # STIG Manager
        )]
        $InputObject,

        [ValidateSet('EvalSTIG', 'CKL', 'CKLB', 'XCCDF')]
        [String]$Output
    )

    $SortingHat = @{
        'EvalSTIG' = @{
            # Input = CKL
            'Not_Reviewed'   = 'NR'
            'NotAFinding'    = 'NF'
            'Not_Applicable' = 'NA'
            'Open'           = 'O'
            # Input = CKLB
            'not_a_finding'  = 'NF'
            # Input = STIGMAN
            'notchecked'     = 'NR'
            'pass'           = 'NF'
            'notapplicable'  = 'NA'
            'fail'           = 'O'
        }
        'CKL'      = @{
            # Input = Evaluate-STIG
            'NR'            = 'Not_Reviewed'
            'NF'            = 'NotAFinding'
            'NA'            = 'Not_Applicable'
            'O'             = 'Open'
            # Input = CKLB
            'not_a_finding' = 'NotAFinding'
            # Input = STIGMAN
            'notchecked'    = 'Not_Reviewed'
            'pass'          = 'NotAFinding'
            'notapplicable' = 'Not_Applicable'
            'fail'          = 'Open'
        }
        'CKLB'     = @{
            # Input = Evaluate-STIG
            'NR'            = 'Not_Reviewed'
            'NF'            = 'not_a_finding'
            'NA'            = 'Not_Applicable'
            'O'             = 'Open'
            # Input = CKLB
            'NotAFinding'   = 'not_a_finding'
            # Input = STIGMAN
            'notchecked'    = 'Not_Reviewed'
            'pass'          = 'not_a_finding'
            'notapplicable' = 'Not_Applicable'
            'fail'          = 'Open'
        }
        'XCCDF'    = @{
            # Input = Evaluate-STIG
            'NR'             = 'notchecked'
            'NF'             = 'pass'
            'NA'             = 'notapplicable'
            'O'              = 'fail'
            # Input = CKL
            'Not_Reviewed'   = 'notchecked'
            'NotAFinding'    = 'pass'
            'Not_Applicable' = 'notapplicable'
            'Open'           = 'fail'
            # Input = CKLB
            'not_a_finding'  = 'pass'
        }
    }

    $result = $SortingHat[$Output][$InputObject]
    if (-not ($result)) {
        $result = $InputObject
    }
    return $result
}

function Save-AnswerFileObject {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$AFObject,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$CreateBackup
    )

    if ($CreateBackup) {
        # Create a backup of the XML file before proceeding
        $BAKFile = $Path -replace ([System.IO.Path]::GetExtension($Path), ".bak")
        Copy-Item -Path $Path -Destination $BAKFile -Force
    }

    # ==========================================================
    # Begin Write XML
    # ==========================================================
    $STIG = $AFObject.Keys | Select-Object -First 1
    $Encoding = [System.Text.Encoding]::UTF8
    $XmlWriter = New-Object System.Xml.XmlTextWriter($Path, $Encoding)
    $XmlWriter.Formatting = "Indented"
    $XmlWriter.Indentation = 2

    $XmlWriter.WriteStartDocument()

    # Add Comment section
    $XmlWriter.WriteComment('**************************************************************************************
This file contains answers for known opens and findings that cannot be evaluated through technical means.
<STIGComments>      - Top element.  May only occur once.
      "Name"           : Required.  Must match the STIG ShortName in -ListSupportedProducts.  When a match is found, this answer file will automatically be used for the STIG.
<Vuln>              - Multiple <Vuln> sections may be configured in a single answer file provided the "ID" attribute is unique.
      "ID"             : Required.  The STIG VulnID or RuleID.
<AnswerKey>         - Multiple <AnswerKey> sections may be configured within a single <Vuln> section provided the "Name" attribute is unique.
      "Name"           : Required.  The name of the key to be called by "-AnswerKey".  "DEFAULT" may be used in lieu of using "-AnswerKey".
<Answer>            - Multiple <Answer> sections may be configured within an <AnswerKey> section provided the "Index" attribute is unique AND the combination of the other attributes is unique.
      "Index"          : Required.  Identifier for the answer.
      "ExpectedStatus" : Required.  The initial status that Evaluate-STIG determined.  Refer to "Valid Status formats" below.
      "Hostname"       : Optional.  Hostname(s) that the answer is applicable to.  Use comma separation for multiple.
      "Instance"       : Optional.  Instance name(s) (e.g. for SQL) that the answer is applicable to.  Use comma separation for multiple.  Reference FindingDetails for appropriate Instance value.
      "Database"       : Optional.  Database name(s) (e.g. for SQL) that the answer is applicable to.  Use comma separation for multiple.  Reference FindingDetails for appropriate Database value.
      "Site"           : Optional.  Site names (e.g. for IIS) that the answer is applicable to.  Use comma separation for multiple.  Reference FindingDetails for appropriate Site value.
      "ResultHash"     : Optional.  Hash of FindingDetails text after "~~~~~" bar.  Use comma separation for multiple.  Reference FindingDetails for calculated ResultHash.
<ValidationCode>    - Powershell code that returns a boolean value or Hashtable.  If blank, "true" is assumed.
                      *Note: If Validation Code returns a Hashtable, the Object MUST contain both [String]"Results" and [Boolean]"Valid" keys.  "Results" will be written to the Comments field of the STIG check.
                      The following Evaluate-STIG variables are also available to be called within validation code:
      $ESPath          : Path that Evaluate-STIG.ps1 was executed from.
      $ExpectedStatus  : Status that Evaluate-STIG determined.  Will be in CKL format (refer to "Valid Status formats" below).
      $ResultHash      : SHA1 hash of ResultData.  Reference FindingDetails for calculated ResultHash.
      $ResultData      : FindingDetails content after "~~~~~" bar.
      $Username        : User name processed for HKCU check.  Reference to FindingDetails for appropriate Username value.
      $UserSID         : User SID processed for HKCU check.  Reference to FindingDetails for appropriate UserSID value.
      $Instance        : Instance name processed.  Reference FindingDetails for appropriate Instance value.
      $Database        : Database name processed.  Reference FindingDetails for appropriate Database value.
      $Site            : Site name processed.  Reference FindingDetails for appropriate Site value.
<ValidTrueStatus>   - The status the check should be set to if ValidationCode returns "true".  Refer to "Valid Status formats" below.  If blank, Status is unchanged.
<ValidTrueComment>  - The verbiage to add to the Comments section if ValidationCode returns "true".
<ValidFalseStatus>  - The status the check should be set to if ValidationCode DOES NOT return "true".  Refer to "Valid Status formats" below.  If blank, Status is unchanged
<ValidFalseComment> - The verbiage to add to the Comments section if ValidationCode DOES NOT return "true".

* Valid Status formats:
    |     Status     | EvalSTIG |       CKL        |       CKLB       |      XCCDF      |
    |================|==========|==================|==================|=================|
    | Not Reviewed   | "NR"     | "Not_Reviewed"   | "Not_Reviewed"   | "notchecked"    |
    | Not A Finding  | "NF"     | "NotAFinding"    | "not_a_finding"  | "pass"          |
    | Open           | "O"      | "Open"           | "Open"           | "fail"          |
    | Not Applicable | "NA"     | "Not_Applicable" | "Not_Applicable" | "notapplicable" |
    |================|==========|==================|==================|=================|

* Answer Weighting:
  Evaluate-STIG adds the weights for all "applicable" attributes configured in an <Answer>.  If an attribute is configured but not applicable to the STIG (e.g. configuring the "Database" attribute for an IIS Site STIG) then the weight for that attribute is not included in the calculation.
    |    Attribute     | Weight |
    |==================|========|
    | ExpectedStatus   |   0 *  |  * ExpectedStatus is a hard requirement.  If not a match, the answer is ignored.
    | Hostname         |   5    |
    | Instance         |   4    |
    | Database         |   3    |
    | Site             |   2    |
    | ResultHash       |   1    |
    | <AnswerKey Name> |   16   |
    |==================|========|
**************************************************************************************')

    # Create STIGComments node
    $XmlWriter.WriteStartElement("STIGComments")
    $XmlWriter.WriteAttributeString("Name", $STIG)
    if ($AFObject.$($STIG)._Comment -notin @($null, "")) {
        $XmlWriter.WriteComment($AFObject.$($STIG)._Comment) # Write the comment for STIGComments node
    }

    # Create Vuln nodes
    foreach ($Vuln in ($AFObject.$($STIG).Keys | Where-Object { $_ -ne "_Comment" })) {
        $XmlWriter.WriteStartElement("Vuln")
        $XmlWriter.WriteAttributeString("ID", $Vuln)
        if ($AFObject.$($STIG).$($Vuln)._Comment -notin @($null, "")) {
            $XmlWriter.WriteComment($AFObject.$($STIG).$($Vuln)._Comment) # Write the comment for Vuln node
        }

        # Create AnswerKey nodes
        foreach ($KeyName in ($AFObject.$($STIG).$($Vuln).Keys | Where-Object { $_ -ne "_Comment" })) {
            $XmlWriter.WriteStartElement("AnswerKey")
            $XmlWriter.WriteAttributeString("Name", $KeyName)
            if ($AFObject.$($STIG).$($Vuln).$($KeyName)._Comment -notin @($null, "")) {
                $XmlWriter.WriteComment($AFObject.$($STIG).$($Vuln).$($KeyName)._Comment) # Write the comment for AnswerKey node
            }

            # Create Answer nodes
            foreach ($Index in ($AFObject.$($STIG).$($Vuln).$($KeyName).Keys | Where-Object { $_ -ne "_Comment" })) {
                $XmlWriter.WriteStartElement("Answer")
                $XmlWriter.WriteAttributeString("Index", $Index)
                foreach ($Attribute in @("ExpectedStatus", "Hostname", "Instance", "Database", "Site", "ResultHash")) {
                    # Add the Index attributes
                    switch ($Attribute) {
                        "ExpectedStatus" {
                            if ($AFObject.$($STIG).$($Vuln).$($KeyName).$($Index).$($Attribute) -notin @($null, "")) {
                                $FormattedStatus = Convert-Status -InputObject $AFObject.$($STIG).$($Vuln).$($KeyName).$($Index).$($Attribute) -Output $script:StatusFormat
                            }
                            else {
                                $FormattedStatus = ""
                            }
                            $XmlWriter.WriteAttributeString($Attribute, $FormattedStatus)
                        }
                        default {
                            $XmlWriter.WriteAttributeString($Attribute, $AFObject.$($STIG).$($Vuln).$($KeyName).$($Index).$($Attribute))
                        }
                    }
                }
                if ($AFObject.$($STIG).$($Vuln).$($KeyName).$($Index)._Comment -notin @($null, "")) {
                    $XmlWriter.WriteComment($AFObject.$($STIG).$($Vuln).$($KeyName).$($Index)._Comment) # Write the comment for the Index
                }

                # Create sub nodes
                foreach ($SubNode in @("ValidationCode", "ValidTrueStatus", "ValidTrueComment", "ValidFalseStatus", "ValidFalseComment")) {
                    $XmlWriter.WriteStartElement($SubNode)
                    if ($AFObject.$($STIG).$($Vuln).$($KeyName).$($Index).$($SubNode) -notin @($null, "")) {
                        switch ($SubNode) {
                            "ValidationCode" {
                                $XmlWriter.WriteString("`r`n")
                                $XmlWriter.WriteString($AFObject.$($STIG).$($Vuln).$($KeyName).$($Index).$($SubNode))
                                $XmlWriter.WriteString("`r`n        ")
                            }
                            { $_ -in @("ValidTrueStatus", "ValidFalseStatus") } {
                                $FormattedStatus = Convert-Status -InputObject $AFObject.$($STIG).$($Vuln).$($KeyName).$($Index).$($SubNode) -Output $script:StatusFormat
                                $XmlWriter.WriteString($FormattedStatus)
                            }
                            default {
                                $XmlWriter.WriteString($AFObject.$($STIG).$($Vuln).$($KeyName).$($Index).$($SubNode))
                            }
                        }
                    }
                    else {
                        $XmlWriter.WriteWhitespace("")
                    }
                    $XmlWriter.WriteFullEndElement()
                }

                # Close Answer node
                $XmlWriter.WriteEndElement()
            }
            # Close AnswerKey node
            $XmlWriter.WriteEndElement()
        }
        # Close Vuln node
        $XmlWriter.WriteEndElement()
    }
    # Close STIGComments node
    $XmlWriter.WriteEndElement()

    $XmlWriter.WriteEnddocument()
    $XmlWriter.Flush()
    $XmlWriter.Close()
}

function Test-XmlAgainstSchema {
    # Validate XML against a schema file or a multiline schema string
    param (
        [Parameter(Mandatory = $true)]
        [String]$XmlFile,

        [Parameter(Mandatory = $true)]
        [String]$SchemaInput,

        # Can be a file path or a multiline string

        [Parameter(Mandatory = $false)]
        [Switch]$IsSchemaString # Set if $SchemaInput is a string, not a file
    )

    try {
        Get-ChildItem $XmlFile -ErrorAction Stop | Out-Null

        $XmlErrors = New-Object System.Collections.Generic.List[System.Object]
        [Scriptblock]$ValidationEventHandler = {
            if ($_.Exception.LineNumber) {
                $Message = "$($_.Exception.Message) Line $($_.Exception.LineNumber), position $($_.Exception.LinePosition)."
            }
            else {
                $Message = ($_.Exception.Message)
            }

            $NewObj = [PSCustomObject]@{
                Message = $Message
            }
            $XmlErrors.Add($NewObj)
        }

        $ReaderSettings = New-Object -TypeName System.Xml.XmlReaderSettings
        $ReaderSettings.ValidationType = [System.Xml.ValidationType]::Schema
        $ReaderSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessIdentityConstraints -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings

        if ($IsSchemaString) {
            $schemaReader = [System.IO.StringReader]::new($SchemaInput)
            $xmlSchema = [System.Xml.Schema.XmlSchema]::Read($schemaReader, $null)
            $schemaSet = New-Object System.Xml.Schema.XmlSchemaSet
            $schemaSet.Add($xmlSchema) | Out-Null
            $ReaderSettings.Schemas.Add($schemaSet) | Out-Null
        }
        else {
            Get-ChildItem $SchemaInput -ErrorAction Stop | Out-Null
            if ((Split-Path $SchemaInput -Leaf) -eq "xccdf_1.2.xsd") {
                $ReaderSettings.Schemas.Add("http://checklists.nist.gov/xccdf/1.2", $SchemaInput) | Out-Null
            }
            else {
                $ReaderSettings.Schemas.Add($null, $SchemaInput) | Out-Null
            }
        }
        $ReaderSettings.add_ValidationEventHandler($ValidationEventHandler)

        try {
            $Reader = [System.Xml.XmlReader]::Create($XmlFile, $ReaderSettings)
            while ($Reader.Read()) {
            }
        }
        catch {
            $NewObj = [PSCustomObject]@{
                Message = ($_.Exception.Message)
            }
            $XmlErrors.Add($NewObj)
        }
        finally {
            if ($Reader) {
                $Reader.Close()
            }
        }

        if ($XmlErrors) {
            return $XmlErrors
        }
        else {
            return $true
        }
    }
    catch {
        return $_.Exception.Message
    }
}

function Update-AFObject {
    param (
        [Parameter(Mandatory = $true)]
        [String]$StatusFormat,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Remove", "Rename")]
        [String]$Action,

        [Parameter(Mandatory = $true)]
        [String]$STIG,

        [Parameter(Mandatory = $false)]
        [String]$VulnID,

        [Parameter(Mandatory = $false)]
        [String]$VulnIDComment,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKeyName,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKeyNameComment,

        [Parameter(Mandatory = $false)]
        [String]$Index,

        [Parameter(Mandatory = $false)]
        [String]$IndexComment,

        [Parameter(Mandatory = $false)]
        [String]$NewKeyName,

        [Parameter(Mandatory = $false)]
        [String[]]$IndexOrder,

        [Parameter(Mandatory = $false)]
        [String]$ExpectedStatus,

        [Parameter(Mandatory = $false)]
        [String[]]$Hostname,

        [Parameter(Mandatory = $false)]
        [String[]]$Instance,

        [Parameter(Mandatory = $false)]
        [String[]]$Database,

        [Parameter(Mandatory = $false)]
        [String[]]$Site,

        [Parameter(Mandatory = $false)]
        [String[]]$ResultHash,

        [Parameter(Mandatory = $false)]
        [String]$ValidationCode,

        [Parameter(Mandatory = $false)]
        [String]$ValidTrueStatus,

        [Parameter(Mandatory = $false)]
        [String]$ValidTrueComment,

        [Parameter(Mandatory = $false)]
        [String]$ValidFalseStatus,

        [Parameter(Mandatory = $false)]
        [String]$ValidFalseComment
    )

    switch ($Action) {
        "Remove" {
            if ($Index) {
                $script:AFObject.$STIG.$VulnID.$AnswerKeyName.Remove($Index)
            }
            elseif ($AnswerKeyName) {
                $script:AFObject.$STIG.$VulnID.Remove($AnswerKeyName)
            }
            elseif ($VulnID) {
                $script:AFObject.$STIG.Remove($VulnID)
            }
        }
        "Rename" {
            if ($Index) {
                # To preserve order, get the current order replacing the old key with new
                $PreservedOrder = ($script:AFObject.$STIG.$VulnID.$AnswerKeyName.Keys) -replace $Index, $NewKeyName

                # Copy old key to new and then remove old key
                $script:AFObject.$STIG.$VulnID.$AnswerKeyName.$NewKeyName = $script:AFObject.$STIG.$VulnID.$AnswerKeyName.$Index
                $script:AFObject.$STIG.$VulnID.$AnswerKeyName.Remove($Index)

                # Create new children object after rename to preserve original order
                $NewChildren = [ordered]@{ }
                foreach ($Key in $PreservedOrder) {
                    $NewChildren.Add($Key, $script:AFObject.$STIG.$VulnID.$AnswerKeyName.$Key)
                }

                # Remove current child objects
                $script:AFObject.$STIG.$VulnID.$AnswerKeyName.Clear()

                # Add new children object
                foreach ($Key in $NewChildren.Keys) {
                    $script:AFObject.$STIG.$VulnID.$AnswerKeyName.Add($Key, $NewChildren.$Key)
                }
            }
            elseif ($AnswerKeyName) {
                # To preserve order, get the current order replacing the old key with new
                $PreservedOrder = ($script:AFObject.$STIG.$VulnID.Keys) -replace $AnswerKeyName, $NewKeyName

                # Copy old key to new and then remove old key
                $script:AFObject.$STIG.$VulnID.$NewKeyName = $script:AFObject.$STIG.$VulnID.$AnswerKeyName
                $script:AFObject.$STIG.$VulnID.Remove($AnswerKeyName)

                # Create new children object after rename to preserve original order
                $NewChildren = [ordered]@{ }
                foreach ($Key in $PreservedOrder) {
                    $NewChildren.Add($Key, $script:AFObject.$STIG.$VulnID.$Key)
                }

                # Remove current child objects
                $script:AFObject.$STIG.$VulnID.Clear()

                # Add new children object
                foreach ($Key in $NewChildren.Keys) {
                    $script:AFObject.$STIG.$VulnID.Add($Key, $NewChildren.$Key)
                }
            }
            elseif ($VulnID) {
                # To preserve order, get the current order replacing the old key with new
                $PreservedOrder = ($script:AFObject.$STIG.Keys) -replace $VulnID, $NewKeyName

                # Copy old key to new and then remove old key
                $script:AFObject.$STIG.$NewKeyName = $script:AFObject.$STIG.$VulnID
                $script:AFObject.$STIG.Remove($VulnID)

                # Create new children object after rename to preserve original order
                $NewChildren = [ordered]@{ }
                foreach ($Key in $PreservedOrder) {
                    $NewChildren.Add($Key, $script:AFObject.$STIG.$Key)
                }

                # Remove current child objects
                $script:AFObject.$STIG.Clear()

                # Add new children object
                foreach ($Key in $NewChildren.Keys) {
                    $script:AFObject.$STIG.Add($Key, $NewChildren.$Key)
                }
            }
            elseif ($STIG) {
                # Copy old key to new and then remove old key
                $script:AFObject.$NewKeyName = $script:AFObject.$STIG
                $script:AFObject.Remove($STIG)
            }
        }
    }
}

function Update-AnswerFileObject {
    param (
        [Parameter(Mandatory = $false)]
        [Switch]$RemoveMissingVulnIDs,

        [Parameter(Mandatory = $false)]
        [Switch]$UpdateRuleIDs,

        [Parameter(Mandatory = $false)]
        [Switch]$ForceUpdate
    )

    $Log = @()

    $Result = "Success"
    $UpdateRequired = $false
    $AFSTIGName = $script:AFObject.Keys | Select-Object -First 1
    $ChecksToRemove = @()
    $ChecksToRename = @{ }
    $UpdateStigCommentsName = $false

    try {
        if ($ForceUpdate) {
            $UpdateRequired = $true
        }

        # Read in STIG's xccdf content
        $STIGListEntry = ($script:STIGListObj | Where-Object { $_.Name -eq $AFSTIGName -or $_.ShortName -eq $AFSTIGName })
        $STIGFile = $STIGListEntry.StigContent
        $ShortName = $STIGListEntry.ShortName
        if (-not ($STIGFile)) {
            $Result = "Failed"
            $Log += " STIG XCCDF file not found."
        }
        else {
            if (Test-Path $(Join-Path -Path $script:ESPath -ChildPath StigContent | Join-Path -ChildPath $STIGFile)) {
                $XccdfPath = (Join-Path -Path $script:ESPath -ChildPath StigContent | Join-Path -ChildPath $STIGFile)
            }
            elseif (Test-Path $(Join-Path -Path $script:ESPath -ChildPath StigContent | Join-Path -ChildPath Manual | Join-Path -ChildPath $STIGFile)) {
                $XccdfPath = (Join-Path -Path $script:ESPath -ChildPath StigContent | Join-Path -ChildPath Manual | Join-Path -ChildPath $STIGFile)
            }

            if ($XccdfPath) {
                if ($AFSTIGName -ne $ShortName) {
                    $Log += " Renaming STIGComments Name '$($AFSTIGName)' to ShortName '$($ShortName)'."
                    $UpdateStigCommentsName = $true
                    $UpdateRequired = $true
                }
                $STIGContent = [XML](Get-Content -Path $XccdfPath -Raw)
                $Log += " Checking for updates against the STIG."

                foreach ($Vuln in ($script:AFObject.$($AFSTIGName).Keys | Where-Object { $_ -ne "_Comment" })) {
                    $STIGItem = ""
                    if ($Vuln -match "^V-") {
                        # Format is GroupID.
                        $STIGItem = ($STIGContent.Benchmark.Group | Where-Object id -EQ $Vuln).id

                        # Check for duplicate RuleID in answer file
                        $Pattern = "^S$($Vuln)"
                        $Duplicates = $script:AFObject.$($AFSTIGName).Keys -match $Pattern
                        if ($Duplicates) {
                            $Log += "  Duplicate entries detected.  Please correct in the editor:"
                            foreach ($Item in $Duplicates) {
                                $Log += "   '$($Item)' is duplicate of '$($Vuln)"
                            }
                        }
                    }
                    elseif ($Vuln -match "^SV-") {
                        # Format is RuleID.
                        $STIGItem = ($STIGContent.Benchmark.Group | Where-Object { $_.Rule.id -match ($Vuln -split "r")[0] }).Rule.id

                        # Check for duplicate RuleID in answer file
                        $VulnNum = $VulnNum = (($Vuln -split "SV-")[1] -split "r")[0]
                        $Pattern = "(^V-$($VulnNum)|^SV-$($VulnNum))"
                        $Duplicates = $script:AFObject.$($AFSTIGName).Keys -match $Pattern | Where-Object { $_ -ne $Vuln }
                        if ($Duplicates) {
                            $Log += "  Duplicate entries detected.  Please correct in the editor:"
                            foreach ($Item in $Duplicates) {
                                $Log += "   '$($Item)' is duplicate of '$($Vuln)"
                            }
                            throw $Log
                        }

                        if ($STIGItem -notin @($null, "") -and $Vuln -ne $STIGItem) {
                            $Log += " '$($Vuln)' has changed in the STIG."
                            if ($UpdateRuleIDs) {
                                $UpdateRequired = $true
                                $Log += "  Updating"
                                $ChecksToRename.Add($Vuln, $STIGItem)
                            }
                            else {
                                $Log += "  This Vuln ID in the answer file will never be applied.  Consider updating or removing."
                            }
                        }
                    }

                    if ($STIGItem -in @($null, "")) {
                        $Log += " '$($Vuln)' is not found in the STIG."
                        if ($RemoveMissingVulnIDs) {
                            $UpdateRequired = $true
                            $Log += "  Removing"
                            $ChecksToRemove += $Vuln
                        }
                        else {
                            $Log += "  This Vuln ID in the answer file will never be applied.  Consider removing."
                        }
                    }
                }

                if ($UpdateRequired) {
                    $Log += " Updating answer file."
                    foreach ($Vuln in $ChecksToRemove) {
                        Update-AFObject -StatusFormat $StatusFormat -Action Remove -STIG $AFSTIGName -VulnID $Vuln
                    }
                    foreach ($Key in $ChecksToRename.Keys) {
                        Update-AFObject -StatusFormat $StatusFormat -Action Rename -STIG $AFSTIGName -VulnID $Key -NewKeyName $ChecksToRename.($Key)
                    }
                    if ($UpdateStigCommentsName -eq $true) {
                        Update-AFObject -StatusFormat $StatusFormat -Action Rename -STIG $AFSTIGName -NewKeyName $ShortName
                    }
                }
                else {
                    $Log += " No update required."
                }
            }
            else {
                $Result = "Failed"
                $Log += " STIG XCCDF file not found."
            }
        }

        $Output = @{
            Result      = $Result
            NeedsUpdate = $UpdateRequired
            Log         = $Log
        }
        return $Output
    }
    catch {
        $ErrorLog = @()
        if ($_.TargetObject -match "duplicate") {
            foreach ($Line in $_.TargetObject) {
                $ErrorLog += $Line
            }
        }
        else {
            $ErrorLog += $_.Exception.Message
        }
        $Output = @{
            Result      = "Failed"
            NeedsUpdate = $false
            Log         = $ErrorLog
        }
        return $Output
    }
}
# <==== End Custom Functions ====>
Write-Host ""
try {
    $script:ESPath = $ESPath
    $script:StatusFormat = $StatusFormat

    if (-not($AFPath)) {
        $AFPath = Join-Path -Path $script:ESPath -ChildPath AnswerFiles
    }
    if (Test-Path -Path $AFPath -PathType Leaf) {
        $AFPathLeaf = Split-Path -Path $AFPath -Leaf
        $AFPath = Split-Path -Path $AFPath -Parent
        if (-not($AFPathLeaf -match "\.xml$")) {
            throw "'$($AFPathLeaf)' is an invalid file type.  Only .xml files are considered."
        }
    }

    # Create legacy answer file schema
    $script:LegacyAFSchema = @'
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" attributeFormDefault="unqualified" elementFormDefault="qualified">
  <xs:element name="STIGComments">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="Vuln" maxOccurs="500" minOccurs="0">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="AnswerKey" maxOccurs="500" minOccurs="1">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element name="ExpectedStatus">
                      <xs:simpleType>
                        <xs:restriction base="xs:string">
                          <xs:enumeration value="Not_Reviewed"/>
                          <xs:enumeration value="Open"/>
                          <xs:enumeration value="NotAFinding"/>
                          <xs:enumeration value="Not_Applicable"/>
                        </xs:restriction>
                      </xs:simpleType>
                    </xs:element>
                    <xs:element type="xs:string" name="ValidationCode"/>
                    <xs:element name="ValidTrueStatus">
                      <xs:simpleType>
                        <xs:restriction base="xs:string">
                          <xs:enumeration value=""/>
                          <xs:enumeration value="Not_Reviewed"/>
                          <xs:enumeration value="Open"/>
                          <xs:enumeration value="NotAFinding"/>
                          <xs:enumeration value="Not_Applicable"/>
                        </xs:restriction>
                      </xs:simpleType>
                    </xs:element>
                    <xs:element type="xs:string" name="ValidTrueComment" maxOccurs="1" minOccurs="1"/>
                    <xs:element name="ValidFalseStatus">
                      <xs:simpleType>
                        <xs:restriction base="xs:string">
                          <xs:enumeration value=""/>
                          <xs:enumeration value="Not_Reviewed"/>
                          <xs:enumeration value="Open"/>
                          <xs:enumeration value="NotAFinding"/>
                          <xs:enumeration value="Not_Applicable"/>
                        </xs:restriction>
                      </xs:simpleType>
                    </xs:element>
                    <xs:element type="xs:string" name="ValidFalseComment" maxOccurs="1" minOccurs="1"/>
                  </xs:sequence>
                  <xs:attribute type="xs:string" name="Name" use="required"/>
                </xs:complexType>
              </xs:element>
            </xs:sequence>
            <xs:attribute name="ID" use="required">
              <xs:simpleType>
                <xs:restriction base="xs:string">
                  <xs:pattern value="V-\d{4,6}" />
                </xs:restriction>
              </xs:simpleType>
            </xs:attribute>
          </xs:complexType>
          <xs:unique name="AnswerKeyUniqueKey">
            <xs:selector xpath="AnswerKey"/>
            <xs:field xpath="@Name"/>
          </xs:unique>
        </xs:element>
      </xs:sequence>
      <xs:attribute name="Name" use="required">
        <xs:simpleType>
          <xs:restriction base="xs:string"/>
        </xs:simpleType>
      </xs:attribute>
    </xs:complexType>
    <xs:unique name="VulnIdUniqueKey">
      <xs:selector xpath="Vuln"/>
      <xs:field xpath="@ID"/>
    </xs:unique>
  </xs:element>
</xs:schema>
'@

    # Verify version of Evaluate-STIG is supported version.
    $SupportedVer = [Version]"1.2507.2"
    Get-Content (Join-Path -Path $script:ESPath -ChildPath "Evaluate-STIG.ps1") | ForEach-Object {
        if ($_ -like '*$EvaluateStigVersion = *') {
            $Version = [Version]((($_ -split "=")[1]).Trim() -replace '"', '')
        }
    }
    if (-not($Version -ge $SupportedVer)) {
        throw "Error: Evaluate-STIG $SupportedVer or greater required.  Found $Version.  Please update Evaluate-STIG to a supported version before using this script."
    }

    # Validate STIGList.xml and answer file for proper schema usage.
    $STIGList_xsd = Join-Path -Path $script:ESPath -ChildPath "xml" | Join-Path -ChildPath "Schema_STIGList.xsd"
    $AnswerFile_xsd = Join-Path -Path $script:ESPath -ChildPath "xml" | Join-Path -ChildPath "Schema_AnswerFile.xsd"

    # STIGList.xml validation
    $XmlFile = Join-Path -Path $script:ESPath -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
    if (-not(Test-Path $XmlFile)) {
        throw "Error: '$XmlFile' - file not found.  Cannot continue."
    }
    elseif (-not(Test-Path $STIGList_xsd)) {
        throw "Error: '$STIGList_xsd' - file not found.  Cannot continue."
    }
    elseif (-not(Test-Path $AnswerFile_xsd)) {
        throw "Error: '$AnswerFile_xsd' - file not found.  Cannot continue."
    }

    $Result = Test-XmlAgainstSchema -XmlFile $XmlFile -SchemaInput $STIGList_xsd
    if ($Result -ne $true) {
        foreach ($Item in $Result.Message) {
            $Message += $Item | Out-String
        }
        throw $Message
    }

    # Get list of supported STIGs
    [XML]$script:STIGListXML = Get-Content (Join-Path -Path $script:ESPath -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $script:STIGListObj = [System.Collections.Generic.List[System.Object]]::new()
    foreach ($Item in ($script:STIGListXML.List.STIG | Sort-Object ShortName)) {
            $NewObj = [PSCustomObject]@{
                Name        = $Item.Name
                ShortName   = $Item.ShortName
                StigContent = $Item.StigContent
                DisaStatus  = $Item.DisaStatus
                Support     = "EvalSTIG"
            }
            $script:STIGListObj.Add($NewObj)
        }
    # Check for Manual STIGs
    $ManualSTIGs = [System.Collections.Generic.List[System.Object]]::new()
    if (Test-Path (Join-Path -Path $script:ESPath -ChildPath StigContent | Join-Path -ChildPath Manual)) {
        foreach ($Item in ((Get-ChildItem (Join-Path -Path $script:ESPath -ChildPath StigContent | Join-Path -ChildPath Manual) | Where-Object Extension -eq ".xml"))) {
            $NewObj = [PSCustomObject]@{
                Name        = $(($ManualSTIGContent.Benchmark.title -replace "_", " " -replace "STIG" -replace "Security Technical Implementation Guide").Trim())
                Shortname   = "M_" + $(($ManualSTIGContent.Benchmark.ID -replace "_" -replace "STIG").Trim())
                StigContent = $Item.Name
                DisaStatus = ""
                Support   = "Manual"
            }
            $STIGsToProcess.Add($NewObj)
        }
    }
    foreach ($Item in ($ManualSTIGs | Sort-Object ShortName)) {
        $script:STIGListObj.Add($Item)
    }

    # Build Update-AnswerFileObject args
    $UpdateArgs = @{ }
    if ($PSBoundParameters.RemoveMissingVulnIDs) {
        $UpdateArgs.Add("RemoveMissingVulnIDs", $true)
    }
    if ($PSBoundParameters.UpdateChangedRuleIDs) {
        $UpdateArgs.Add("UpdateRuleIDs", $true)
    }
    if ($PSBoundParameters.ForceUpdate) {
        $UpdateArgs.Add("ForceUpdate", $true)
    }

    # Get STIG AnswerFiles
    if ($AFPathLeaf) {
        $AnswerFiles = (Get-ChildItem -Path (Join-Path -Path $AFPath -ChildPath $AFPathLeaf) | Sort-Object Name | Where-Object Extension -eq ".xml").Name
        if ($AnswerFiles -eq "Template_AnswerFile.xml") {
            return "Selected file is Evaluate-STIG's template answer file and should not be modified.  Please select a different file."
        }
    }
    else {
        $AnswerFiles = (Get-ChildItem -Path $AFPath | Sort-Object Name | Where-Object {$_.Extension -eq ".xml" -and $_.Name -ne "Template_AnswerFile.xml"}).Name
    }
    if (-not($AnswerFiles)) {
        return "No answer files found in path '$($AFPath)'"
    }

    foreach ($File in $AnswerFiles) {
        $ValidFile = $true
        $UpdateRequired = $false
        $Content = @{
            Result  = ""
            Message = @()
        }

        Write-Host "Processing $($File)..." -ForegroundColor Gray -NoNewline

        # Check legacy schema first
        $LegacyResult = Test-XmlAgainstSchema -XmlFile (Join-Path -Path $AFPath -ChildPath $File) -SchemaInput $script:LegacyAFSchema -IsSchemaString
        if ($LegacyResult -eq $true) {
            $LegacyAFObject = Convert-AnswerFileToObject -XmlFile (Join-Path -Path $AFPath -ChildPath $File) -IsLegacy -StatusFormat $script:StatusFormat

            if ($PSBoundParameters.HostnameRegEx) {
                $MigrateResult = Convert-LegacyAFObject -LegacyObject $LegacyAFObject -HostnamePattern $HostnameRegEx
            }
            else {
                $MigrateResult = Convert-LegacyAFObject -LegacyObject $LegacyAFObject
            }

            foreach ($Entry in $MigrateResult.Log) {
                $Content.Message += $Entry
            }

            # Update the answer file object
            $script:AFObject = $MigrateResult.Object
            if ($PSBoundParameters.ForceUpdate) {
                $UpdateResult = Update-AnswerFileObject @UpdateArgs
            }
            else {
                $UpdateResult = Update-AnswerFileObject @UpdateArgs -ForceUpdate
            }
            $UpdateRequired = $UpdateResult.NeedsUpdate
            $Content.Result = $UpdateResult.Result
            foreach ($Entry in $UpdateResult.Log) {
                $Content.Message += $Entry
            }
        }
        else {
            $Result = Test-XmlAgainstSchema -XmlFile (Join-Path -Path $AFPath -ChildPath $File) -SchemaInput (Join-Path -Path $script:ESPath -ChildPath xml | Join-Path -ChildPath Schema_AnswerFile.xsd)
            if ($Result -eq $true) {
                $script:AFObject = Convert-AnswerFileToObject -XmlFile (Join-Path -Path $AFPath -ChildPath $File) -StatusFormat $script:StatusFormat

                # Update the answer file object
                $UpdateResult = Update-AnswerFileObject @UpdateArgs
                $UpdateRequired = $UpdateResult.NeedsUpdate
                $Content.Result = $UpdateResult.Result
                foreach ($Entry in $UpdateResult.Log) {
                    $Content.Message += $Entry
                }
            }
            else {
                $ValidFile = $false
                $Content.Result = "Failed"
                $Content.Message = $Result.Message
            }
        }

        if ($ValidFile -and $UpdateRequired) {
            # Save file
            if (-Not($PSBoundParameters.NoBackup)) {
                Save-AnswerFileObject -AFObject $script:AFObject -Path (Join-Path -Path $AFPath -ChildPath $File) -CreateBackup
            }
            else {
                Save-AnswerFileObject -AFObject $script:AFObject -Path (Join-Path -Path $AFPath -ChildPath $File)
            }
        }

        if ($Content.Result -eq "Success") {
            Write-Host $Content.Result -ForegroundColor Green
        }
        else {
            Write-Host $Content.Result -ForegroundColor Red
        }
        foreach ($Line in $Content.Message) {
            Write-Host $Line
        }

        Write-Host ""
    }
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC+FP8z6d6CmlBC
# CR/UHMVAewMSngBFWEmcW6TRGS8M/6CCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCD3N4tK7WkIiT+XXwFdlXv7/UafRFf6OKhCdD+eQ3YkzDANBgkqhkiG9w0BAQEF
# AASCAQAo1WQxHhiZX6T3fZQVQGDFVD4zA+l++geD8x/311cnvLleORqToMoscuJ6
# 2qCVhevEbcFeGjJwYsKp0LWVKYfspbYOgrjjnzip5oP3P481sC+q2rq686uusdhq
# VCFEaB4jYcFLMv99KCDJ3tdB7m4TCdxyJzwyMNY/ZWtAN+2/gkTNanHVJma6WfLa
# NcKKT+TVE4tFzd7F32c+bEHW7OJXHGGlcKbUPt2Dfmu+RWH4key00MbZuqWK9lBQ
# 0sYbLLke8TABwBXiXhMnt9KaK84q2fnEMqR77wc4x5E3Gn1Oma3ezuSPjttRYDAh
# yyaqLHJWefQy2+cqEBZdX+JHXyBGoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyOTE3NTYyNlowLwYJKoZIhvcNAQkEMSIEIPrWJIeliGU3a0gMBPvbit7EU7ZK
# 8wS9z3Nk2EfD+AlbMA0GCSqGSIb3DQEBAQUABIICAKPswkv+wqHwe231bVgUEPfJ
# JusFH4Kgk0F+hYIYtSzzOsftkCwr/PFjB/WZzIUVNhHpaTfKPHS1lNs/ysNvx3QQ
# Gvu6dfK8rpIF4t8KM313C2Sf2UwYGXrsr6uHtL+bPhNGFS4odKy4IhJOp57DmCNc
# 9W6zzAr2+iw6aywT5Ef0D+9fMpdNokrKzwB4FMQ1SdRFXwWX79W2eRgT65Qh36fJ
# 7oVMgAb1AH3zf8BZCjSDd5rLGEq3ydr9yBAPVjdW79fKXhfXwLq6nWrRXpBJ3XAc
# z6I+mhF0mwO+vAgj9YlQOYpC6S/DgQmT1XfuhKsjuJkshCRmmCLA4j5pj7B1yslP
# K7m6Ndsy5ko+qOMDT/whbrXx4Y8oB5AsFu9iEo4LGK/fimiDFYzPd+brKmRzKp0R
# Bjfrx3uuuAfEKg/y1vfbceZdLn89DWjergjP7Z2O1LpYzPYGOD9sRYeThrBvryzl
# 5bFDvVAtwnkrGp+oU9YI1UdgLA+bqqu509grn8Hr6CoNY1LXv0toYCGuG+QASie3
# 3UO7KeMqqc3bI+RoKqvtTMrvN06FNsX5cb3NPtZKcPnkyz848tGa/wnKYoh6K4fi
# Lq5EZFyk+USswi+jO0FqrplNwbm902xIiSMSY8VZadV6Osyd6y5XuuFlprPNuJK4
# EjAiI6KMP80KLbQXfFX5
# SIG # End signature block
