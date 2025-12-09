<#
    .Synopsis
    Create an Report from completed STIG assessments.
    .DESCRIPTION
    Creates a report from Evaluate-STIG Summary Reports.  Suggest running Validate-Results.ps1 prior to creating this report.
    Excel is required be installed.
    .EXAMPLE
    PS C:\> Get-SummaryReport.ps1 -ESResultsPath C:\Results
    .INPUTS
    -ESResultsPath
        Path to the Evaluate-STIG results directory.  Expected structure - Results Directory -> HostName Directory -> Checklist Directory, SummaryReport.xml
    .INPUTS
    -MachineInfo
        Add a worksheet for per Machine findings (increases run time substantially).
    .INPUTS
    -STIGInfo
        Add worksheets for each STIG found in Summary Reports (increases run time substantially).
    .INPUTS
    -OutputPath
        Path to location to save Summary Report.
#>

Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String[]]$ESResultsPath,

    [Parameter(Mandatory = $false)]
    [switch]$MachineInfo,

    [Parameter(Mandatory = $false)]
    [switch]$STIGInfo,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]$OutPutpath
)

Function Write-Log {
    <#
    .Synopsis
        Write to a CMTrace friendly .log file.
    .DESCRIPTION
        Takes the input and generates an entry for a CMTrace friendly .log file
        by utilizing a PSCustomObject and Generic List to hold the data.
        A string is created and added to the .log file.
    .EXAMPLE
       PS C:\> Write-Log -Path 'C:\Temp\sample.log' -Message 'Test Message' -Component 'Write-Log' -MessageType Verbose -OSPlatform Windows
    .INPUTS
        -Path
            Use of this parameter is required. Forced to be a String type. The path to where the .log file is located.
        -Message
            Use of this parameter is required. Forced to be a String type. The message to pass to the .log file.
        -Component
            Use of this parameter is required. Forced to be a String type. What is providing the Message.
            Typically this is the script or function name.
        -Type
            Use of this parameter is required. Forced to be a String type. What type of output to be. Choices are
            Info, Warning, Error and Verbose.
        -OSPlatform
            Use of this parameter is required. Forced to be a String type. What OS platform the system is. Choices are Windows or Linux.
    .OUTPUTS
        No output. Writes an entry to a .log file via Add-Content.
    .NOTES
        Resources/Credits:
            Dan Ireland - daniel.ireland@navy.mil
            Brent Betts - brent.betts@navy.mil
        Helpful URLs:
            Russ Slaten's Blog Post - Logging in CMTrace format from PowerShell
            https://blogs.msdn.microsoft.com/rslaten/2014/07/28/logging-in-cmtrace-format-from-powershell/
    #>

    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$Message,

        [Parameter(Mandatory = $true)]
        [String]$Component,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error", "Verbose")]
        [String]$Type
    )

    # Obtain date/time

    $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
    $DateTime.SetVarDate($(Get-Date))
    $UtcValue = $DateTime.Value
    $UtcOffset = [Math]::Abs($UtcValue.Substring(21, $UtcValue.Length - 21))

    # Create Object to hold items to log
    $LogItems = New-Object System.Collections.Generic.List[System.Object]
    $NewObj = [PSCustomObject]@{
        Message   = $Message
        Time      = [Char]34 + (Get-Date -Format "HH:mm:ss.fff") + "+$UtcOffset" + [Char]34
        Date      = [Char]34 + (Get-Date -Format "MM-dd-yyyy") + [Char]34
        Component = [Char]34 + $Component + [Char]34
        Type      = [Char]34 + $Type + [Char]34
    }
    $LogItems.Add($NewObj)

    # Format Log Entry
    $Entry = "<![LOG[$($LogItems.Message)]LOG]!><time=$($LogItems.Time) date=$($LogItems.Date) component=$($LogItems.Component) type=$($LogItems.Type)"

    # Add to Log
    Add-Content -Path $Path -Value $Entry -ErrorAction SilentlyContinue | Out-Null
}

if (!($OutPutpath)){
    $OutPutpath = $PSScriptRoot
}

if (!($STIGInfo)){
    $STIGInfo = $false
}

$LogPath = "$OutPutPath\Summary_Report_Log_$(Get-Date -Format yyyyMMdd_HHmmss).log"
$Report_Name = "Summary_Report_$(Get-Date -Format yyyyMMdd_HHmmss).xlsx"

Write-Log $LogPath "==========[Begin Logging]==========" "PreReq_Check" "Info"

Try {
    $ReportExcel = New-Object -ComObject Excel.Application
}
Catch {
    Write-Host "Excel is not installed. Exiting" -ForegroundColor Red
    Write-Log $LogPath "Excel is not installed." "PreReq_Check" "Error"
    Write-Log $LogPath "==========[End Logging]==========" "PreReq_Check" "Info"
    return
}

Write-Host "Getting data..."
Write-Log $LogPath "Getting data..." "PreReq_Check" "Info"

$SummaryReports = New-Object -TypeName "System.Collections.ArrayList"
$SummaryReports = [System.Collections.ArrayList]@()
$Computer_count = New-Object -TypeName "System.Collections.ArrayList"
$Computer_count = [System.Collections.ArrayList]@()
$Findings_List = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Counts_CAT_I = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Counts_CAT_II = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Counts_CAT_III = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$null = $ESResultsPath | ForEach-Object { $SummaryReports += @(Get-ChildItem -Path $_ -Recurse -Filter "SummaryReport.xml" -File) | Where-Object { $_.FullName -notmatch "Previous" } }

if ($SummaryReports.Count -eq 0){
    Write-Host "No Summary Reports found.  Exiting." -ForegroundColor Red
    Write-Log $LogPath "No Summary Report found.  Exiting." "PreReq_Check" "Info"
    Write-Log $LogPath "==========[End Logging]==========" "PreReq_Check" "Info"
    return
}

$Summary_ScriptBlock = {
    param([xml]$SummaryXML, $Findings_List, $Counts_CAT_I, $Counts_CAT_II, $Counts_CAT_III, $Computer_count, $STIGInfo)
    
    # Create list of invalid characters
    $InvalidChars = [System.IO.Path]::GetInvalidFileNameChars() # Get system identified invalid characters - varies by OS
    $InvalidChars += @('<', '>', ':', '"', '/', '\', '|', '?', '*')     # Add known invalid characters for Windows OS
    $InvalidChars = $InvalidChars | Select-Object -Unique       # Remove any duplicates

    if ([version]$SummaryXML.Summary.Computer.EvalSTIGVer -ge "1.2401.0"){
        $Results = $SummaryXML.Summary.Results.Result
    }
    else{
        $Results = $SummaryXML.Summary.Checklists.Checklist
    }

    ForEach ($Checklist in $Results) {
        $STIGName = [String]"$($Checklist.STIG -replace '_', ' ') V$($Checklist.Version)R$($Checklist.Release)"
        if ([version]$SummaryXML.Summary.Computer.EvalSTIGVer -ge "1.2501.0"){
            $BaseFileName = $($Checklist.ShortName)
        }
        else{
            $BaseFileName = $($Checklist.STIG)
        }

        $WebDB = $null
        
        If ($Checklist.Instance) {
            $STIGName = $STIGName + " ($($Checklist.Instance))"
            $WebDB = $Checklist.Instance
        }
        If ($Checklist.Site) {
            $STIGName = $STIGName + " ($($Checklist.Site))"
            $WebDB += "_$($Checklist.Site)"
        }

        if ($STIGInfo){
            $TempPath = [System.IO.Path]::GetTempPath() + $BaseFileName + ".csv"
            [System.Threading.Monitor]::Enter($Findings_List.SyncRoot)
            $Findings_List.Add($TempPath)
            [System.Threading.Monitor]::Exit($Findings_List.SyncRoot)
        }
        $findings = New-Object -TypeName "System.Collections.ArrayList"
        $findings_CAT_I = New-Object -TypeName "System.Collections.ArrayList"
        $findings_CAT_II = New-Object -TypeName "System.Collections.ArrayList"
        $findings_CAT_III = New-Object -TypeName "System.Collections.ArrayList"
        $findings = [System.Collections.ArrayList]@()
        $findings_CAT_I = [System.Collections.ArrayList]@()
        $findings_CAT_II = [System.Collections.ArrayList]@()
        $findings_CAT_III = [System.Collections.ArrayList]@()

        $Computer_count.add($SummaryXML.Summary.Computer.Name)

        [System.Threading.Monitor]::Enter($Counts_CAT_I.SyncRoot)
        $Counts_CAT_I.Add([PSCustomObject]@{
            STIG           = $STIGName
            Hostname       = $SummaryXML.Summary.Computer.Name
            Total          = $Checklist.CAT_I.Total
            Open           = $Checklist.CAT_I.Open
            Not_Applicable = $Checklist.CAT_I.Not_Applicable
            NotAFinding    = $Checklist.CAT_I.NotAFinding
            Not_Reviewed   = $Checklist.CAT_I.Not_Reviewed
        })
        [System.Threading.Monitor]::Exit($Counts_CAT_I.SyncRoot)

        [System.Threading.Monitor]::Enter($Counts_CAT_II.SyncRoot)
        $Counts_CAT_II.Add([PSCustomObject]@{
                STIG           = $STIGName
                Hostname       = $SummaryXML.Summary.Computer.Name
                Total          = $Checklist.CAT_II.Total
                Open           = $Checklist.CAT_II.Open
                Not_Applicable = $Checklist.CAT_II.Not_Applicable
                NotAFinding    = $Checklist.CAT_II.NotAFinding
                Not_Reviewed   = $Checklist.CAT_II.Not_Reviewed
            })
        [System.Threading.Monitor]::Exit($Counts_CAT_II.SyncRoot)

        [System.Threading.Monitor]::Enter($Counts_CAT_III.SyncRoot)
        $Counts_CAT_III.Add([PSCustomObject]@{
                STIG           = $STIGName
                Hostname       = $SummaryXML.Summary.Computer.Name
                Total          = $Checklist.CAT_III.Total
                Open           = $Checklist.CAT_III.Open
                Not_Applicable = $Checklist.CAT_III.Not_Applicable
                NotAFinding    = $Checklist.CAT_III.NotAFinding
                Not_Reviewed   = $Checklist.CAT_III.Not_Reviewed
            })
        [System.Threading.Monitor]::Exit($Counts_CAT_III.SyncRoot)

        ForEach ($Vuln in $Checklist.CAT_I.Vuln) {
            $findings_CAT_I.Add([PSCustomObject]@{
                ScanDate  = ([datetime]$Checklist.StartTime).ToString("yyyy-MM-dd HH:mm:ss")
                Hostname  = $SummaryXML.Summary.Computer.Name
                WebDB     = $WebDB
                Status    = $Vuln.Status
                Severity  = "CAT I"
                ID        = $Vuln.ID
                Override  = $Vuln.Override
                Justification = $Vuln.Justification
                AFStatusChange = $Vuln.AFStatusChange
                PreAFStatus = $Vuln.PreAFStatus
                RuleTitle = $Vuln.RuleTitle
            })
        }

        ForEach ($Vuln in $Checklist.CAT_II.Vuln) {
                $findings_CAT_II.Add([PSCustomObject]@{
                ScanDate  = ([datetime]$Checklist.StartTime).ToString("yyyy-MM-dd HH:mm:ss")
                Hostname  = $SummaryXML.Summary.Computer.Name
                WebDB     = $WebDB
                Status    = $Vuln.Status
                Severity  = "CAT II"
                ID        = $Vuln.ID
                Override  = $Vuln.Override
                Justification = $Vuln.Justification
                AFStatusChange = $Vuln.AFStatusChange
                PreAFStatus = $Vuln.PreAFStatus
                RuleTitle = $Vuln.RuleTitle
            })
        }

        ForEach ($Vuln in $Checklist.CAT_III.Vuln) {
                $findings_CAT_III.Add([PSCustomObject]@{
                ScanDate  = ([datetime]$Checklist.StartTime).ToString("yyyy-MM-dd HH:mm:ss")
                Hostname  = $SummaryXML.Summary.Computer.Name
                WebDB     = $WebDB
                Status    = $Vuln.Status
                Severity  = "CAT III"
                ID        = $Vuln.ID
                Override  = $Vuln.Override
                Justification = $Vuln.Justification
                AFStatusChange = $Vuln.AFStatusChange
                PreAFStatus = $Vuln.PreAFStatus
                RuleTitle = $Vuln.RuleTitle
            })
        }

        $Findings = $findings_CAT_I + $findings_CAT_II + $findings_CAT_III
        if ($STIGInfo){
            $Findings | Export-Csv $TempPath -NoTypeInformation -Append
        }
    }
}

Write-Host "Generating data from Summary Reports..."
Write-Log $LogPath "Generating data from Summary Reports..." "Summary Reports" "Info"

$MaxThreads = 10
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$RunspacePool.ApartmentState = "MTA"
$RunspacePool.Open()
$Jobs = @()

$Scandate = New-Object -TypeName "System.Collections.ArrayList"
$Scandate = [System.Collections.ArrayList]@()

$SummaryReports | ForEach-Object {

    $SummaryXML = New-Object -TypeName System.Xml.XmlDataDocument
    Try{
        $SummaryXML.Load($_.FullName)
        $null = $Scandate.Add([PSCustomObject]@{
                Hostname = $SummaryXML.Summary.Computer.Name
                ScanDate = $SummaryXML.Summary.Computer.ScanDate
            })
    }
    Catch{
        Write-Host "Error loading $($_.FullName)" -ForegroundColor Red
        Write-Log $LogPath "Error loading $($_.FullName)" "Summary Reports" "Error"
        Continue
    }

    $Job = [powershell]::Create().AddScript($Summary_ScriptBlock).AddArgument($SummaryXML).AddArgument($Findings_List).AddArgument($Counts_CAT_I).AddArgument($Counts_CAT_II).AddArgument($Counts_CAT_III).AddArgument($Computer_count).AddArgument($STIGInfo)
    $Job.RunspacePool = $RunspacePool
    $Jobs += [PSCustomObject]@{Runspace = $Job; Status = $Job.BeginInvoke()}
}

while ($Jobs.IsCompleted -contains $false) {
    Start-Sleep 1
}

foreach ($Job In $Jobs) {
    $null = $Job.Runspace.EndInvoke($Job.Status)
    $job.Runspace.Dispose()
}

$RunspacePool.Close()
$RunspacePool.Dispose()

$Findings_List = $Findings_List | Sort-Object -Unique

Write-Host "Creating Excel Data..."
Write-Log $LogPath "Creating Excel Data..." "Excel" "Info"

$ReportExcel.visible = $false
Start-Sleep 2

$Finding_CSV = 1
$ReportExcel.sheetsInNewWorkbook = $Findings_List.count + 3
$workbooks = $ReportExcel.Workbooks.Add()
$InfoWKST = $workbooks.Worksheets.Item($Finding_CSV)

Write-Log $LogPath "Adding Information Data..." "Information Worksheet" "Info"

$InfoWKST.Name = "Information"
$InfoWKST.Cells.Item(1, 3) = "STIG Information per Evaluate-STIG"
$InfoWKST.Cells.Item(1, 3).Font.Size = 18
$InfoWKST.Range("C1:F1").MergeCells = $true

$Computer_count = $Computer_count | Sort-Object -Unique
$InfoWKST.Cells.Item(2, 1) = "STIG Totals for $($Computer_count.count) Computer(s)"
$InfoWKST.Cells.Item(2, 1).Font.Size = 18
$InfoWKST.Cells.Item(2, 1).HorizontalAlignment = -4108

$InfoWKST.Cells.Item(4, 2) = ($Counts_CAT_I | Measure-Object Open -Sum).Sum
$InfoWKST.Cells.Item(4, 3) = ($Counts_CAT_I | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(4, 4) = ($Counts_CAT_I | Measure-Object NotAFinding -Sum).Sum
$InfoWKST.Cells.Item(4, 5) = ($Counts_CAT_I | Measure-Object Not_Applicable -Sum).Sum
$InfoWKST.Cells.Item(4, 6) = ($Counts_CAT_I | Measure-Object Open -Sum).Sum + ($Counts_CAT_I | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(4, 7) = ($Counts_CAT_I | Measure-Object Total -Sum).Sum - ($Counts_CAT_I | Measure-Object Not_Applicable -Sum).Sum

$InfoWKST.Cells.Item(5, 2) = ($Counts_CAT_II | Measure-Object Open -Sum).Sum
$InfoWKST.Cells.Item(5, 3) = ($Counts_CAT_II | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(5, 4) = ($Counts_CAT_II | Measure-Object NotAFinding -Sum).Sum
$InfoWKST.Cells.Item(5, 5) = ($Counts_CAT_II | Measure-Object Not_Applicable -Sum).Sum
$InfoWKST.Cells.Item(5, 6) = ($Counts_CAT_II | Measure-Object Open -Sum).Sum + ($Counts_CAT_II | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(5, 7) = ($Counts_CAT_II | Measure-Object Total -Sum).Sum - ($Counts_CAT_II | Measure-Object Not_Applicable -Sum).Sum

$InfoWKST.Cells.Item(6, 2) = ($Counts_CAT_III | Measure-Object Open -Sum).Sum
$InfoWKST.Cells.Item(6, 3) = ($Counts_CAT_III | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(6, 4) = ($Counts_CAT_III | Measure-Object NotAFinding -Sum).Sum
$InfoWKST.Cells.Item(6, 5) = ($Counts_CAT_III | Measure-Object Not_Applicable -Sum).Sum
$InfoWKST.Cells.Item(6, 6) = ($Counts_CAT_III | Measure-Object Open -Sum).Sum + ($Counts_CAT_III | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(6, 7) = ($Counts_CAT_III | Measure-Object Total -Sum).Sum - ($Counts_CAT_III | Measure-Object Not_Applicable -Sum).Sum

$InfoWKST.Cells.Item(8, 2) = "CAT I"
$InfoWKST.Cells.Item(8, 2).Font.Size = 18
$InfoWKST.Cells.Item(8, 2).HorizontalAlignment = -4108
$InfoWKST.Range("B8:E8").MergeCells = $true

$InfoWKST.Cells.Item(8, 9) = "CAT II"
$InfoWKST.Cells.Item(8, 9).Font.Size = 18
$InfoWKST.Cells.Item(8, 9).HorizontalAlignment = -4108
$InfoWKST.Range("I8:L8").MergeCells = $true

$InfoWKST.Cells.Item(8, 16) = "CAT III"
$InfoWKST.Cells.Item(8, 16).Font.Size = 18
$InfoWKST.Cells.Item(8, 16).HorizontalAlignment = -4108
$InfoWKST.Range("P8:S8").MergeCells = $true

$InfoWKST.Cells.Item(3, 2) = "Open"
$InfoWKST.Cells.Item(3, 3) = "Not_Reviewed"
$InfoWKST.Cells.Item(3, 4) = "NotAFinding"
$InfoWKST.Cells.Item(3, 5) = "Not_Applicable"
$InfoWKST.Cells.Item(3, 6) = "Total Open"
$InfoWKST.Cells.Item(3, 7) = "Possible"
$InfoWKST.Cells.Item(4, 1) = "CAT I"
$InfoWKST.Cells.Item(5, 1) = "CAT II"
$InfoWKST.Cells.Item(6, 1) = "CAT III"

$InfoWKST.Cells.Item(9, 2) = "Open"
$InfoWKST.Cells.Item(9, 3) = "Not_Reviewed"
$InfoWKST.Cells.Item(9, 4) = "NotAFinding"
$InfoWKST.Cells.Item(9, 5) = "Not_Applicable"
$InfoWKST.Cells.Item(9, 6) = "Total Open"
$InfoWKST.Cells.Item(9, 7) = "Possible"
$InfoWKST.Cells.Item(9, 9) = "Open"
$InfoWKST.Cells.Item(9, 10) = "Not_Reviewed"
$InfoWKST.Cells.Item(9, 11) = "NotAFinding"
$InfoWKST.Cells.Item(9, 12) = "Not_Applicable"
$InfoWKST.Cells.Item(9, 13) = "Total Open"
$InfoWKST.Cells.Item(9, 14) = "Possible"
$InfoWKST.Cells.Item(9, 16) = "Open"
$InfoWKST.Cells.Item(9, 17) = "Not_Reviewed"
$InfoWKST.Cells.Item(9, 18) = "NotAFinding"
$InfoWKST.Cells.Item(9, 19) = "Not_Applicable"
$InfoWKST.Cells.Item(9, 20) = "Total Open"
$InfoWKST.Cells.Item(9, 21) = "Possible"

$cellcount = 10
$count = 0
Write-Log $LogPath "Adding CAT I Data..." "Information Worksheet" "Info"
Foreach ($STIG in ($Counts_CAT_I.STIG | Where-Object {$_} | Sort-Object -Unique)) {

    Write-Progress -Activity "Counting CAT I Findings" -Status $STIG -PercentComplete ($count / @($Counts_CAT_I.STIG | Select-Object -Unique).count * 100)

    $InfoWKST.Cells.Item($cellcount, 1) = $STIG
    $InfoWKST.Cells.Item($cellcount, 2) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 3) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 4) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object NotAFinding -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 5) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 6) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum + (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 7) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Total -Sum).Sum - (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $cellcount++
    $count++
}

Write-Progress -Activity "Counting CAT I Findings" -Completed

$cellcount = 10
$count = 0
Write-Log $LogPath "Adding CAT II Data..." "Information Worksheet" "Info"
Foreach ($STIG in ($Counts_CAT_II.STIG | Where-Object {$_} | Sort-Object -Unique)) {

    Write-Progress -Activity "Counting CAT II Findings" -Status $STIG -PercentComplete ($count / @($Counts_CAT_II.STIG | Select-Object -Unique).count * 100)

    $InfoWKST.Cells.Item($cellcount, 9) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 10) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 11) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object NotAFinding -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 12) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 13) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum + (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 14) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Total -Sum).Sum - (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $cellcount++
    $count++
}

Write-Progress -Activity "Counting CAT II Findings" -Completed

$cellcount = 10
$count = 0
Write-Log $LogPath "Adding CAT III Data..." "Information Worksheet" "Info"
Foreach ($STIG in ($Counts_CAT_III.STIG | Where-Object {$_} | Sort-Object -Unique)) {

    Write-Progress -Activity "Counting CAT III Findings" -Status $STIG -PercentComplete ($count / @($Counts_CAT_III.STIG | Select-Object -Unique).count * 100)

    $InfoWKST.Cells.Item($cellcount, 16) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 17) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 18) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object NotAFinding -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 19) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 20) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum + (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 21) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Total -Sum).Sum - (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $cellcount++
    $count++
}

$null = $InfoWKST.UsedRange.Columns.AutoFit()
$Finding_CSV++

Write-Progress -Activity "Counting CAT III Findings" -Completed

if ($MachineInfo){
    Write-Log $LogPath "Adding Machine Info..." "Machine Info" "Info"
    $MachineInfoWKST = $workbooks.Worksheets.Item($Finding_CSV)
    $MachineInfoWKST.Name = "Machine Information"
    $MachineInfoWKST.Cells.Item(1, 8) = "Per Machine STIG Information per Evaluate-STIG"
    $MachineInfoWKST.Cells.Item(1, 8).Font.Size = 18
    $MachineInfoWKST.Range("H1:O1").MergeCells = $true
    $MachineInfoWKST.Cells.Item(4, 2) = "Scan Date"

    $MachineInfoWKST.Cells.Item(3, 4) = "CAT I"
    $MachineInfoWKST.Cells.Item(3, 4).Font.Size = 18
    $MachineInfoWKST.Cells.Item(3, 4).HorizontalAlignment = -4108
    $MachineInfoWKST.Range("D3:G3").MergeCells = $true

    $MachineInfoWKST.Cells.Item(3, 10) = "CAT II"
    $MachineInfoWKST.Cells.Item(3, 10).Font.Size = 18
    $MachineInfoWKST.Cells.Item(3, 10).HorizontalAlignment = -4108
    $MachineInfoWKST.Range("J3:M3").MergeCells = $true

    $MachineInfoWKST.Cells.Item(3, 16) = "CAT III"
    $MachineInfoWKST.Cells.Item(3, 16).Font.Size = 18
    $MachineInfoWKST.Cells.Item(3, 16).HorizontalAlignment = -4108
    $MachineInfoWKST.Range("P3:S3").MergeCells = $true

    $MachineInfoWKST.Cells.Item(4, 4) = "Open"
    $MachineInfoWKST.Cells.Item(4, 5) = "Not_Reviewed"
    $MachineInfoWKST.Cells.Item(4, 6) = "NotAFinding"
    $MachineInfoWKST.Cells.Item(4, 7) = "Not_Applicable"
    $MachineInfoWKST.Cells.Item(4, 10) = "Open"
    $MachineInfoWKST.Cells.Item(4, 11) = "Not_Reviewed"
    $MachineInfoWKST.Cells.Item(4, 12) = "NotAFinding"
    $MachineInfoWKST.Cells.Item(4, 13) = "Not_Applicable"
    $MachineInfoWKST.Cells.Item(4, 16) = "Open"
    $MachineInfoWKST.Cells.Item(4, 17) = "Not_Reviewed"
    $MachineInfoWKST.Cells.Item(4, 18) = "NotAFinding"
    $MachineInfoWKST.Cells.Item(4, 19) = "Not_Applicable"

    $cellcount = 5
    $count = 0

    Foreach ($Hostname in ($Counts_CAT_I.Hostname | Sort-Object -Unique)) {

        Write-Progress -Activity "Counting CAT I Findings for Assets" -Status $HostName -PercentComplete ($count / @($Counts_CAT_I.HostName | Select-Object -Unique).count * 100)
        Write-Log $LogPath "  Adding $Hostname CAT I Info..." "Machine Info" "Info"

        $MachineInfoWKST.Cells.Item($cellcount, 1) = $Hostname
        $MachineInfoWKST.Cells.Item($cellcount, 2) = ($Scandate | Where-Object { $_.Hostname -eq $Hostname }).ScanDate
        $MachineInfoWKST.Cells.Item($cellcount, 4) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Open -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 5) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Reviewed -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 6) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object NotAFinding -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 7) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Applicable -Sum).Sum

        $cellcount++
        $count++
    }

    Write-Progress -Activity "Counting CAT I Findings for Assets" -Completed

    $cellcount = 5
    $count = 0

    Foreach ($Hostname in ($Counts_CAT_II.Hostname | Sort-Object -Unique)) {

        Write-Progress -Activity "Counting CAT II Findings for Assets" -Status $HostName -PercentComplete ($count / @($Counts_CAT_II.HostName | Select-Object -Unique).count * 100)
        Write-Log $LogPath "  Adding $Hostname CAT II Info..." "Machine Info" "Info"

        $MachineInfoWKST.Cells.Item($cellcount, 10) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Open -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 11) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Reviewed -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 12) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object NotAFinding -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 13) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Applicable -Sum).Sum
        $cellcount++
        $count++
    }

    Write-Progress -Activity "Counting CAT II Findings for Assets" -Completed

    $cellcount = 5
    $count = 0

    Foreach ($Hostname in ($Counts_CAT_III.Hostname | Sort-Object -Unique)) {

        Write-Progress -Activity "Counting CAT III Findings for Assets" -Status $HostName -PercentComplete ($count / @($Counts_CAT_III.HostName | Select-Object -Unique).count * 100)
        Write-Log $LogPath "  Adding $Hostname CAT III Info..." "Machine Info" "Info"

        $MachineInfoWKST.Cells.Item($cellcount, 16) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Open -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 17) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Reviewed -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 18) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object NotAFinding -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 19) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Applicable -Sum).Sum
        $cellcount++
        $count++
    }

    Write-Progress -Activity "Counting CAT III Findings for Assets" -Completed
    $null = $MachineInfoWKST.UsedRange.Columns.AutoFit()
    $Finding_CSV++
}

Write-Host "Combining Finding data to Excel spreadsheet."
Write-Log $LogPath "Combining Finding data to Excel spreadsheet." "Excel" "Info"

if ($STIGInfo){
    forEach ($Finding in $Findings_List) {
        $WorkSheet_Name = $Finding.replace([System.IO.Path]::GetTempPath(), "").replace(".csv", "")
        $WorkSheet_Name = $WorkSheet_Name.Substring(0, [System.Math]::Min(31, $WorkSheet_Name.Length))
        $worksheet = $workbooks.Worksheets.Item($Finding_CSV)
        $sheet = $workbooks.worksheets | Where-Object {$_.Name -eq $WorkSheet_Name}
        if (!($sheet)){
            $worksheet.Name = $WorkSheet_Name
        }
        $TxtConnector = ("TEXT;" + $Finding)
        $Cellref = $Worksheet.Range("A1")
        $Connector = $worksheet.QueryTables.add($TxtConnector,$Cellref)
        $worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $true
        $worksheet.QueryTables.item($Connector.name).TextFileParseType = 1
        $null = $worksheet.QueryTables.item($Connector.name).Refresh()
        $null = $worksheet.QueryTables.item($Connector.name).delete()
        $null = $worksheet.UsedRange.EntireColumn.AutoFit()
        $Finding_CSV++
    }

    $Findings_List | ForEach-Object {Remove-Item $_ -Force}
}

Try {
    $workbooks.SaveAs("$(join-path $OutPutpath -ChildPath $Report_Name)", 51)
    Write-Host "Combined excel spreadsheet saved as $(Join-Path $OutPutpath -ChildPath $Report_Name)"
    Write-Host "Log saved as $LogPath"
    Write-Log $LogPath "Combined excel spreadsheet saved as $(Join-Path $OutPutpath -ChildPath $Report_Name)" "Finish" "Info"
}
Catch{
    $workbooks.SaveAs("$(Join-Path $PSScriptRoot -ChildPath $Report_Name)", 51)
    Write-Host "$OutputPath was not accessible.  Saving to script directory."
    Write-Host "Combined excel spreadsheet saved as $(Join-Path $PSScriptRoot -ChildPath $Report_Name)"
    Write-Host "Log saved as $LogPath"
    Write-Log $LogPath "$OutputPath was not accessible.  Saving to script directory." "Finish" "Info"
    Write-Log $LogPath "Combined excel spreadsheet saved as $(Join-Path $PSScriptRoot -ChildPath $Report_Name)" "Finish" "Info"
}

$workbooks.Close()
$null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbooks)
Write-Log $LogPath "==========[End Logging]==========" "Finish" "Info"

# SIG # Begin signature block
# MIIjzgYJKoZIhvcNAQcCoIIjvzCCI7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCbGkZlXWijdZ8c
# Flxpo55oF82wByjB5F2pW9e7TaOjQqCCHe0wggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# u6ud36J9k9xg5brIqTW2ripCBEEtMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0o
# ZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIy
# MjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# OzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGlt
# ZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1
# BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3z
# nIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZ
# Kz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald6
# 8Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zk
# psUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYn
# LvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIq
# x5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOd
# OqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJ
# TYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJR
# k8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEo
# AA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8G
# A1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYD
# VR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9
# bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0T
# zzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYS
# lm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaq
# T5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl
# 2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1y
# r8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05
# et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6um
# AU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSwe
# Jywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr
# 7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYC
# JtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzga
# oSv27dZ8/DCCBrwwggSkoAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcN
# AQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQTAeFw0yNDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJ
# BgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQg
# VGltZXN0YW1wIDIwMjQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+
# anOf9pUhq5Ywultt5lmjtej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5
# bUlYYSuuM4vQngvQepVHVzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKv
# NminKQPTv/1+kBPgHGlP28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZ
# j75MU/HNmtsgtFjKfITLutLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQ
# rxGFSKx+rDdNMsePW6FLrphfYtk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJ
# pVIfdNsEvxHofBf1BWkadc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk
# 3RIySho1XyHLIAOJfXG5PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8Zh
# qcaDHOoj5KGg4YuiYx3eYm33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXae
# BQjIK13SlnzODdLtuThALhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLts
# VAxFvGqsxUA2Jq/WTjbnNjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0n
# VepsFk8nlcuWfyZLzBaZ0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYD
# VR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaA
# FLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+S
# H3agWzBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3Js
# MIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0Eu
# Y3J0MA0GCSqGSIb3DQEBCwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShP
# z9Pce4FLJl6reNKLkZd5Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyj
# UkKhk3aYx7D8vi2mpU1tKlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6la
# ICtKjPICYYf/qgxACHTvypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv
# /M93748YTeoXU/fFa9hWJQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw
# 23vT6QSgwX5Pq2m0xQ2V6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4
# zvSWzVXpAb9k4Hpvpi6bUe8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTk
# TXpFIEB06nXZrDwhCGED+8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2L
# lTbMcqFSzm4cd0boGhBq7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3
# mgrlgbAW+BzikRVQ3K2YHcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gx
# ftt/8wY3grcc/nS//TVkej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7
# aRZOwqw6pDGCBTcwggUzAgEBMGEwWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu
# Uy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNV
# BAMTDERPRCBJRCBDQS03MgIDE2HVMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQB
# gjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKUd8/tZ
# Q0M8drKuFUNNJJPvDU4hYhnJjS4VDLpqx2mZMA0GCSqGSIb3DQEBAQUABIIBAHg4
# MhLPQhi/9JS+xpdTsdUr6hc/lrEJfuSW76L+qZ+VxXB7b9lFiac9OBRVMUm0SJvh
# y9jsSTKPDiRpCnev1lgI++oJCssEQ/jF1FLLOYkgrMXT0BKkVgQ7WEjAoc1GyjUY
# u73geZCfoiTgVQ+4O05LKhYJdkN/uIcohkxFgRaI5ZNZSA1X6U/R2TO1CLDEG54F
# 1UceC2JI0KXqwkAfSHGDouPQsJjjWLT8JomlKgARtnd+YEUM3MUBksuS/jMKvTsy
# LvuWQ3BgTyVDLTqpzNSC1eCeL7mGynWq8A31DtTQYjO8210VT5rYyAwsIbfExdJ7
# zDuVHyQBX94M9q/8EtqhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5n
# IENBAhALrma8Wrp/lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNDA3MTI1MzUyWjAv
# BgkqhkiG9w0BCQQxIgQgLtD/hLKVP3f88kow72LPXvOUcc/hi0Yih2mQOjruOREw
# DQYJKoZIhvcNAQEBBQAEggIAQGNIuHJ19Kte+YCh03TeFhediRQo7/mdtsOIG2Wk
# vfQDJ/UrurjyOwHTsxL9nbqIw5Z9A6uAXG55Uge/N0bjak8NQrohoqXcrQijxkb1
# FZ8hlQKzNFRqcC2RWjlHgJhgmt5e6+KST+dOhlURZr39iEy7LREI5c5DeCiShtSV
# uiXT7JabX+ctEO9tB0IHwWghS5si6jhf3rfF4sFUVbR/d3SbD/aesDGdn+RIudbu
# y9ZM02xUkX9E2+nV3dymMzrOX7MRczNodeopyQPq5ZLK1MMu+wUQRW+/GVxYeeZI
# eukmjYPHOZ+ZJU677Oz1HpLpt5ooLn/Xp2wGCcqoQteCQnNZwbhLEpSxgWL10Mjq
# BZ/t/xD9Pno8bGe/foQqNlOq2eitnKwc87eBLbGBghIitBHp9UZfg5IVFuIjCIJ2
# HzxVClDgG1iXiXnJosW/Ts7/vE1agvcJ3TQlf8UdUCvrLhocuU4FfgZeuYfH2O8k
# zSvK4hDJAz9+SnAZqHCuciYtvARrQ8qYyi7nH85JeJ/DCY1vw9ykpi6YBiC1Kzvt
# urfAmapFvUn1Vz5m+Fv3UKyjoEWYBYNIPv1yuT6zQHbcq+SohK3a6YQqgom1kfJy
# k5IZM+JpyjAyt8lxYOQ4MzDAHZbEzMa6E83DGNQG6dR5Pi0tBx3PVJG122PnELhX
# Qjw=
# SIG # End signature block
