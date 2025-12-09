##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MS SQL Server 2014 Database
# Version:  V1R7
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

$PSDefaultParameterValues['out-string:width'] = 200

Function Get-V213765 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213765
        STIG ID    : SQL4-00-011200
        Rule ID    : SV-213765r960879_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-DB-000064
        Rule Title : SQL Server must generate Trace or Audit records for organization-defined auditable events.
        DiscussMD5 : E69375F89B30492809807EC889B44D6B
        CheckMD5   : 49B2CC13D8D014C519FADAE8F8DDCAC9
        FixMD5     : FB517D79EFC0E0BCBD0F4E176EBBD845
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $AANames = 'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
            'AUDIT_CHANGE_GROUP',
            'BACKUP_RESTORE_GROUP',
            'DATABASE_CHANGE_GROUP',
            'DATABASE_OBJECT_ACCESS_GROUP',
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OPERATION_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'DBCC_GROUP',
            'FAILED_LOGIN_GROUP',
            'LOGIN_CHANGE_PASSWORD_GROUP',
            'LOGOUT_GROUP',
            'SCHEMA_OBJECT_ACCESS_GROUP',
            'SCHEMA_OBJECT_CHANGE_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OPERATION_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_PRINCIPAL_CHANGE_GROUP',
            'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SERVER_STATE_CHANGE_GROUP',
            'SUCCESSFUL_LOGIN_GROUP',
            'TRACE_CHANGE_GROUP'
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
            'AUDIT_CHANGE_GROUP',
            'BACKUP_RESTORE_GROUP',
            'DATABASE_CHANGE_GROUP',
            'DATABASE_OBJECT_ACCESS_GROUP',
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OPERATION_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'DBCC_GROUP',
            'FAILED_LOGIN_GROUP',
            'LOGIN_CHANGE_PASSWORD_GROUP',
            'LOGOUT_GROUP',
            'SCHEMA_OBJECT_ACCESS_GROUP',
            'SCHEMA_OBJECT_CHANGE_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OPERATION_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_PRINCIPAL_CHANGE_GROUP',
            'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SERVER_STATE_CHANGE_GROUP',
            'SUCCESSFUL_LOGIN_GROUP',
            'TRACE_CHANGE_GROUP'
            );
        "

        $AANamesRC = Compare-Object $AANames $res.audit_action_name
        $AResultSF = $res.audited_result -eq "SUCCESS AND FAILURE"

        If ($res -and !$AANamesRC -and $AResultSF) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation. If there are no locally-defined security tables or procedures, this is not applicable.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND !$AuditExist -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(14, 15, 16, 17, 18, 20, 42, 43, 46, 47, 90, 102, 103, 104,
                       105, 106, 107, 108, 109, 110, 111, 112, 113, 115, 116, 117,
                       118, 128, 129, 130, 131, 132, 133, 134, 135, 152, 153, 162,
                       164, 170, 171, 172, 173, 175, 176, 177, 178, 180)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation. If there are no locally-defined security tables or procedures, this is not applicable.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213766 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213766
        STIG ID    : SQL4-00-011320
        Rule ID    : SV-213766r960882_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : Where SQL Server Audit is in use at the database level, SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited at the database level.
        DiscussMD5 : EC43AE66A02E8FB37FFFF34FE702BF3E
        CheckMD5   : C98BB75E63F1B6C44FDC70CD60F21B57
        FixMD5     : D8ABB798B64CE71DCFDC617537539DB0
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
    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
        where is_state_enabled = 1
    "

    If (!$AuditExist) {
        $Status = "Not_Applicable"
        $FindingDetails = "SQL Server Audit is not in use at the database level, this is not applicable (NA)."
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

Function Get-V213767 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213767
        STIG ID    : SQL4-00-014900
        Rule ID    : SV-213767r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must be monitored to discover unauthorized changes to functions.
        DiscussMD5 : 4E5D33BEA97B8F243A6C87545E556F1B
        CheckMD5   : 3DEDBFB1CB159D7C88B33370FAE9718C
        FixMD5     : 090EF5271C7BE61712CCA6BBC918E7AB
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT name, enabled FROM msdb.dbo.sysjobs
        where name <> 'syspolicy_purge_history'
    "

    If ($res) {
        $FindingDetails = "From the list below identify the job that automatically checks all system and user-defined Functions for being modified.  If such a job exists, mark this check as 'Not a Finding'.  If a timed job or some other method is not implemented to check for Functions being modified, mark this check as 'Open'.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    Else {
        $Status = "Open"
        $FindingDetails = "No custom jobs exist that automatically checks all system and user-defined Functions for being modified."
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

Function Get-V213768 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213768
        STIG ID    : SQL4-00-015100
        Rule ID    : SV-213768r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must be monitored to discover unauthorized changes to triggers.
        DiscussMD5 : 19E73F92288B7003A7647ED45B5F0B93
        CheckMD5   : 902899873F4915F3CEEDDE5FC89404B9
        FixMD5     : 0C77E75B1FEA3907A264EB8047F5E827
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT name, enabled FROM msdb.dbo.sysjobs
        where name <> 'syspolicy_purge_history'
    "

    If ($res) {
        $FindingDetails = "From the list below identify the job that automatically checks all system and user-defined Triggers for being modified.  If such a job exists, mark this check as 'Not a Finding'.  If such a job, or an alternative method of monitoring triggers for modification does not exist, mark this check as 'Open'.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    Else {
        $Status = "Open"
        $FindingDetails = "No custom jobs exist that automatically checks all system and user-defined Triggers for being modified."
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

Function Get-V213769 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213769
        STIG ID    : SQL4-00-015200
        Rule ID    : SV-213769r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must be monitored to discover unauthorized changes to stored procedures.
        DiscussMD5 : F24ACF2255DE127EE8AB4D373EB8074C
        CheckMD5   : 238622B129BCE5992C10A57A5EB4B6F4
        FixMD5     : CBB41AC6E487086ABA2C128E3AD17D20
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT name, enabled FROM msdb.dbo.sysjobs
        where name <> 'syspolicy_purge_history'
    "

    If ($res) {
        $FindingDetails = "From the list below identify the job that monitors for changes to stored procedures.  If such a job exists, mark this check as 'Not a Finding'.  If such a job, or an alternative method of monitoring stored procedures for modification does not exist,  mark this check as 'Open'.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    Else {
        $Status = "Open"
        $FindingDetails = "No custom jobs exist that monitors for changes to stored procedures."
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

Function Get-V213771 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213771
        STIG ID    : SQL4-00-015610
        Rule ID    : SV-213771r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000200
        Rule Title : In a database owned by [sa], or by any other login having administrative privileges at the instance level, the database property TRUSTWORTHY must be OFF.
        DiscussMD5 : 858D9C1CBA1753CDC01F7E80CFFB6D1A
        CheckMD5   : 11B5CD659845EF612A94B8A00B251797
        FixMD5     : 387E745777BC33C701D43C3E90009DB0
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        WITH FixedServerRoles(RoleName) AS
        (
              SELECT 'sysadmin'
              UNION SELECT 'securityadmin'
              UNION SELECT 'serveradmin'
              UNION SELECT 'setupadmin'
              UNION SELECT 'processadmin'
              UNION SELECT 'diskadmin'
              UNION SELECT 'dbcreator'
              UNION SELECT 'bulkadmin'
        )
        SELECT
              DB_NAME() AS [Database],
              SUSER_SNAME(D.owner_sid) AS [Database Owner],
              F.RoleName AS [Fixed Server Role],
              CASE WHEN D.is_trustworthy_on = 1 THEN 'ON' ELSE 'off' END
                    AS [Trustworthy]
        FROM
              FixedServerRoles F
              INNER JOIN sys.databases D ON D.Name = DB_NAME()
        WHERE
              IS_SRVROLEMEMBER(F.RoleName, SUSER_SNAME(D.owner_sid)) = 1
        AND   DB_NAME() <> 'msdb'
        AND   D.is_trustworthy_on = 1;
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "The following databases owned by SA have TRUSTWORTHY improperly set to ON:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
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

Function Get-V213772 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213772
        STIG ID    : SQL4-00-015620
        Rule ID    : SV-213772r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000200
        Rule Title : In a database owned by a login not having administrative privileges at the instance level, the database property TRUSTWORTHY must be OFF unless required and authorized.
        DiscussMD5 : 858D9C1CBA1753CDC01F7E80CFFB6D1A
        CheckMD5   : BD3CAA48647043D3BEF40DAC0DABE6EB
        FixMD5     : 18E188DD591F7FFD013FA1E8AB17A22A
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT
        DB_NAME() AS [Database],
        SUSER_SNAME(D.owner_sid) AS [Database Owner],
        CASE WHEN D.is_trustworthy_on = 1 THEN 'ON' ELSE 'off' END
        AS [Trustworthy]
        FROM
        sys.databases D
        WHERE
        D.[name] = DB_NAME()
        AND DB_NAME() <> 'msdb'
        AND D.is_trustworthy_on = 1
    "
    if ($res) {
        $Status = 'Not_Reviewed'
        $FindingDetails += "DBA, review the system security plan to determine whether the need for TRUSTWORTHY is documented as approved for these databases:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
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

Function Get-V213773 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213773
        STIG ID    : SQL4-00-021210
        Rule ID    : SV-213773r961125_rule
        CCI ID     : CCI-001665
        Rule Name  : SRG-APP-000226-DB-000147
        Rule Title : In the event of a system failure, SQL Server must preserve any information necessary to return to operations with least disruption to mission processes.
        DiscussMD5 : 79982D3778015F0FA769665724B4D351
        CheckMD5   : 254D1EF0948B40EC972BB62298601089
        FixMD5     : 95E39207C085A66A88439BE6628095A1
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT name, enabled FROM msdb.dbo.sysjobs
        where name <> 'syspolicy_purge_history'
    "

    $Recmod = Get-ISQL -ServerInstance $Instance "
        select name, recovery_model_desc
        from sys.databases
    "

    If ($res) {
        $FindingDetails = "From the list below identify the job or jobs that perform backups per SSP.`n$($res | Format-Table -AutoSize| Out-String)"
        $FindingDetails += "Also verify recovery models match your documentation.`n$($Recmod | Format-Table -AutoSize| Out-String)"
        $FindingDetails += "If you have backup jobs and they do not show a pattern of failures; and the database recovery models match your documentation; and you have evidence of annual database recovery, mark this check as 'Not a Finding'."
        $FindingDetails += " If all conditions are not met, mark this check as 'Open'."
    }
    Else {
        $Status = "Open"
        $FindingDetails = "No custom jobs exist that perform backups"
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

Function Get-V213779 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213779
        STIG ID    : SQL4-00-024100
        Rule ID    : SV-213779r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : The Database Master Key must be encrypted by the Service Master Key, where a Database Master Key is required and another encryption method has not been specified.
        DiscussMD5 : E20E1D2CC9839DC27B64F09DFB76F6DD
        CheckMD5   : 1C5FD01A4D392C8AE5E0AC62F51E5577
        FixMD5     : BC25B295DA82CF8E76CE091ECE2A6DFC
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT name
    FROM [master].sys.databases
    WHERE is_master_key_encrypted_by_server = 1
    AND owner_sid <> 1
    AND state = 0;
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the SSP has approved the encryption of these database master keys using the service master keys:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
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

Function Get-V213780 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213780
        STIG ID    : SQL4-00-024200
        Rule ID    : SV-213780r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : Database Master Key passwords must not be stored in credentials within the database.
        DiscussMD5 : EDE5EA77177F1E32F465CDF5484BC80F
        CheckMD5   : 8E21E42521FC9A6C99372943F46DE291
        FixMD5     : 3999F8A6B2D14C45172F747201183A09
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT COUNT(credential_id)
        FROM [master].sys.master_key_passwords
    "
    if ($res.column1 -gt 0) {
        $Status = 'Open'
        $FindingDetails += "Marked as Open because the check query found $($res.column1) master password(s) being stored within the database."
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Marked as NF because the check query found no master passwords being stored within the database."
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

Function Get-V213781 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213781
        STIG ID    : SQL4-00-024300
        Rule ID    : SV-213781r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : Symmetric keys (other than the database master key) must use a DoD certificate to encrypt the key.
        DiscussMD5 : 5BCD73D14BD84F2D910166227A858D71
        CheckMD5   : ED6109EFD5B06A41FA5940A7A5783A33
        FixMD5     : 523F15726A0DE67F4261D30AB268CF4D
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT s.name, k.crypt_type_desc
        FROM sys.symmetric_keys s, sys.key_encryptions k
        WHERE s.symmetric_key_id = k.key_id
        AND s.name <> '##MS_DatabaseMasterKey##'
        AND k.crypt_type IN ('ESKP', 'ESKS')
        ORDER BY s.name, k.crypt_type_desc;
    "
    if ($res) {
        $Status = 'Not_Reviewed'
        $FindingDetails += "DBA, ensure these symmetric keys use DoD PKI certs for encryption and that they are documented in the SSP:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
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

Function Get-V213790 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213790
        STIG ID    : SQL4-00-035800
        Rule ID    : SV-213790r961797_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000494-DB-000344
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is accessed.
        DiscussMD5 : 4DC5E8FDDC9A552CD25442C66A72293E
        CheckMD5   : 58B3FC126D8CBAD883866B61C9431764
        FixMD5     : CF3A90E9ECFD32ED8EB2765B09212CEB
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
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
        where is_state_enabled = 1
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($Auditexist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "
        If ($res) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

        }
        Else {
            $Status = "Open"
            $FindingDetails = "No audit records are generated when categorized information (e.g., classification levels/security levels) is accessed."
            $FindingDetails += "Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level.  If it is not, this is not applicable (NA)."
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $FindingDetails = "A Trace is present. Since Trace does not provide for tracking SELECT statements, it is necessary to provide this tracking at the application level, if Trace is used for audit purposes."
        $FindingDetails += "Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level.  If it is not, this is not applicable (NA)."
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

Function Get-V213791 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213791
        STIG ID    : SQL4-00-035900
        Rule ID    : SV-213791r961797_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000494-DB-000345
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 4B8AA5406C666B4122F61EB9553C240F
        CheckMD5   : 43AFFDA6BD9252311902F861E833BE0F
        FixMD5     : CEF65A41D81675563AAA8FFB69D33907
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
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
        where is_state_enabled = 1
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($Auditexist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "
        If ($res) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

        }
        Else {
            $Status = "Open"
            $FindingDetails = "No audit records are generated when categorized information (e.g., classification levels/security levels) is accessed."
            $FindingDetails += "Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level.  If it is not, this is not applicable (NA)."
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $FindingDetails = "A Trace is present. Since Trace does not provide for tracking SELECT statements, it is necessary to provide this tracking at the application level, if Trace is used for audit purposes."
        $FindingDetails += "Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level.  If it is not, this is not applicable (NA)."
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

Function Get-V213792 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213792
        STIG ID    : SQL4-00-036200
        Rule ID    : SV-213792r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000328
        Rule Title : SQL Server must generate Trace or Audit records when privileges/permissions are modified via locally-defined security objects.
        DiscussMD5 : 8BD6B45B25B07E1F885DC225C3B1A9F6
        CheckMD5   : 06CA9D5475C788785EDC5ED1DB4D10FA
        FixMD5     : 3572B1DFE26BEBBA3F7785CD87229353
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.  Obtain the list of locally-defined security tables, procedures and functions that require tracking.  If there are none, this is not a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(42, 43, 90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the locally-defined security tables for the existence of triggers to raise a custom event on each Update operation.  If such triggers are not present, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.  Obtain the list of locally-defined security tables, procedures and functions that require tracking.  If there are none, this is not a finding.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213793 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213793
        STIG ID    : SQL4-00-036300
        Rule ID    : SV-213793r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000329
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to modify privileges/permissions via locally-defined security objects occur.
        DiscussMD5 : EF04256FD66BF83190C5657CD28B7E5C
        CheckMD5   : 2431A19C546ED1F86D9691CBAE8BBB94
        FixMD5     : 3572B1DFE26BEBBA3F7785CD87229353
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing. Obtain the list of locally-defined security tables, procedures and functions that require tracking.  If there are none, this is not a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(42, 43, 90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the locally-defined security tables for the existence of triggers to raise a custom event on each Update operation.  If such triggers are not present, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213794 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213794
        STIG ID    : SQL4-00-036400
        Rule ID    : SV-213794r961803_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000496-DB-000334
        Rule Title : SQL Server must generate Trace or Audit records when locally-defined security objects are modified.
        DiscussMD5 : B5F2E8EBFA7567485785B421A4ADF035
        CheckMD5   : 22D215E5EEB17A0F820793CB17B6F97C
        FixMD5     : A6AF829790405294C5669C9D3F87FE25
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_CHANGE_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(46, 47, 162, 164)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213795 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213795
        STIG ID    : SQL4-00-036500
        Rule ID    : SV-213795r961803_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000496-DB-000335
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to modify locally-defined security objects occur.
        DiscussMD5 : 88B0B6D464BBF9AF9A8E7AB21EE439C1
        CheckMD5   : 163BF9A57B8EE4DDD8C8497139EDF1B0
        FixMD5     : A6AF829790405294C5669C9D3F87FE25
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_CHANGE_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(46, 47, 162, 164)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213796 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213796
        STIG ID    : SQL4-00-036600
        Rule ID    : SV-213796r961809_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000346
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is created.
        DiscussMD5 : 7FCA8B37D29ADA4F2DD7EC5C9E349080
        CheckMD5   : 363164231C2398D19E08CEEE7EBB397D
        FixMD5     : 8D70BA8BBDE0F7CA45ECDDEDA7EC7162
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the Trace settings, and the triggers on the tables holding categorized information, to determine whether all INSERT actions on these tables are traced, including failed attempts.  If not, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213797 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213797
        STIG ID    : SQL4-00-036650
        Rule ID    : SV-213797r961809_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000346
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is modified.
        DiscussMD5 : 1EE2338DBB2DA66294A4337ACBD0700A
        CheckMD5   : 12FFFB78426D663983A14D613F32D026
        FixMD5     : 346353BAC603495DAC381657FE1551A2
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the triggers on all tables holding categorized information, to determine whether trace events are generated for all UPDATE actions on these tables.  If not, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level.  If it is not, this is not applicable (NA).`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213798 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213798
        STIG ID    : SQL4-00-036800
        Rule ID    : SV-213798r961809_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000347
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to create categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 5611A02A30656063E7A91C42DBC58207
        CheckMD5   : 269CC2FFE28B0B33B5587CC97CD85FE9
        FixMD5     : 8D70BA8BBDE0F7CA45ECDDEDA7EC7162
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the Trace settings, and the triggers on the tables holding categorized information, to determine whether all INSERT actions on these tables are traced, including failed attempts. If not, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213799 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213799
        STIG ID    : SQL4-00-036850
        Rule ID    : SV-213799r961809_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000347
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : C683091EC2BA10245DD6FCF0FF71B21E
        CheckMD5   : 056B02CFC419CBE4187480F5E0CE17FC
        FixMD5     : 346353BAC603495DAC381657FE1551A2
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the Trace settings, and the triggers on the tables holding categorized information, to determine whether all UPDATE actions on these tables are traced, including failed attempts.  If not, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level.  If it is not, this is not applicable (NA).`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213800 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213800
        STIG ID    : SQL4-00-037100
        Rule ID    : SV-213800r961818_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000501-DB-000336
        Rule Title : SQL Server must generate Trace or Audit records when locally-defined security objects are dropped.
        DiscussMD5 : 89E7B9112026B8E9C94BE3E3647F0F31
        CheckMD5   : 35372CFC8C231D723755C773A807A174
        FixMD5     : 6BB04033EEC001884FBBC1AA3118C2A3
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_CHANGE_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(46, 47, 162, 164)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213801 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213801
        STIG ID    : SQL4-00-037200
        Rule ID    : SV-213801r961818_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000501-DB-000337
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to drop locally-defined security objects occur.
        DiscussMD5 : BD6EF0BDB7E4A0ECBCA0026FBE63B2B0
        CheckMD5   : F0E83C088A5E59E58CE531ABE27C85BB
        FixMD5     : 6BB04033EEC001884FBBC1AA3118C2A3
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_CHANGE_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(46, 47, 162, 164)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213802 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213802
        STIG ID    : SQL4-00-037300
        Rule ID    : SV-213802r961821_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000502-DB-000348
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is deleted.
        DiscussMD5 : 89DD77B4CA52B4403E35DC172B115D9E
        CheckMD5   : 0651B6B24A0BECE549432A227400146F
        FixMD5     : 1F4156BD8FF5A297ED8F0A2E625C0E27
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the triggers on all tables holding categorized information, to determine whether trace events are generated for all DELETE actions on these tables.  If not, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213803 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213803
        STIG ID    : SQL4-00-037400
        Rule ID    : SV-213803r961821_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000502-DB-000349
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 8E109A26687674426F124DB6FD5F33E3
        CheckMD5   : F8EB43AC909741B2DECC37C2F924DCC4
        FixMD5     : 1F4156BD8FF5A297ED8F0A2E625C0E27
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the Trace settings, and the triggers on the tables holding categorized information, to determine whether all DELETE actions on these tables are traced, including failed attempts.  If not, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213804 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213804
        STIG ID    : SQL4-00-038100
        Rule ID    : SV-213804r961836_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000507-DB-000356
        Rule Title : SQL Server must generate Trace or Audit records when successful accesses to designated objects occur.
        DiscussMD5 : B424B72B54F63B0E81198AD977EE8E61
        CheckMD5   : F5ACF272964336B7459E5EB17B335C8A
        FixMD5     : 3C9EFD565906379F8741B5785C030B8D
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(42, 43, 90, 162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $FindingDetails = "Trace exists and contains event ids specified in the check text."
            $FindingDetails += "Review the application(s) using the database to verify that all SELECT actions on categorized data are being audited, and that the tracking records are written to the SQL Server Trace used for audit purposes.  If not, this is a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213805 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213805
        STIG ID    : SQL4-00-038200
        Rule ID    : SV-213805r961836_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000507-DB-000357
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful accesses to designated objects occur.
        DiscussMD5 : 15452D59DD99BD0CEB25CC2B351A7151
        CheckMD5   : 70AC920C5DD01FA82AA213B7FFA5D89B
        FixMD5     : 682E48E4CBE0CC53C8B4DEE0082B1BEF
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
    # Corrected a problem with trace events not being identified. Ken Row, 4/7/25, Issue #2194
    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "
    If ($NonDefTrace) {
        $TraceID = $NonDefTrace.id
    }

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
        "

        If ($res -and $res.result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Audit exists however either SCHEMA_OBJECT_ACCESS_GROUP or SUCCESS and FAILURE is missing.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = @(162)

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains the event id specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = "Open"
            $FindingDetails = "Trace exists and does not contain the event id specified in the check text. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V265637 {
    <#
    .DESCRIPTION
        Vuln ID    : V-265637
        STIG ID    : SQL4-00-038300
        Rule ID    : SV-265637r998188_rule
        CCI ID     : CCI-003376
        Rule Name  : SQL4-00-038300
        Rule Title : Microsoft SQL Server products must be a version supported by the vendor.
        DiscussMD5 : A62B17501780D92ECF5A0F54F0183A13
        CheckMD5   : A2FB1D7291777D429B359971758BDE68
        FixMD5     : A07810298CF143FC024991C1F52DE6EB
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
    $AppName = "SQL Server"
    $AppVer = "2014"
    If (Test-IsMSSQLInstalled -Version $AppVer) {
        $Status = "Open"
        $FindingDetails += "Microsoft $($AppName) $($AppVer) is installed. [finding]"
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Microsoft $($AppName) $($AppVer) is not installed."
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDvwvYLwvaO0rXn
# rB9e6Z676atTEEpIQBKEOm3CvcdGFaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCA2LAZPUyfre+7ZakLOsDd8tTWXlqaZZYj6NRCok7cKPjANBgkqhkiG9w0BAQEF
# AASCAQCw4kW2ZmwV2p9uOvc1o4ObmRZesFAwq53o7YKyEcCXIPOwOueLYgZ3TIsb
# VbjHMA6HTVkaNbCq6QmeqEyXiQZ1DeNFatfYyAyCp1WELchyufEfqC/YspQ2Owu/
# NsoBvlVT6QnM+nVgLO6qc/zcvSsXpmQZPT/w8AXcHpMsWG+5eiX7FPXgvd6rDsSN
# yQNUQZrAszvmklLwqH5r8/4ENQ+5l6b+kjXygaeGVT4C0eZmja9meyURNk1YVBRK
# PYkmHC0fX/dSbdYTeYMrLH6PcyTbl4JjgsU3m7MhH7CRT8UQcEMH/YgtEEdSPSxg
# CzK0zNHKn/fel4IQWiKxIRjglNknoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTc1NFowLwYJKoZIhvcNAQkEMSIEINEXHWox85UfWP1lpA4zio5KsFO5
# 6AdNNxekfhoOtLEYMA0GCSqGSIb3DQEBAQUABIICAKvawAifXPTnletPF3rSDPcB
# b75h8VITJfXocTD/fiN3xR4p0fFkfw2Naj2lO1CtHSIj/agoI1U0gKKNK8rHUxcy
# kNSySxDa6fVQjuAyumB/961btw0IxFSw9q+QSBGGBmKcZd+TcJFjtDCs2NHA82os
# /uWFa4ch4oG/fuWIT4xrCwJg3wLa1VR+9Ij+SjUF+ixSpmp5CUWivw6C88GOLx25
# EaR4sD+4/MQfd1fkiNqSaKX8VMq1znjSKf+YTMktVfrkSu12UGWawC8zVcz1Igdz
# A4rpQJ7I+9M8YUN08LzTgCBPmn94XyzbQ82PowGkFkGWrPV7ah6u8vwIvoU0Vg7T
# uH0TQqO8TAI25tI4Pw/GH/VaRSfr8UWHX5g1kpmtTRzklvSknWp5Ur1w40Jpu7GN
# Vsf1JCcXY8g+3i7s3hm+/r5Mgtj8d/ZvKvfKiQaireAZBPBgFFhMDLTx6dli+eBP
# m3WmfTUrxKgD5rkWpiL7NtgcNyvm+aCjR9IQxvvVVx/Cvit45u4eG4qpTlarJD7g
# ECNqTjY3G3QIZA0Bfb1BFjLAiqOBCwpIEjt/BN0rzLRPiI8sbmpRc6aLUQcQUFgb
# MSwkZe3TNIMXaT/H1/UzLZcMYSblgM5X18SAk/HULABOaQZDJWETGvmELQOnU9KZ
# hj3fiNBcDX0ml7d8iaPN
# SIG # End signature block
