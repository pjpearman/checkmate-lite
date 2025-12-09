##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MS SQL Server 2014 Instance
# Version:  V2R4
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

$PSDefaultParameterValues['out-string:width'] = 200

Function Get-V213807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213807
        STIG ID    : SQL4-00-000100
        Rule ID    : SV-213807r960735_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-DB-000031
        Rule Title : The number of concurrent SQL Server sessions for each system account must be limited.
        DiscussMD5 : BD6C0A04BBCFB8C9896628FE1A8CCC99
        CheckMD5   : C15BB091E7C0E0A647151516FF2A8AC9
        FixMD5     : 01A1FF7C9FB6854D44702D972A7EEDFF
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT name, is_disabled FROM master.sys.server_triggers"

    if (!$res) {
        $Status = "Open"
        $FindingDetails = "No triggers are defined."
    }
    else {
        # 20201021 JJS Fixed output of $res
        $FindingDetails = "Confirm there are triggers that limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types. `n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213809
        STIG ID    : SQL4-00-010200
        Rule ID    : SV-213809r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : SQL Server default account [sa] must have its name changed.
        DiscussMD5 : 898D79C643876788A53F3FF350095BA8
        CheckMD5   : 0EBC4A9A40B6BEA5EBD882270611A3DA
        FixMD5     : 39733C6C785C898254835F7499888B09
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
    # Changed to use the passed-in instance name instead of asking SQL for a list of instances. Ken Row, 04/04/25, Issue 2188
    $res = Get-ISQL -ServerInstance $Instance "
        SELECT name
        FROM sys.sql_logins
        WHERE [name] = 'sa'
            OR [principal_id] = 1
    "
    if ($res) {
        if ($res.name -eq 'sa') {
            $FindingDetails += "The SQL Server default account has not been renamed.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    } # if ($res)
    if ($FindingDetails -gt '') {
        $Status = 'Open'
    }
    else {
        $Status = 'NotAFinding'
        $FindingDetails = "The SQL Server default account has been renamed."
    } # if ($FindingDetails -gt '')
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

Function Get-V213810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213810
        STIG ID    : SQL4-00-011300
        Rule ID    : SV-213810r960882_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : Where SQL Server Trace is in use for auditing purposes, SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be traced.
        DiscussMD5 : 005E32DB0BBD59F3A40139118B87C550
        CheckMD5   : 121C9C4FB842104BCF5F067D95BDAC3E
        FixMD5     : F58D3F8423A494A0A63F2438AAD375BE
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

    If (!$NonDefTrace) {
        $Status = "NotAFinding"
        $FindingDetails = "SQL Server Trace is not in use for audit purposes, this is not a finding."
    }
    Else {

        $STIGPermsExist = Get-ISQL -ServerInstance $Instance -Database $Database "
            IF EXISTS (SELECT * FROM sys.objects
            WHERE object_id = OBJECT_ID(N'STIG.server_permissions')
            )
            SELECT '1'
            ELSE
            SELECT '0'
        "
        If ($STIGPermsExist.Column1 -eq '0') {
            $FindingDetails = "A trace is in use, however the STIG.server_permissions view is missing.  Install 'permissions.sql' from the supplemental folder of the SQL 2014 Instance STIG .zip file in order to complete this check."
        }
        If ($STIGPermsExist.Column1 -eq '1') {
            $res = Get-ISQL -ServerInstance $Instance "
            SELECT Grantee, Permission
            FROM
            STIG.server_permissions P
            WHERE
            P.[Permission] IN
            (
            'ALTER TRACE',
            'CREATE TRACE EVENT NOTIFICATION'
            );
        "
        }
        If (!$res) {
            $Status = "NotAFinding"
            $FindingDetails = "A trace is in use, the check query returned nothing.  This is not a finding."
        }
        Else {
            $FindingDetails = "A trace is in use, the check query returned the following.`n$($res | Format-Table -AutoSize| Out-String)"
            $FindingDetails += "
                To see what logins and server roles inherit these permissions from the server roles reported by the previous query, repeat the following for each one:
                SELECT * FROM STIG.members_of_server_role(<server role name>);
                To see all the permissions in effect for a server principal (server role or login):
                SELECT * FROM STIG.server_effective_permissions(<principal name>);
                If designated personnel are not able to configure auditable events, this is a finding.
                If unapproved personnel are able to configure auditable events, this is a finding
            "
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

Function Get-V213811 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213811
        STIG ID    : SQL4-00-011310
        Rule ID    : SV-213811r960882_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : Where SQL Server Audit is in use, SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited at the server level.
        DiscussMD5 : EC43AE66A02E8FB37FFFF34FE702BF3E
        CheckMD5   : 03A0FDCDE849F7DA74224B49EE6B7A3C
        FixMD5     : F5E787175538C27E7EF29FB20542385E
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
        $Status = "NotAFinding"
        $FindingDetails = "SQL Server Audit is not in use, this is not a finding."
    }
    Else {

        $STIGPermsExist = Get-ISQL -ServerInstance $Instance -Database $Database "
            IF EXISTS (SELECT * FROM sys.objects
            WHERE object_id = OBJECT_ID(N'STIG.server_permissions')
            )
            SELECT '1'
            ELSE
            SELECT '0'
        "
        If ($STIGPermsExist.Column1 -eq '0') {
            $FindingDetails = "An audit is in use, however the STIG.server_permissions view is missing.  Install 'permissions.sql' from the supplemental folder of the SQL 2014 Instance STIG .zip file in order to complete this check."
        }
        If ($STIGPermsExist.Column1 -eq '1') {
            $res = Get-ISQL -ServerInstance $Instance -Database $Database "
                SELECT * FROM STIG.server_permissions P
                WHERE
                P.[Permission] IN
                (
                'ALTER ANY SERVER AUDIT',
                'CONTROL SERVER',
                'ALTER ANY DATABASE',
                'CREATE ANY DATABASE' --AND P.Grantee NOT LIKE '##%'
                );
            "
        }
        If (!$res) {
            $Status = "NotAFinding"
            $FindingDetails = "An audit is in use, the check query returned nothing.  This is not a finding."
        }
        Else {
            $FindingDetails = "An audit is in use, the check query returned the following.`n$($res | Format-Table -AutoSize| Out-String)"
            $FindingDetails += "
                To see what logins and server roles inherit these permissions from the server roles reported by the previous query, repeat the following for each one:
                SELECT * FROM STIG.members_of_server_role(<server role name>);
                To see all the permissions in effect for a server principal (server role or login):
                SELECT * FROM STIG.server_effective_permissions(<principal name>);
                If designated personnel are not able to configure auditable events, this is a finding.
                If unapproved personnel are able to configure auditable events, this is a finding
            "
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

Function Get-V213812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213812
        STIG ID    : SQL4-00-011410
        Rule ID    : SV-213812r960885_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-DB-000066
        Rule Title : Where SQL Server Audit is in use, SQL Server must generate audit records when privileges/permissions are retrieved.
        DiscussMD5 : FF6D480324FF4C8B1426EAB7366EF82D
        CheckMD5   : 7BB4B467C1013DF53F9B08D68E41B24E
        FixMD5     : 5CE32D103D386E9FA99F50BCD3D40F33
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

    If (!$AuditExist -AND $NonDefTrace) {
        $Status = "NotAFinding"
        $FindingDetails = "Trace exists and SQL Server Audit is not in use, this is not a finding."
    }
    Else {

        If ($AuditExist) {
            $AuditSOAG = Get-ISQL -ServerInstance $Instance -Database $Database "
                SELECT a.name AS 'AuditName',
                s.name AS 'SpecName',
                d.audit_action_name AS 'ActionName',
                d.audited_result AS 'Result'
                FROM sys.server_audit_specifications s
                JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
            "
            If ($AuditSOAG.Result -eq "SUCCESS AND FAILURE") {
                $Status = "NotAFinding"
                $FindingDetails = "SCHEMA_OBJECT_ACCESS_GROUP is audited for SUCCESS AND FAILURE, this is not a finding.`n$($AuditSOAG | Format-Table -AutoSize| Out-String)"
            }
            Else {
                $FindingDetails = "Audit exists however SCHEMA_OBJECT_ACCESS_GROUP is not audited for SUCCESS AND FAILURE.`n$($AuditExist | Format-Table -AutoSize| Out-String)"
            }
        }

    }
    If (!$AuditExist -AND !$NonDefTrace) {
        $Status = "Open"
        $FindingDetails = "Neither a trace or audit is in use, this is a finding."
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

Function Get-V213813 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213813
        STIG ID    : SQL4-00-011900
        Rule ID    : SV-213813r960894_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-DB-000040
        Rule Title : SQL Server must produce Trace or Audit records containing sufficient information to establish when the events occurred.
        DiscussMD5 : 0976FED1F78F7E7FD6A6B6386982EEA7
        CheckMD5   : 21EF86FD4C63D30825B56B516F84D0AD
        FixMD5     : C2890E194E250EAB70BA09D0DFF6CFC0
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

    If ($AuditExist) {
        $Status = "NotAFinding"
        $FindingDetails = "SQL audit is in use. The server instance, database, schema, and object names are each automatically captured when applicable; this is not a finding."
    }

    If (!$AuditExist -AND !$NonDefTrace) {
        $Status = "Open"
        $FindingDetails = "Neither a trace or audit is in use, this is a finding."
    }
    If (!$AuditExist -AND $NonDefTrace) {
        $TraceID = $NonDefTrace.id
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            WITH
            EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo($TraceID)),
            E AS (SELECT DISTINCT eventid FROM EC)
            SELECT
                E.eventid,
                CASE WHEN EC14.columnid IS NULL THEN 'Start Time (14) missing' ELSE '14 OK' END AS field14,
                CASE WHEN EC15.columnid IS NULL THEN 'End Time (15) missing' ELSE '15 OK' END AS field15
            FROM E E
                LEFT OUTER JOIN EC EC14
                    ON  EC14.eventid = E.eventid
                    AND EC14.columnid = 14
                LEFT OUTER JOIN EC EC15
                    ON  EC15.eventid = E.eventid
                    AND EC15.columnid = 15
            WHERE
                EC14.columnid IS NULL OR EC15.columnid IS NULL;
        "
        If (!$res) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace is in use, nothing returned from the check query. This is not a finding."
        }
        Else {
            $FindingDetails = "Trace is in use however field specifications are missing.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213814 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213814
        STIG ID    : SQL4-00-012000
        Rule ID    : SV-213814r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-DB-000041
        Rule Title : SQL Server must produce Trace or Audit records containing sufficient information to establish where the events occurred.
        DiscussMD5 : 8990274A4EF4EBDA51321115DADD11DC
        CheckMD5   : 6ED245145ED5680F314F28667297C005
        FixMD5     : 1C7347D2AA7B53E1322EF38C1BC5C5FE
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

    If ($AuditExist) {
        $Status = "NotAFinding"
        $FindingDetails = "SQL audit is in use. The server instance, database, schema, and object names are each automatically captured when applicable; this is not a finding."
    }

    If (!$AuditExist -AND !$NonDefTrace) {
        $Status = "Open"
        $FindingDetails = "Neither a trace or audit is in use, this is a finding."
    }

    If (!$AuditExist -AND $NonDefTrace) {
        $TraceID = $NonDefTrace.id
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            WITH
            EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo($TraceID)),
            E AS (SELECT DISTINCT eventid FROM EC)
            SELECT
                E.eventid,
                CASE WHEN EC26.columnid IS NULL THEN 'Server Name (26) missing' ELSE '26 OK' END AS field26,
                CASE WHEN EC35.columnid IS NULL THEN 'Database Name (35) missing' ELSE '35 OK' END AS field35,
                CASE WHEN EC28.columnid IS NULL THEN 'Object Type (28) missing' ELSE '28 OK' END AS field28,
                CASE WHEN EC34.columnid IS NULL THEN 'Object Name (34) missing' ELSE '34 OK' END AS field34,
                CASE WHEN EC37.columnid IS NULL THEN 'Object Owner (37) missing' ELSE '34 OK' END AS field37
            FROM E E
                LEFT OUTER JOIN EC EC26
                    ON  EC26.eventid = E.eventid
                    AND EC26.columnid = 26
                LEFT OUTER JOIN EC EC35
                    ON  EC35.eventid = E.eventid
                    AND EC35.columnid = 35
                LEFT OUTER JOIN EC EC28
                    ON  EC28.eventid = E.eventid
                    AND EC28.columnid = 28
                LEFT OUTER JOIN EC EC34
                    ON  EC34.eventid = E.eventid
                    AND EC34.columnid = 34
                LEFT OUTER JOIN EC EC37
                    ON  EC37.eventid = E.eventid
                    AND EC37.columnid = 37
            WHERE
                EC26.columnid IS NULL OR EC35.columnid IS NULL OR EC28.columnid IS NULL OR EC34.columnid IS NULL OR EC37.columnid IS NULL;
        "
        If (!$res) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace is in use, nothing returned from the check query. This is not a finding."
        }
        Else {
            $FindingDetails = "Trace is in use however field specifications are missing.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213815 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213815
        STIG ID    : SQL4-00-012100
        Rule ID    : SV-213815r960900_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098-DB-000042
        Rule Title : SQL Server must produce Trace or Audit records containing sufficient information to establish the sources (origins) of the events.
        DiscussMD5 : 1413DB1449DDEDC2AAB14423D175A7AB
        CheckMD5   : 0742E7496F643914621F5C1594B43C4F
        FixMD5     : 4586E37B5F4ADA1C8CD78EC8245C2D9A
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

    If ($AuditExist) {
        $Status = "NotAFinding"
        $FindingDetails = "SQL audit is in use. This is not a finding."
    }

    If (!$AuditExist -AND !$NonDefTrace) {
        $Status = "Open"
        $FindingDetails = "Neither a trace or audit is in use, this is a finding."
    }
    If (!$AuditExist -AND $NonDefTrace) {
        $TraceID = $NonDefTrace.id
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            WITH
            EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo($TraceID)),
            E AS (SELECT DISTINCT eventid FROM EC)
            SELECT
                E.eventid,
                CASE WHEN EC6.columnid IS NULL THEN 'NT User Name (6) missing' ELSE '6 OK' END AS field26,
                CASE WHEN EC7.columnid IS NULL THEN 'NT Domain Name (7) missing' ELSE '7 OK' END AS field7,
                CASE WHEN EC8.columnid IS NULL THEN 'Host Name (8) missing' ELSE '8 OK' END AS field8,
                CASE WHEN EC9.columnid IS NULL THEN 'Client Process ID (9) missing' ELSE '9 OK' END AS field9,
                CASE WHEN EC10.columnid IS NULL THEN 'Application Name (10) missing' ELSE '10 OK' END AS field10,
                CASE WHEN EC11.columnid IS NULL THEN 'Login Name (11) missing' ELSE '11 OK' END AS field11,
                CASE WHEN EC12.columnid IS NULL THEN 'SPID (12) missing' ELSE '12 OK' END AS field12,
                CASE WHEN EC40.columnid IS NULL THEN 'DB User Name (40) missing' ELSE '40 OK' END AS field40,
                CASE WHEN EC41.columnid IS NULL THEN 'Login SID (41) missing' ELSE '41 OK' END AS field41
            FROM E E
                LEFT OUTER JOIN EC EC6
                    ON  EC6.eventid = E.eventid
                    AND EC6.columnid = 6
                LEFT OUTER JOIN EC EC7
                    ON  EC7.eventid = E.eventid
                    AND EC7.columnid = 7
                LEFT OUTER JOIN EC EC8
                    ON  EC8.eventid = E.eventid
                    AND EC8.columnid = 8
                LEFT OUTER JOIN EC EC9
                    ON  EC9.eventid = E.eventid
                    AND EC9.columnid = 9
                LEFT OUTER JOIN EC EC10
                    ON  EC10.eventid = E.eventid
                    AND EC10.columnid = 10
                LEFT OUTER JOIN EC EC11
                    ON  EC11.eventid = E.eventid
                    AND EC11.columnid = 11
                LEFT OUTER JOIN EC EC12
                    ON  EC12.eventid = E.eventid
                    AND EC12.columnid = 12
                LEFT OUTER JOIN EC EC40
                    ON  EC40.eventid = E.eventid
                    AND EC40.columnid = 40
                LEFT OUTER JOIN EC EC41
                    ON  EC41.eventid = E.eventid
                    AND EC41.columnid = 41
            WHERE
                EC6.columnid IS NULL OR EC7.columnid IS NULL OR EC8.columnid IS NULL OR EC9.columnid IS NULL
                OR EC10.columnid IS NULL OR EC11.columnid IS NULL OR EC12.columnid IS NULL
                OR EC40.columnid IS NULL OR EC41.columnid IS NULL;
        "
        If (!$res) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace is in use, nothing returned from the check query. This is not a finding."
        }
        Else {
            $FindingDetails = "Trace is in use however field specifications are missing.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213816 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213816
        STIG ID    : SQL4-00-012200
        Rule ID    : SV-213816r960903_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-DB-000043
        Rule Title : SQL Server must produce Trace or Audit records containing sufficient information to establish the outcome (success or failure) of the events.
        DiscussMD5 : C2DBEAF9663A3D282C464F9CD9083CE8
        CheckMD5   : 44DEB2294FF9FDAB39517CE23C26CA27
        FixMD5     : 94F5B7A6081DED345F622F1F5174A20C
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

    If ($AuditExist) {
        $Status = "NotAFinding"
        $FindingDetails = "SQL audit is in use. The Succeeded column is populated for all relevant events:  this is not a finding."
    }

    If (!$AuditExist -AND !$NonDefTrace) {
        $Status = "Open"
        $FindingDetails = "Neither a trace or audit is in use, this is a finding."
    }
    If (!$AuditExist -AND $NonDefTrace) {
        $TraceID = $NonDefTrace.id
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            WITH
            EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo($TraceID)),
            E AS (SELECT DISTINCT eventid FROM EC)
            SELECT
                E.eventid,
                CASE WHEN EC23.columnid IS NULL THEN 'Success (successful use of permissions) (23) missing' ELSE '23 OK' END AS field23,
                CASE WHEN EC30.columnid IS NULL THEN 'State (30) missing' ELSE '30 OK' END AS field30,
                CASE WHEN EC31.columnid IS NULL THEN 'Error (31) missing' ELSE '31 OK' END AS field31
            FROM E E
                LEFT OUTER JOIN EC EC23
                    ON  EC23.eventid = E.eventid
                    AND EC23.columnid = 23
                LEFT OUTER JOIN EC EC30
                    ON  EC30.eventid = E.eventid
                    AND EC30.columnid = 30
                LEFT OUTER JOIN EC EC31
                    ON  EC31.eventid = E.eventid
                    AND EC31.columnid = 31
            WHERE
                EC23.columnid IS NULL OR EC30.columnid IS NULL OR EC31.columnid IS NULL;
        "
        If (!$res) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace is in use, nothing returned from the check query. This is not a finding."
        }
        Else {
            $FindingDetails = "Trace is in use however field specifications are missing.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213817 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213817
        STIG ID    : SQL4-00-012300
        Rule ID    : SV-213817r960906_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-DB-000201
        Rule Title : SQL Server must produce Trace or Audit records containing sufficient information to establish the identity of any user/subject associated with the event.
        DiscussMD5 : FF4665FE5D5080C053B09EF48A424865
        CheckMD5   : 2DB421F18B378075A7F26812629DF4FB
        FixMD5     : 94F5B7A6081DED345F622F1F5174A20C
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

    If ($AuditExist) {
        $Status = "NotAFinding"
        $FindingDetails = "SQL audit is in use. The Principal Name columns are populated for all relevant events:  this is not a finding."
    }

    If (!$AuditExist -AND !$NonDefTrace) {
        $Status = "Open"
        $FindingDetails = "Neither a trace or audit is in use, this is a finding."
    }
    If (!$AuditExist -AND $NonDefTrace) {
        $TraceID = $NonDefTrace.id
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            WITH
            EC AS (SELECT eventid, columnid FROM sys.fn_trace_geteventinfo($TraceID)),
            E AS (SELECT DISTINCT eventid FROM EC)
            SELECT
                E.eventid,
                CASE WHEN EC6.columnid IS NULL THEN 'NT User Name (6) missing' ELSE '6 OK' END AS field26,
                CASE WHEN EC7.columnid IS NULL THEN 'NT Domain Name (7) missing' ELSE '7 OK' END AS field7,
                CASE WHEN EC8.columnid IS NULL THEN 'Host Name (8) missing' ELSE '8 OK' END AS field8,
                CASE WHEN EC11.columnid IS NULL THEN 'Login Name (11) missing' ELSE '11 OK' END AS field11,
                CASE WHEN EC40.columnid IS NULL THEN 'DB User Name (40) missing' ELSE '40 OK' END AS field40,
                CASE WHEN EC41.columnid IS NULL THEN 'Login SID (41) missing' ELSE '41 OK' END AS field41
            FROM E E
                LEFT OUTER JOIN EC EC6
                    ON  EC6.eventid = E.eventid
                    AND EC6.columnid = 6
                LEFT OUTER JOIN EC EC7
                    ON  EC7.eventid = E.eventid
                    AND EC7.columnid = 7
                LEFT OUTER JOIN EC EC8
                    ON  EC8.eventid = E.eventid
                    AND EC8.columnid = 8
                LEFT OUTER JOIN EC EC11
                    ON  EC11.eventid = E.eventid
                    AND EC11.columnid = 11
                LEFT OUTER JOIN EC EC40
                    ON  EC40.eventid = E.eventid
                    AND EC40.columnid = 40
                LEFT OUTER JOIN EC EC41
                    ON  EC41.eventid = E.eventid
                    AND EC41.columnid = 41
            WHERE
                EC6.columnid IS NULL OR EC7.columnid IS NULL OR EC8.columnid IS NULL
                OR EC11.columnid IS NULL OR EC40.columnid IS NULL OR EC41.columnid IS NULL;
        "
        If (!$res) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace is in use, nothing returned from the check query. This is not a finding."
        }
        Else {
            $FindingDetails = "Trace is in use however field specifications are missing.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213819
        STIG ID    : SQL4-00-013000
        Rule ID    : SV-213819r960915_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-APP-000109-DB-000049
        Rule Title : Unless it has been determined that availability is paramount, SQL Server must shut down upon the failure of an Audit, or a Trace used for auditing purposes, to include the unavailability of space for more audit/trace log records.
        DiscussMD5 : 40DDBCE3283C60B0926683E0278A3FC2
        CheckMD5   : 5A270623E24092EEBA2123576D32FE7C
        FixMD5     : BB21A67F8E3292E8C4D06F38620B4EA3
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
        select name, on_failure_desc from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($AuditExist) {
        If ($AuditExist.on_failure_desc -eq "SHUTDOWN SERVER INSTANCE") {
            $Status = "NotAFinding"
            $FindingDetails = "STIG_AUDIT is in use and is configured to shutdown on failure.`n$($AuditExist | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $FindingDetails = "STIG_AUDIT is in use and is NOT configured to shutdown on failure. If the system documentation indicates that availability takes precedence over audit trail completeness, this is not applicable (NA).`n$($AuditExist | Format-Table -AutoSize | Out-String)"
        }
    }

    If ($NonDefTrace) {
        If ($NonDefTrace.is_shutdown -eq "True") {
            $Status = "NotAFinding"
            $FindingDetails = "This trace is configured to shutdown on failure.`n$($NonDefTrace | Select-Object id, status, is_shutdown | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $FindingDetails = "Verify the trace is used for audits.  This trace is NOT configured to shutdown on failure. If the system documentation indicates that availability takes precedence over audit trail completeness, this is not applicable (NA).`n$($NonDefTrace | Format-Table -AutoSize | Out-String)"
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

Function Get-V213820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213820
        STIG ID    : SQL4-00-013600
        Rule ID    : SV-213820r960930_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-DB-000059
        Rule Title : The audit information produced by SQL Server must be protected from unauthorized read access.
        DiscussMD5 : C1FA7110BD2ABC32665BB12002BAB21D
        CheckMD5   : 0EAA757A43DB05614D728003881E44BD
        FixMD5     : AEE8FA2A19A5C4ED688E761DB659AB48
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
    # Changed to use the passed-in instance name instead of asking SQL for a list of instances. Ken Row, 04/04/25, Issue 2188

    $NonDefTrace = Get-ISQL -ServerInstance $Instance -Database $Database "
        select * from sys.traces
        where is_default = 0 AND status = 1
    "

    $AuditExist = Get-ISQL -ServerInstance $Instance -Database $Database "
        select name, on_failure_desc from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($NonDefTrace) {
        $Status = "NotAFinding"
        $FindingDetails = "Trace is in use, SQL Server creates each trace file with a standard set of permissions, overriding the folder permissions. It grants full control to OWNER RIGHTS, Administrators, and <SQL Server Instance name>.  Since this is not configurable, this is not a finding."
    }

    If ($AuditExist) {
        $authSQLSVC = @('FullControl')
        $authSSASVC = @('ReadAndExecute', 'Write')

        $hashAuth = @{
            'BUILTIN\Administrators'         = @('Read')
            'NT Service\MSSQL$<INSTANCE>'    = $authSQLSVC
            'NT Service\SQLAgent$<INSTANCE>' = $authSSASVC
        }
        # The MSSQL STIG doesn't say these are acceptable, but they do seem to be bestowed by MSSQL, so should also not be a finding:
        $auditAuth = @{
            #    'BUILTIN\Administrators'         = @('FullControl')
            #    'NT AUTHORITY\SYSTEM'            = @('FullControl')
        }

        $iDirCnt = 0
        $sDirList = ''

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@ServiceName as InstanceName"
        $sInstance = $res.InstanceName # Will err if there is no $res, and that's OK.

        # But we just want the service accounts used by this particular instance
        $myhash = $hashAuth + @{} # the empty set forces the array to duplicate, not just update its pointer

        # First add accounts for the SQL Service
        $sServName = 'MSSQLSERVER'
        if ($sInstance -ne $sServName) {
            $sServName = "mssql`$$sInstance"
        } # service name will either be mssqlserver or mssql$sqlnn
        $sname = (Get-CimInstance win32_service | Where-Object name -EQ $sServName).startname
        $myhash[$sname] = $authSQLSVC # add authorizations for the account on the service
        $sname = "NT SERVICE\MSSQL`$$sInstance"
        $myhash[$sname] = $authSQLSVC # also add authorizations for the "NT SERVICE" account that MSSQL creates

        # Add accounts for the SQL Agent
        $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ "SQLAgent`$$sInstance")  # at some point we need code for SQLAgent on a default instance
        if ($ssasrv) {
            $sname = $ssasrv.startname
            $myhash[$sname] = $authSSASVC
            $sname = "NT SERVICE\SQLAgent`$$sInstance"
            $myhash[$sname] = $authSSASVC
        }

        $paths = Get-ISQL -ServerInstance $Instance "select log_file_path from sys.server_file_audits"
        if ($paths) {
            foreach ($path in $paths.log_file_path) {
                $iDirCnt += 1
                $sDir = $path -replace '\\$'
                $SearchDir = "$sDir\*.sqlaudit"

                $pathHash = $myhash += @{}
                foreach ($k in $auditAuth.Keys) {
                    $pathHash[$k] = $auditAuth[$k]
                }
                $sDirList += "  $SearchDir`n";
                Get-Acl $SearchDir -ErrorAction SilentlyContinue | Select-Object access -Unique | ForEach-Object {
                    $FindingDetails += Get-AccessProblem -CurrentAuthorizations $_.access -AllowedAuthorizations $pathHash -FilePath $SearchDir -InstanceName $sInstance
                }

            } # foreach ($path in $paths.path)
        } # if ($paths)

        # Interpret results...
        if ($FindingDetails -gt '') {
            $Status = "Open"
        }
        else {
            $Status = "NotAFinding"
            if ($iDirCnt -eq 0) {
                $FindingDetails = "No audit directories were found on this host."
            }
            else {
                $FindingDetails = "The audit files in the following directories were checked and found to have proper authorizations:`n`n$sDirList"
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

Function Get-V213821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213821
        STIG ID    : SQL4-00-013700
        Rule ID    : SV-213821r960933_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-APP-000119-DB-000060
        Rule Title : The audit information produced by SQL Server must be protected from unauthorized modification.
        DiscussMD5 : 56C246FD25088092F5302FD20FA1B440
        CheckMD5   : C873A77E681803902FC6C22969E714D1
        FixMD5     : 63F7D37721EE10D313AFC6C1B1BC5955
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
        select name, on_failure_desc from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($NonDefTrace) {
        $Status = "NotAFinding"
        $FindingDetails = "Trace is in use, SQL Server creates each trace file with a standard set of permissions, overriding the folder permissions. It grants full control to OWNER RIGHTS, Administrators, and <SQL Server Instance name>.  Since this is not configurable, this is not a finding."
    }
    Else {
        $authSQLSVC = @('FullControl')
        $authSSASVC = @('ReadAndExecute', 'Write')

        $hashAuth = @{
            'BUILTIN\Administrators'         = @('Read')
            'NT Service\MSSQL$<INSTANCE>'    = $authSQLSVC
            'NT Service\SQLAgent$<INSTANCE>' = $authSSASVC
        }
        # The MSSQL STIG doesn't say these are acceptable, but they do seem to be bestowed by MSSQL, so should also not be a finding:
        $auditAuth = @{
            #    'BUILTIN\Administrators'         = @('FullControl')
            #    'NT AUTHORITY\SYSTEM'            = @('FullControl')
        }

        $iDirCnt = 0
        $sDirList = ''

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@ServiceName as InstanceName"
        $sInstance = $res.InstanceName # Will err if there is no $res, and that's OK.


        # But we just want the service accounts used by this particular instance
        $myhash = $hashAuth + @{} # the empty set forces the array to duplicate, not just update its pointer

        # First add accounts for the SQL Service
        $sServName = 'MSSQLSERVER'
        if ($sInstance -ne $sServName) {
            $sServName = "mssql`$$sInstance"
        } # service name will either be mssqlserver or mssql$sqlnn
        $sname = (Get-CimInstance win32_service | Where-Object name -EQ $sServName).startname
        $myhash[$sname] = $authSQLSVC # add authorizations for the account on the service
        $sname = "NT SERVICE\MSSQL`$$sInstance"
        $myhash[$sname] = $authSQLSVC # also add authorizations for the "NT SERVICE" account that MSSQL creates

        # Add accounts for the SQL Agent
        $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ "SQLAgent`$$sInstance")  # at some point we need code for SQLAgent on a default instance
        if ($ssasrv) {
            $sname = $ssasrv.startname
            $myhash[$sname] = $authSSASVC
            $sname = "NT SERVICE\SQLAgent`$$sInstance"
            $myhash[$sname] = $authSSASVC
        }

        $paths = Get-ISQL -ServerInstance $Instance "select log_file_path from sys.server_file_audits"
        if ($paths) {
            foreach ($path in $paths.log_file_path) {
                $iDirCnt += 1
                $sDir = $path -replace '\\$'
                $SearchDir = "$sDir\*.sqlaudit"

                $pathHash = $myhash += @{}
                foreach ($k in $auditAuth.Keys) {
                    $pathHash[$k] = $auditAuth[$k]
                }
                $sDirList += "  $SearchDir`n";
                Get-Acl $SearchDir -ErrorAction SilentlyContinue | Select-Object access -Unique | ForEach-Object {
                    $FindingDetails += Get-AccessProblem -CurrentAuthorizations $_.access -AllowedAuthorizations $pathHash -FilePath $SearchDir -InstanceName $sInstance
                }

            } # foreach ($path in $paths.path)
        } # if ($paths)

        # Interpret results...
        if ($FindingDetails -gt '') {
            $Status = "Open"
        }
        else {
            $Status = "NotAFinding"
            if ($iDirCnt -eq 0) {
                $FindingDetails = "No audit directories were found on this host."
            }
            else {
                $FindingDetails = "The audit files in the following directories were checked and found to have proper authorizations:`n`n$sDirList"
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

Function Get-V213822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213822
        STIG ID    : SQL4-00-013800
        Rule ID    : SV-213822r960936_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-DB-000061
        Rule Title : The audit information produced by SQL Server must be protected from unauthorized deletion.
        DiscussMD5 : 58681C376C295C1E140371F30094F88C
        CheckMD5   : 04D53C5EE227CBCD0E1509ED6F3F6E37
        FixMD5     : 06D8FDEFA1D239C1C0D763BFBB9C3DF9
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
        select name, on_failure_desc from sys.server_audits
    "

    If (!$NonDefTrace -AND !$AuditExist) {
        $Status = "Open"
        $FindingDetails = "Neither SQL Server Trace or Audit is in use for audit purposes, this is a finding."
    }

    If ($NonDefTrace) {
        $Status = "NotAFinding"
        $FindingDetails = "Trace is in use, SQL Server creates each trace file with a standard set of permissions, overriding the folder permissions. It grants full control to OWNER RIGHTS, Administrators, and <SQL Server Instance name>.  Since this is not configurable, this is not a finding."
    }
    Else {
        $authSQLSVC = @('FullControl')
        $authSSASVC = @('ReadAndExecute', 'Write')

        $hashAuth = @{
            'BUILTIN\Administrators'         = @('Read')
            'NT Service\MSSQL$<INSTANCE>'    = $authSQLSVC
            'NT Service\SQLAgent$<INSTANCE>' = $authSSASVC
        }
        # The MSSQL STIG doesn't say these are acceptable, but they do seem to be bestowed by MSSQL, so should also not be a finding:
        $auditAuth = @{
            #    'BUILTIN\Administrators'         = @('FullControl')
            #    'NT AUTHORITY\SYSTEM'            = @('FullControl')
        }

        $iDirCnt = 0
        $sDirList = ''

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@ServiceName as InstanceName"
        $sInstance = $res.InstanceName # Will err if there is no $res, and that's OK.

        # But we just want the service accounts used by this particular instance
        $myhash = $hashAuth + @{} # the empty set forces the array to duplicate, not just update its pointer

        # First add accounts for the SQL Service
        $sServName = 'MSSQLSERVER'
        if ($sInstance -ne $sServName) {
            $sServName = "mssql`$$sInstance"
        } # service name will either be mssqlserver or mssql$sqlnn
        $sname = (Get-CimInstance win32_service | Where-Object name -EQ $sServName).startname
        $myhash[$sname] = $authSQLSVC # add authorizations for the account on the service
        $sname = "NT SERVICE\MSSQL`$$sInstance"
        $myhash[$sname] = $authSQLSVC # also add authorizations for the "NT SERVICE" account that MSSQL creates

        # Add accounts for the SQL Agent
        $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ "SQLAgent`$$sInstance")  # at some point we need code for SQLAgent on a default instance
        if ($ssasrv) {
            $sname = $ssasrv.startname
            $myhash[$sname] = $authSSASVC
            $sname = "NT SERVICE\SQLAgent`$$sInstance"
            $myhash[$sname] = $authSSASVC
        }

        $paths = Get-ISQL -ServerInstance $Instance "select log_file_path from sys.server_file_audits"
        if ($paths) {
            foreach ($path in $paths.log_file_path) {
                $iDirCnt += 1
                $sDir = $path -replace '\\$'
                $SearchDir = "$sDir\*.sqlaudit"

                $pathHash = $myhash += @{}
                foreach ($k in $auditAuth.Keys) {
                    $pathHash[$k] = $auditAuth[$k]
                }
                $sDirList += "  $SearchDir`n";
                Get-Acl $SearchDir -ErrorAction SilentlyContinue | Select-Object access -Unique | ForEach-Object {
                    $FindingDetails += Get-AccessProblem -CurrentAuthorizations $_.access -AllowedAuthorizations $pathHash -FilePath $SearchDir -InstanceName $sInstance
                }

            } # foreach ($path in $paths.path)
        } # if ($paths)

        # Interpret results...
        if ($FindingDetails -gt '') {
            $Status = "Open"
        }
        else {
            $Status = "NotAFinding"
            if ($iDirCnt -eq 0) {
                $FindingDetails = "No audit directories were found on this host."
            }
            else {
                $FindingDetails = "The audit files in the following directories were checked and found to have proper authorizations:`n`n$sDirList"
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

Function Get-V213823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213823
        STIG ID    : SQL4-00-013900
        Rule ID    : SV-213823r960939_rule
        CCI ID     : CCI-001493
        Rule Name  : SRG-APP-000121-DB-000202
        Rule Title : Audit tools used in, or in conjunction with, SQL Server must be protected from unauthorized access.
        DiscussMD5 : F71B9F9E548A98B1AAD9ECCF2C2DF02F
        CheckMD5   : 2D084AB3E21572E4E21BA7246A6734A6
        FixMD5     : FFE3D012BA4247B9305C967BBDEDB31D
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
        SELECT @@servername as instance,
    login.name, perm.permission_name, perm.state_desc
    FROM sys.server_permissions perm
    JOIN sys.server_principals login
    ON perm.grantee_principal_id = login.principal_id
    WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE')
    and login.name not like '##MS_%'"
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following are documented in the SSP as authorized to access audits:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
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

Function Get-V213828 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213828
        STIG ID    : SQL4-00-015400
        Rule ID    : SV-213828r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000198
        Rule Title : SQL Server software installation account(s) must be restricted to authorized users.
        DiscussMD5 : F5A20E7D777F09C30BDDF9567C3B1562
        CheckMD5   : 36FF96234324C5E0C90ACE7F0FC09E1F
        FixMD5     : CEBCC4812F6E6B5825754E425B6C3431
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
    # Fixed 'Failed to compare two elements in the array.'  Ken Row, 04/07/25, Issue #2195
    $InstallAccounts = (
        Get-ChildItem "C:\program files\Microsoft SQL Server\*\setup bootstrap\log" -Recurse -Include *.log | Select-String -Pattern 'LogonUser = '
    ) -replace '^.*LogonUser = ' -replace 'SYSTEM', 'SYSTEM (Windows Update)' | Sort-Object -Unique | Out-String

    $FindingDetails = "Verify the following account/s are documented as authorized to install and update SQL Server.`n$($InstallAccounts | Format-Table -AutoSize| Out-String)"

    $LocalUsers = Get-LocalUser
    $GroupMemberList = Get-LocalGroup | ForEach-Object {
      $group = $_.Name
      $(
        try {
          Get-LocalGroupMember -Group $group -ErrorAction Stop
        } catch {
          Get-CimInstance -classname win32_group -filter "name = '${group}'" | Get-CimAssociatedInstance -Association win32_groupuser
        }
      ) | Select-Object @{n='GroupName'; e={$group}}, Name, Sid
    }
    $LocalUserGroups = $GroupMemberList | Where-Object SID -in $Localusers.sid.value | select Name, GroupName

    $FindingDetails += "Check OS settings to determine whether users are restricted from accessing SQL Server objects and data they are not authorized to access.`n$($LocalUserGroups | Format-Table -AutoSize| Out-String)"
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

Function Get-V213829 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213829
        STIG ID    : SQL4-00-015500
        Rule ID    : SV-213829r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000199
        Rule Title : Database software directories, including SQL Server configuration files, must be stored in dedicated directories, separate from the host OS and other applications.
        DiscussMD5 : 18AFC31B2C84A1C98CA7EF16E78BDE42
        CheckMD5   : 683F50D25B3F3C76BFB5A4B8F14AB9EF
        FixMD5     : C67C7931EA6FABA14E1301689487A742
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
    $windir = $env:windir -replace '\\$'

    $rootdir = $(Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT value_data
            FROM master.sys.dm_server_registry
        where value_name = 'ImagePath'" | Where-Object value_data -Like '*sqlservr*'
            ).value_data -replace '\\Binn\\sqlservr.exe.*$', '' -replace '^"', ''

    $FindingDetails += "Windows Directory: $windir`n"
    $FindingDetails += "SQL Root Directory: $rootdir`n`n"

    if ($rootdir -like "$windir\*") {
        $Status = "Open"
        $FindingDetails += "SQL appears to be installed within the Windows directory.:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    elseif ($rootdir -match '^[a-z]:\\(program *files\\)?m(icro)?s(oft)? ?sql ?server') {
        $Status = "Not_Reviewed"
        $FindingDetails += "SQL appears to be installed in a directory of its own. Verify only applications that are required for the functioning and administration, not use, of SQL Server are located in the same directory node as the SQL Server software libraries."
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

Function Get-V213830 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213830
        STIG ID    : SQL4-00-016200
        Rule ID    : SV-213830r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000090
        Rule Title : SQL Server must have the publicly available Northwind sample database removed.
        DiscussMD5 : D0540EBE11551DAEB46C02E263D09C66
        CheckMD5   : 4E9A778FD54D0C87EC213670671ED295
        FixMD5     : C1BAF6032A1927569BAFA966320F3603
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
        select @@SERVERNAME as InstanceName
            , name AS DatabaseName
            FROM sys.databases
        WHERE name IN (
                'pubs'
                , 'Northwind'
                , 'AdventureWorks'
                , 'WorldwideImporters'
                )
        ORDER BY 1, 2
        "
    if ($res) {
        $Status = "Open"
        $FindingDetails = "The following demonstration/sample databases should not exist on a production server:`n$($res | Format-Table | Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No demonstration or sample databases were found."
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

Function Get-V213831 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213831
        STIG ID    : SQL4-00-016300
        Rule ID    : SV-213831r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000090
        Rule Title : SQL Server must have the publicly available pubs sample database removed.
        DiscussMD5 : 40437A989C0CC2A06ECB69A7F649B3BE
        CheckMD5   : F32F6DC6CF9DFC11ABA1BDA8A279AA50
        FixMD5     : A86B774DCDE6ED85A4748EC54925D8D9
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
        select @@SERVERNAME as InstanceName
            , name AS DatabaseName
            FROM sys.databases
        WHERE name IN (
                'pubs'
                , 'Northwind'
                , 'AdventureWorks'
                , 'WorldwideImporters'
                )
        ORDER BY 1, 2
        "
    if ($res) {
        $Status = "Open"
        $FindingDetails = "The following demonstration/sample databases should not exist on a production server:`n$($res | Format-Table | Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No demonstration or sample databases were found."
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

Function Get-V213832 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213832
        STIG ID    : SQL4-00-016310
        Rule ID    : SV-213832r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000090
        Rule Title : SQL Server must have the publicly available AdventureWorks sample database removed.
        DiscussMD5 : 351A487CA2C7613C0B1C57A9E35D54AC
        CheckMD5   : C9261BD3974A5E419E06BDE2767DB6B6
        FixMD5     : 2E9D8141A1F04746FF393A42DEB7D0D6
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
        select @@SERVERNAME as InstanceName
            , name AS DatabaseName
            FROM sys.databases
        WHERE name IN (
                'pubs'
                , 'Northwind'
                , 'AdventureWorks'
                , 'WorldwideImporters'
                )
        ORDER BY 1, 2
        "
    if ($res) {
        $Status = "Open"
        $FindingDetails = "The following demonstration/sample databases should not exist on a production server:`n$($res | Format-Table | Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No demonstration or sample databases were found."
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

Function Get-V213834 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213834
        STIG ID    : SQL4-00-016600
        Rule ID    : SV-213834r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the SQL Server Reporting Services (SSRS) software component removed if it is unused.
        DiscussMD5 : 4F1C42BB2DFEAD163054D6382568F2C6
        CheckMD5   : FFF230C7187C1E331C79F17F6C8DD2D3
        FixMD5     : 253732B763222F35AC7BB3E8E6E94A7E
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Reporting Services") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Reporting Services appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Reporting Services is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213835 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213835
        STIG ID    : SQL4-00-016700
        Rule ID    : SV-213835r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the SQL Server Integration Services (SSIS) software component removed if it is unused.
        DiscussMD5 : BD6B58E7CD9C917378646E7E6882693E
        CheckMD5   : 968AF6DF0473C096A84F06AE6138B2B5
        FixMD5     : A85A6D7074F455961DA22A188A21A52A
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Integration Services") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Integration Services appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Integration Services is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213836 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213836
        STIG ID    : SQL4-00-016800
        Rule ID    : SV-213836r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the SQL Server Analysis Services (SSAS) software component removed if it is unused.
        DiscussMD5 : 198644A1FA5BAE1686F7CD6AA7759100
        CheckMD5   : 66367D3FF436CE1541F126CC91160620
        FixMD5     : E22A0FACB492DCF310ED152FD9E4C737
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Analysis Services") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Analysis Services appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Analysis Services is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213837 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213837
        STIG ID    : SQL4-00-016805
        Rule ID    : SV-213837r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the SQL Server Distributed Replay Client software component removed if it is unused.
        DiscussMD5 : FD2E7ABFC2071A5BCFE2B9AEAE7886C6
        CheckMD5   : FC30A1687FEB17E30A2A5CD9586DED88
        FixMD5     : 28F6E883CEDB4BCEC046A2050E5BAD03
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
    # Fixed 'Cannot find any service with service name...'.  Ken Row, 04/07/25, Issue #2196
    $res = Get-Service -DisplayName 'SQL Server Distributed Replay Client*' | Select-Object status, name, displayname
    if ($res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "SQL Server Distributed Replay Client is installed, verify it is required in the system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "SQL Server Distributed Replay Client is not installed, this is not a finding."
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

Function Get-V213838 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213838
        STIG ID    : SQL4-00-016810
        Rule ID    : SV-213838r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the SQL Server Distributed Replay Controller software component removed if it is unused.
        DiscussMD5 : 96D6480F87EBBE63050A97B7422F8E1D
        CheckMD5   : CE2A5CCCF0AA03CFEC268A88AA153EE3
        FixMD5     : 8035AB861A23CDE2D04A6C0057BB9E23
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
    # Fixed 'Cannot find any service with service name...'.  Ken Row, 04/07/25, Issue #2196
    $res = Get-Service -DisplayName 'SQL Server Distributed Replay Controller*' | Select-Object status, name, displayname
    if ($res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "SQL Server Distributed Replay Controller is installed, verify it is required in the system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "SQL Server Distributed Replay Controller is not installed, this is not a finding."
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

Function Get-V213839 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213839
        STIG ID    : SQL4-00-016815
        Rule ID    : SV-213839r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the Full-Text Search software component removed if it is unused.
        DiscussMD5 : CAA77288843B2623C3C2F80CFE1F9A53
        CheckMD5   : 40D3724F0F466414AD011468929F38BF
        FixMD5     : 817621ECE547FD67F3444B97A46D1FB8
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Full-Text and Semantic Extractions") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Full-Text Search appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Full-Text Search is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213841 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213841
        STIG ID    : SQL4-00-016826
        Rule ID    : SV-213841r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the SQL Server Replication software component removed if it is unused.
        DiscussMD5 : 7C5AC82B4F96C7F1FCEC2A872ADF1DA5
        CheckMD5   : B8A5649CCD11315847B0D75C6AB94E7E
        FixMD5     : 89CFD7BAEB657A9C15445ED4EB677DBA
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "SQL Server Replication") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Replication appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Replication is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213842 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213842
        STIG ID    : SQL4-00-016830
        Rule ID    : SV-213842r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the Data Quality Client software component removed if it is unused.
        DiscussMD5 : 52FC8798F42F01B1ABE156E79E745385
        CheckMD5   : F0D5A6F4EC3DB6936B3960D99DDE58BE
        FixMD5     : EF76CBA2E3AFE10EB8A290E565851DA2
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Data Quality Client") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Data Quality Client appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Data Quality Client is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213843 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213843
        STIG ID    : SQL4-00-016835
        Rule ID    : SV-213843r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the Data Quality Services software component removed if it is unused.
        DiscussMD5 : 850368DA034BD252FDAFE6A8A167B0EC
        CheckMD5   : 460CEC3E296D9E208E5C0D7EFD669506
        FixMD5     : 10E184FBDF2E0DC532C0686E64952722
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Data Quality Services") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Data Quality Services appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Data Quality Services is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213844 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213844
        STIG ID    : SQL4-00-016845
        Rule ID    : SV-213844r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the Client Tools SDK software component removed if it is unused.
        DiscussMD5 : 4B22F78CCF97F0C9D3FA976E09AC6D96
        CheckMD5   : 351EF26EF039A0E7059378CB00140976
        FixMD5     : B6CB9AC58CF62BF80A053B4F42CCF6CB
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Client Tools SDK") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Client Tools SDK appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Client Tools SDK is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213845 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213845
        STIG ID    : SQL4-00-016850
        Rule ID    : SV-213845r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the Management Tools software component removed if it is unused.
        DiscussMD5 : F8E770CA0BE859A4358D628019FB80AC
        CheckMD5   : 3DA1ED97B551C738A5B3D8D4DC0D55CE
        FixMD5     : D721FB81B26F6E4B05328EC6087CDB41
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Not_Reviewed"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        If ($res -match "Management Tools") {
            $Status = "Not_Reviewed"
            $FindingDetails = "SQL Server Management Tools appears to be installed. Verify this component is required and documented."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "SQL Server Management Tools is not installed."
            $FindingDetails += "Microsoft SQL Product Features Installed:`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213846 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213846
        STIG ID    : SQL4-00-016855
        Rule ID    : SV-213846r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the Filestream feature disabled if it is unused.
        DiscussMD5 : 4F695B0A66CD0F182D83E53EF74C5E8E
        CheckMD5   : DF7126A3042ECC3A04A915A9316F7A7D
        FixMD5     : E46CCC27EEDAE360574AF409E7D9B0E2
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
    $qry = "
        select @@SERVERNAME InstanceName
            , value
            , value_in_use
        from sys.configurations
        where name = 'filestream access level'
        and (value > 0 or value_in_use > 0)
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        if ($_.value -gt 0) {
            #$FindingDetails += "Instance $($_.InstanceName) is configured with FileStream enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with FileStream enabled.`n"
        }
        else {
            #$FindingDetails += "Instance $($_.InstanceName) is running with FileStream enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is running with FileStream enabled.`n"
        }
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "FileStream is not enabled."
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

Function Get-V213847 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213847
        STIG ID    : SQL4-00-017000
        Rule ID    : SV-213847r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : Unused database components that are integrated in SQL Server and cannot be uninstalled must be disabled.
        DiscussMD5 : 6588C8D4925F7A8448E7215E908C03F2
        CheckMD5   : 9B7B91B495C9D81540BB1EE47AC037A4
        FixMD5     : A90FCAC0F886C6CB94E64E642531F079
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
    $res = Get-SqlProductFeatures $Instance
    $FindingDetails = "Review the system documentation to verify that the enabled components or features are documented and authorized.`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213848 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213848
        STIG ID    : SQL4-00-017100
        Rule ID    : SV-213848r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : The SQL Server default account [sa] must be disabled.
        DiscussMD5 : CE413C3DD4617F4EED252DDB9664ED40
        CheckMD5   : B76A90A3AA947333B4D221577842B6DE
        FixMD5     : CABCA60CD3BD9D50501C3225C46411B9
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
    # Changed to use the passed-in instance name instead of asking SQL for a list of instances. Ken Row, 04/04/25, Issue 2188
    $res = Get-ISQL -ServerInstance $Instance "
      SELECT name, is_disabled, principal_id
        FROM sys.sql_logins
       WHERE principal_id = 1
    "
    if ($res) {
        if ($res.is_disabled -ne $true) {
            $FindingDetails += "The SQL Server default account account is not disabled.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }
    else {
        $FindingDetails = "This is odd -- no sql login was found with principal_id = 1"
    } # if ($res)

    if ($FindingDetails -gt '') {
        $Status = 'Open'
    }
    else {
        $Status = 'NotAFinding'
        $FindingDetails += "The SQL Server default account is disabled."
    } # if ($FindingDetails -gt '')
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

Function Get-V213849 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213849
        STIG ID    : SQL4-00-017200
        Rule ID    : SV-213849r960963_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Access to xp_cmdshell must be disabled, unless specifically required and approved.
        DiscussMD5 : 0DD51441D9D8F15FB28444EF43432A7F
        CheckMD5   : 54C15BAA1871B083DBB46599B4280F58
        FixMD5     : 006833C74ED71A3078667A1C6CEAF462
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
    $qry = "
        select @@SERVERNAME InstanceName
            , value
            , value_in_use
        from sys.configurations
        where name = 'xp_cmdshell'
        and 1 in (value, value_in_use)
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        if ($_.value -eq 1) {
            #$FindingDetails += "Instance $($_.InstanceName) is configured with xp_cmdshell enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) is configured with xp_cmdshell enabled.`n$($_ | Format-Table -AutoSize| Out-String)"
        }
        else {
            #$FindingDetails += "Instance $($_.InstanceName) is running with xp_cmdshell enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) is running with xp_cmdshell enabled.`n$($_ | Format-Table -AutoSize| Out-String)"
        }
    } # foreach-object

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "XP_CmdShell is not enabled."
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

Function Get-V213850 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213850
        STIG ID    : SQL4-00-017400
        Rule ID    : SV-213850r960966_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-DB-000094
        Rule Title : SQL Server must be configured to prohibit or restrict the use of unauthorized network protocols.
        DiscussMD5 : 610677C19047BF559C0F48BB4E81E51E
        CheckMD5   : 1993EF606684BC430A1F6B121A0DE526
        FixMD5     : 2C7C0F514A3FFA471837BD20F5D18604
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
        SELECT @@servername as Instance
            , dn.value_data as Protocol
        from sys.dm_server_registry dn
        inner join sys.dm_server_registry de on dn.registry_key = de.registry_key
        where dn.value_name = 'DisplayName'
        and de.value_name = 'Enabled'
        and de.value_data = 1
    "
    If ($res) {
        $FindingDetails = "Below are the enabled protocols.  Review the system documentation. If any listed protocol is enabled but not authorized, this is a finding..`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No protocols are enabled."
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

Function Get-V213851 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213851
        STIG ID    : SQL4-00-017410
        Rule ID    : SV-213851r960966_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-DB-000094
        Rule Title : SQL Server must be configured to prohibit or restrict the use of unauthorized network ports.
        DiscussMD5 : 610677C19047BF559C0F48BB4E81E51E
        CheckMD5   : 5F7EA5FA7B5789660BF5CB9BC8DB09CF
        FixMD5     : 09662C5D15622EE46E107727809F49FE
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
    Get-ISQL -ServerInstance $Instance -Database $Database "
        select @@servername as Instance
            , ds.value_data StaticPort
            , dd.value_data DynamicPort
        from sys.dm_server_registry ds
        inner join sys.dm_server_registry dd on ds.registry_key = dd.registry_key
        where ds.registry_key like '%IPAll'
        and dd.registry_key like '%IPAll'
        and ds.value_name = 'TcpPort'
        and dd.value_name = 'TcpDynamicPorts'
    " | ForEach-Object {
        $inst = $_.Instance
        $DynamicPort = Get-LeftNumbers($_.DynamicPort.trim())
        $StaticPort = Get-LeftNumbers($_.StaticPort.trim())
        if ($DynamicPort -gt 0) {
            $FindingDetails += "Instance $inst is configured to use dynamic ports $DynamicPort."
        }
        elseif ($StaticPort -lt 49152) {
            $FindingDetails += "Instance $inst is configured with a lower-value static port StaticPort $StaticPort."
        }
    }

    if ($FindingDetails -gt '') {
        $Status = 'Open'
        $FindingDetails += "`nNote: the STIG asks that port usage comply with PPSM or organizational mandates, but industry best practices advise using high-number static ports."
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "High-number static ports are being used, as per industry best practices."
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

Function Get-V213852 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213852
        STIG ID    : SQL4-00-018400
        Rule ID    : SV-213852r960969_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-APP-000148-DB-000103
        Rule Title : SQL Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).
        DiscussMD5 : AE7B1666F6D2970583C81DAF46E45716
        CheckMD5   : A35ECDDA98D732FCAAE8F3C565F7125C
        FixMD5     : 3980DD77BB488C368452F57D1780344B
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
        SELECT name AS Login_Name, type_desc AS Account_Type, is_disabled AS Account_Disabled
        FROM sys.server_principals
        WHERE TYPE IN ('U', 'S', 'G')
        and name not like '%##%'
        ORDER BY name, type_desc
    "
    If ($res) {
        $FindingDetails = "Verify the accounts listed below are not shared accounts.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213858 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213858
        STIG ID    : SQL4-00-030300
        Rule ID    : SV-213858r960768_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : SQL Server authentication and identity management must be integrated with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.
        DiscussMD5 : AECB0D086A4A8A7F31A22508A6B8401F
        CheckMD5   : 9E7AEB7220C3694B2B4A9F69D51158CA
        FixMD5     : A1B9EF428A4900BA352B1996016B458B
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
    # Changed to use the passed-in instance name instead of asking SQL for a list of instances. Ken Row, 04/04/25, Issue 2188

    $res = Get-ISQL -ServerInstance $Instance "EXEC sp_configure 'contained database authentication'"
    if ($res.run_value -eq 1 -or $res.config_value -eq 1) {
        $FindingDetails += "Instance $h is using contained database authentication.`n"
    }
    $res = Get-ISQL -ServerInstance $Instance "
    SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
    WHEN 1 THEN 'Windows Authentication'
    WHEN 0 THEN 'Windows and SQL Server Authentication'
    END as AuthenticationMode
    "
    if ($res.AuthenticationMode -ne 'Windows Authentication') {
        $FindingDetails += "Instance $h's login authention mode is $($res.AuthenticationMode) instead of Windows Authentication.`n"
    }

    if ($FindingDetails -gt "") {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the above are documented as authorized in the SSP.`n"
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        select @@servername
            , name
        FROM sys.sql_logins
        WHERE type_desc = 'SQL_LOGIN'
        AND is_disabled = 0
        "
        if ($res) {
            $FindingDetails += "DBA, also ensure the following accounts are authorized in the SSP to be managed by SQL Server:`n$($res | Format-Table -AutoSize| Out-String)"
        } # if ($res)
    } # if ($FindingDetails -gt "")

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "Windows Authentication is used."
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

Function Get-V213859 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213859
        STIG ID    : SQL4-00-030410
        Rule ID    : SV-213859r960885_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-DB-000325
        Rule Title : Where SQL Server Audit is in use, SQL Server must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.
        DiscussMD5 : 08421D6F203E1E3AA2D3327D3627F2E6
        CheckMD5   : 318F9A7F5907B92F0703983112C6BD7C
        FixMD5     : 5CE32D103D386E9FA99F50BCD3D40F33
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
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?"
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

Function Get-V213860 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213860
        STIG ID    : SQL4-00-030600
        Rule ID    : SV-213860r960915_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-APP-000109-DB-000321
        Rule Title : Where availability is paramount, the SQL Server must continue processing (preferably overwriting existing records, oldest first), in the event of lack of space for more Audit/Trace log records; and must keep processing after any failure of an Audit/Trace.
        DiscussMD5 : A0D8730D9469A489AA1171C941AB32E0
        CheckMD5   : B4C8C00681899646E876386EA75D1A61
        FixMD5     : 4FA8298295D96FF5CFCBCAE2C75D8119
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT a.name 'audit_name',
    a.type_desc 'storage_type',
    f.max_rollover_files
    FROM sys.server_audits a
    LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id
    WHERE a.is_state_enabled = 1"
    if ($res) {
        if ($res.storage_type -eq 'FILE') {
            if ($res.max_rollover_files -gt 0) {
                $Status = 'NotAFinding'
                #$FindingDetails += "The storage type is 'FILE' and the max rollover files are greater than zero."
                # 20201027 JJS Added all Results to output
                $FindingDetails += "The storage type is 'FILE' and the max rollover files are greater than zero.`n$($res | Format-Table -AutoSize| Out-String)"
            }
            else {
                $Status = "Open"
                #$FindingDetails += "The storage type is 'FILE' and the max rollover files are zero."
                # 20201027 JJS Added all Results to output
                $FindingDetails += "The storage type is 'FILE' and the max rollover files are zero.`n$($res | Format-Table -AutoSize| Out-String)"
            } # if ($res.max_rollover_files -gt 0)
        }
        elseif ($res.storage_type -in 'APPLICATION LOG', 'SECURITY LOG') {
            $Status = 'NotAFinding'
            #$FindingDetails += "LOG storage types do not require max rollover files to be configured."
            # 20201027 JJS Added all Results to output
            $FindingDetails += "LOG storage types do not require max rollover files to be configured.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        else {
            $Status = "Open"
            #$FindingDetails = "An unexpected storage type was found on the security audit."
            # 20201027 JJS Added all Results to output
            $FindingDetails = "An unexpected storage type was found on the security audit.`n$($res | Format-Table -AutoSize| Out-String)"
        } # if ($res.storage_type -eq 'FILE')
    }
    else {
        $Status = "Open"
        $FindingDetails = "No audits appear to be configured on this system."
    } # if ($res)
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

Function Get-V213861 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213861
        STIG ID    : SQL4-00-030700
        Rule ID    : SV-213861r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000362
        Rule Title : The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be restricted to authorized users.
        DiscussMD5 : 978959640256E1378015BF8DB91A4E1E
        CheckMD5   : 9E71938FF750257A99E9A9EE804A66CC
        FixMD5     : 1150AED4FC0263C32AC610A31912103C
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
    SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
    CASE class
    WHEN 0 THEN DB_NAME()
    WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
    WHEN 3 THEN SCHEMA_NAME(major_id)
    ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
    END AS securable_name, DP.state_desc, DP.permission_name
    FROM sys.database_permissions DP
    JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
    LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
    WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following accounts are authorized in the SSP to modify objects:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
    FROM sys.database_principals R
    JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
    JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
    WHERE R.name IN ('db_ddladmin','db_owner')
    AND M.name != 'dbo'
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            $Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the SSP to modify objects:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
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

Function Get-V213862 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213862
        STIG ID    : SQL4-00-031100
        Rule ID    : SV-213862r961050_rule
        CCI ID     : CCI-000803, CCI-002450
        Rule Name  : SRG-APP-000179-DB-000114
        Rule Title : SQL Server must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.
        DiscussMD5 : 5F2ADCE13DCC1DE02CD4DD58E28750C8
        CheckMD5   : E56804C55133870156BA2EBE21DEC061
        FixMD5     : B813D3A7A0D813AC8BAE8222A223B3EB
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"  # Registry path identified in STIG
    $RegistryValueName = "Enabled"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $AF_UserHeader = $true
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        #$RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        #If the registry value does not exist
        If ($SettingNotConfiguredAllowed -eq $true) {
            #And it is allowed to be not configured set to notAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            #Or, if it must be configured, set this to Open
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        #If the registry value is found...
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                #If the registry result matches the expected value
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                #If the result value and expected value are different, print what the value is set to and what it should be.
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                #If the result type is the same as expected
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If the result type is different from what is expected, print both.
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213863 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213863
        STIG ID    : SQL4-00-031400
        Rule ID    : SV-213863r961149_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-APP-000243-DB-000374
        Rule Title : Access to database files must be limited to relevant processes and to authorized, administrative users.
        DiscussMD5 : 6219D3BDDC7ECCE2CCCEC7B904118CB0
        CheckMD5   : 5293FB043B9E69C62EA83DD33D36FF2D
        FixMD5     : FC93E4BC6D28969DBAFCC36743EA1288
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
    <#
    Allowed privileges per the STIG:

    Database Administrators ALL Full Control
    SQL Server Service SID Data; Log; Backup; Full Control
    SQL Server Agent Service SID Backup Full Control
    SYSTEM ALL Full Control
    CREATOR OWNER ALL Full Control
    #>


    $hashBase = @{
        #$C_ACCT_SQLADMINS                       = @('FullControl') # 20200805 JJS commented out
        'BUILTIN\Administrators'      = @('FullControl')
        #$C_ACCT_SQLSVC                          = @('FullControl') # 20200805 JJS commented out
        'NT SERVICE\MSSQL$<INSTANCE>' = @('FullControl')
        'NT AUTHORITY\SYSTEM'         = @('FullControl')
        'CREATOR OWNER'               = @('FullControl')
    }

    $hashDataLog = $hashBase += @{}
    $hashBackup = $hashBase += @{
        #$C_ACCT_SQLAGENT                        = @('FullControl') # 20200805 JJS commented out
        'NT SERVICE\SQLAgent$<INSTANCE>' = @('FullControl')
    }

    $iDirCnt = 0
    $fFound = $false
    $sDirList = ''

    # Poll MSSQL to get directories of interest...
    Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT distinct @@servername ServerName
            , @@servicename Instance
            , directorytype
            , replace(rtrim(replace(directoryname, '\', ' ')), ' ', '\') directoryname
        FROM
        (
            SELECT
                CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(260)) AS DirectoryName,
                'DataLog' AS DirectoryType
            UNION ALL
            SELECT
                CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(260)),
                'DataLog' AS DirectoryType
            UNION ALL
            SELECT DISTINCT
                LEFT(physical_name, (LEN(physical_name) - CHARINDEX('\', REVERSE(physical_name)))),
                CASE type
                    WHEN 0 THEN 'DataLog'
                    WHEN 1 THEN 'DataLog'
                    ELSE 'Other'
                END
            FROM sys.master_files
            UNION ALL
            SELECT DISTINCT
                LEFT(physical_device_name, (LEN(physical_device_name) - CHARINDEX('\', REVERSE(physical_device_name)))),
                'Backup'
            FROM msdb.dbo.backupmediafamily
            WHERE device_type IN (2, 9, NULL)
        ) A
        ORDER BY
            DirectoryType,
            DirectoryName
    " | ForEach-Object {
        $sInstance = $_.Instance
        $sServer = $_.ServerName
        $sDir = $_.DirectoryName
        $sType = $_.DirectoryType
        $fFound = $true;

        if (Test-Path $sDir) {
            $objACL = Get-Acl $sDir
        }
        else {
            $objACL = $null
            #$FindingDetails += "Instance $sServer appears to be running, but $sDir seems missing.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $sServer appears to be running, but $sDir seems missing.`n$($_ | Format-Table -AutoSize| Out-String)"
        } # if (test-path $sdir)

        if ($objACL) {
            $sDirList += "  $sDir`n"; $iDirCnt += 1

            if ($sType -eq 'Backup') {
                $hashAuth = $hashBackup
            }
            else {
                $hashAuth = $hashDataLog
            }
            $FindingDetails += Get-AccessProblem -CurrentAuthorizations $objACL.access -AllowedAuthorizations $hashAuth -FilePath $sDir -InstanceName $sInstance
        } # if ($objACL)
    } # Get-ISQL -ServerInstance $Instance -Database $Database ... | foreach-object


    # Interpret results...
    if ($FindingDetails -gt '') {
        $Status = "Open"
    }
    else {
        if ($fFound) {
            $Status = "NotAFinding"
            if ($iDirCnt -eq 0) {
                $FindingDetails = "No SQL data, log, or backup directories were found on this host."
            }
            elseif ($iDirCnt -gt 1) {
                $FindingDetails = "The following directories were checked and found to have proper authorizations:`n`n$sDirList"
            }
            else {
                $FindingDetails = "The following root directory was checked and found to have proper authorizations:`n`n$sDirList"
            }
        }
        else {
            $Status = "Open"
            $FindingDetails = "Unable to determine the SQL data root directory."
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

Function Get-V213868 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213868
        STIG ID    : SQL4-00-033000
        Rule ID    : SV-213868r961392_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-DB-000316
        Rule Title : SQL Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
        DiscussMD5 : CB6D963E3907155B3097E6EAE8702569
        CheckMD5   : 79D4E723FCCEACAA355B8EDBEE2BB4EE
        FixMD5     : 0BC9F847D53E92FFFE1C4D60C00A4F42
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
        SELECT @@servername as instance
            , max_file_size
            , max_rollover_files
            , max_files
            , log_file_path
        FROM sys.server_file_audits
    "
    if ($res) {
        $res | ForEach-Object {
            $maxsize = (0 + $_.max_file_size) * 1024 * 1024
            $maxfiles = 0 + $_.max_rollover_files
            if ($maxfiles -eq 2147483647) {
                $maxfiles = 0 + $_.max_files
            }
            $logdisk = $_.log_file_path -replace ':.*$'
            $psdrive = Get-PSDrive $logdisk
            $capacity = $psdrive.Free + $psdrive.Used
            if ((($maxsize * $maxfiles) -gt $capacity) -or 0 -in $maxsize, $maxfiles ) {
                $Status = 'Open'
                #$FindingDetails += "Audit path $($_.log_file_path) has potential to exceed disk capacity."
                # 20201027 JJS Added all Results to output
                $FindingDetails += "Audit path $($_.log_file_path) has potential to exceed disk capacity.`n$($_ | Format-Table -AutoSize| Out-String)"
            }
        } # $res | foreach-object
        if ($FindingDetails -eq '') {
            $Status = 'NotAFinding'
            $FindingDetails += "All audit storage is within capacity."
        } # if ($FindingDetails -eq '')
    }
    else {
        $Status = "Open"
        $FindingDetails = 'No audits are defined at all, but the STIG doesn''t allow for "Not Applicable."'
    } #   if ($res)
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

Function Get-V213871 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213871
        STIG ID    : SQL4-00-033600
        Rule ID    : SV-213871r961443_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-APP-000374-DB-000322
        Rule Title : SQL Server must produce time stamps that can be mapped to Coordinated Universal Time (UTC, formerly GMT).
        DiscussMD5 : F354B68A32C0CC148C7DE3E3D81C2924
        CheckMD5   : 17624EE654281282099CC42E4CC73187
        FixMD5     : 9BE37620A6ED79C0F703D69ECFB1599D
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@servername as instance, isnull(default_domain(),'NULL') as DefaultDomain"
    if ($res) {
        $res | ForEach-Object {
            if ($_.DefaultDomain -eq 'NULL') {
                # The instance is not part of a domain, so we need to see if a time source is set.
                $ts = (w32tm /query /source)
                if ($ts -eq 'Local CMOS Clock') {
                    #$FindingDetails += "Instance $($_.instance) does not appear to sync with a time server."
                    # 20201027 JJS Added all Results to output
                    $FindingDetails += "Instance $($_.instance) does not appear to sync with a time server.`n$($_ | Format-Table -AutoSize| Out-String)"
                }
            }
        } # $res | foreach-object
        if ($FindingDetails -eq '') {
            $Status = 'NotAFinding'
            $FindingDetails += "All servers are either part of a domain or are configured to correctly synchronize with a time server."
        } # if ($FindingDetails -eq '')
    }
    else {
        $Status = "Open"
        $FindingDetails = "Unable to determine default domain."
    } # if ($res)
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

Function Get-V213873 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213873
        STIG ID    : SQL4-00-033900
        Rule ID    : SV-213873r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : SQL Server and Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance or database(s).
        DiscussMD5 : 88DA8C452AAFDBB8DA9B3A809D507D46
        CheckMD5   : 007032B5F18663455BF464141E7E9A77
        FixMD5     : 04435115AD4D85ED33E028E17EB3E29F
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
        SELECT @@servername as instance
            , p.name AS Principal,
    p.type_desc AS Type,
    sp.permission_name AS Permission,
    sp.state_desc AS State
    FROM sys.server_principals p
    INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id
    WHERE (sp.permission_name = 'CONTROL SERVER' OR sp.state = 'W')
    AND p.name not in ('##MS_PolicySigningCertificate##')
    "
    if ($res) {
        $FindingDetails += "DBA, ensure the following have been documented as authorized to control the server:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
    , m.name AS Member,
    m.type_desc AS Type,
    r.name AS Role
    FROM sys.server_principals m
    INNER JOIN sys.server_role_members rm ON m.principal_id = rm.member_principal_id
    INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
    WHERE r.name IN ('sysadmin','securityadmin','serveradmin')
    and m.name not in (
        'Sandman'
    , 'NT SERVICE\SQLWriter'
    , 'NT SERVICE\Winmgmt'
    , 'NT SERVICE\MSSQL`$'+@@SERVICENAME
    , 'NT SERVICE\SQLAgent`$'+@@SERVICENAME
    )"
    if ($res) {
        $FindingDetails += "DBA, ensure the following have been documented as authorized to administer the server:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq '') {
        $Status = "NotAFinding"
        $FindingDetails = "The check queries did not find any accounts other than those authorized in the SSP."
    }
    else {
        $Status = 'Open'
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

Function Get-V213874 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213874
        STIG ID    : SQL4-00-034000
        Rule ID    : SV-213874r981958_rule
        CCI ID     : CCI-001814
        Rule Name  : SRG-APP-000381-DB-000361
        Rule Title : SQL Server must produce Trace or Audit records of its enforcement of access restrictions associated with changes to the configuration of the DBMS or database(s).
        DiscussMD5 : B96BB396C3E74830E792C9277CE0D1C0
        CheckMD5   : 24C0D2788CEFE5AFE3DA017B3458704F
        FixMD5     : E28DD45DCB9CDEE98C20B1AA991F55CA
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
        $AANames =  'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
                    'AUDIT_CHANGE_GROUP',
                    'BACKUP_RESTORE_GROUP',
                    'DATABASE_CHANGE_GROUP',
                    'DATABASE_OBJECT_ACCESS_GROUP',
                    'DATABASE_OBJECT_CHANGE_GROUP',
                    'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                    'DATABASE_OPERATION_GROUP',
                    'DATABASE_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_PERMISSION_CHANGE_GROUP',
                    'DATABASE_PRINCIPAL_CHANGE_GROUP',
                    'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
                    'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                    'DBCC_GROUP',
                    'LOGIN_CHANGE_PASSWORD_GROUP',
                    'SCHEMA_OBJECT_CHANGE_GROUP',
                    'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_OBJECT_CHANGE_GROUP',
                    'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_OPERATION_GROUP',
                    'SERVER_PERMISSION_CHANGE_GROUP',
                    'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
                    'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                    'SERVER_STATE_CHANGE_GROUP',
                    'TRACE_CHANGE_GROUP'
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
            'AUDIT_CHANGE_GROUP',
            'BACKUP_RESTORE_GROUP',
            'DATABASE_CHANGE_GROUP',
            'DATABASE_OBJECT_ACCESS_GROUP',
            'DATABASE_OBJECT_CHANGE_GROUP',
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OPERATION_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_CHANGE_GROUP',
            'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'DBCC_GROUP',
            'LOGIN_CHANGE_PASSWORD_GROUP',
            'SCHEMA_OBJECT_CHANGE_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OPERATION_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SERVER_STATE_CHANGE_GROUP',
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
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            102
            103
            104
            105
            106
            107
            108
            109
            110
            111
            112
            113
            115
            116
            117
            118
            128
            129
            130
            131
            132
            133
            134
            135
            152
            153
            162
            170
            171
            172
            173
            175
            176
            177
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213875 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213875
        STIG ID    : SQL4-00-034200
        Rule ID    : SV-213875r961470_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-DB-000364
        Rule Title : SQL Server must disable communication protocols not required for operation.
        DiscussMD5 : FA329FD78B2D93F14C195815A5F5BA7F
        CheckMD5   : D3460C2F0963CA9FB3522227E8C86750
        FixMD5     : 7C21CD00E6F7FCA08D3C19BBFA7192AB
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
        SELECT @@servername as Instance
            , dn.value_data as Protocol
        from sys.dm_server_registry dn
        inner join sys.dm_server_registry de on dn.registry_key = de.registry_key
        where dn.value_name = 'DisplayName'
        and de.value_name = 'Enabled'
        and de.value_data = 1
    "
    If ($res) {
        $FindingDetails = "Below are the enabled protocols.  Review the system documentation. If any listed protocol is enabled but not authorized, this is a finding..`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No protocols are enabled."
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

Function Get-V213877 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213877
        STIG ID    : SQL4-00-035000
        Rule ID    : SV-213877r961638_rule
        CCI ID     : CCI-002420
        Rule Name  : SRG-APP-000441-DB-000378
        Rule Title : The confidentiality and integrity of information managed by SQL Server must be maintained during preparation for transmission.
        DiscussMD5 : 7C69F2757045E210D5F38044715B0F36
        CheckMD5   : C4C9F7F69B83F4B6C6D28CA9900D5899
        FixMD5     : E3F323CD125F89D9802819E0E8F2C4F8
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
    $Status = 'NotAFinding' # if we make it through all the tests unscathed, then NaF

    # Get the FQDN of the Instance's Server name for later use...
    $sqlSvr = $(Get-ISQL -ServerInstance $Instance -Database $Database "select machine = serverproperty('MachineName')").machine
    $sqlFQDN = [system.net.dns]::GetHostByName($sqlSvr).Hostname

    #The check says to look at SQL config mgr, but we cannot automate that, so let's look at the registry...
    $sqlHost = $env:COMPUTERNAME
    $FindingDetails = "Checking encryption settings on host $sqlhost...`n"
    $SQLReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $sqlHost)

    #Get the registry key/path for the instance...
    $sRegKey = $(Get-ISQL -ServerInstance $Instance -Database $Database "
        select registry_key from sys.dm_server_registry where value_name = 'CurrentVersion'
        ").registry_key -replace '\\CurrentVersion$', '' -replace '^HKLM\\Software', 'SOFTWARE'

    #Get cert/encryption info...
    $SQLSNL = $SQLReg.OpenSubKey("$sRegKey\SuperSocketNetLib")
    $Thumbprint = $SQLSNL.GetValue("Certificate")
    $fForceEnc = $SQLSNL.GetValue("ForceEncryption")

    #Examine what we found...
    If ([string]::IsNullOrEmpty($Thumbprint)) {
        $Status = "Open"
        $FindingDetails += "No certificate is assigned for encryption.`n"

    }
    ElseIf ($fForceEnc -eq 0) {
        $Status = "Open"
        $FindingDetails += "Force Encryption value is 0 -- no encryption.`n"

    }
    Else {
        $FindingDetails += "Force Encryption value is 1.`n"
        $sqlcert = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object Thumbprint -ieq $Thumbprint
        if ($sqlcert) {
            $FindingDetails += "Encryption uses this cert:`n$(
            $sqlcert | Format-List Subject, Issuer, Thumbprint, FriendlyName, NotBefore, NotAfter, HasPrivateKey | Out-String
        )"
            $resTest = Test-Certificate $sqlcert -ErrorAction SilentlyContinue 3>&1 # send warning info to stdout
            if (!($?)) {
                # Test-Cert must have failed.
                $status = "Open"
                $FindingDetails += "But the certificate is not valid because of the following error:`n$(
                $resTest.message
                $Error[0].exception
            )`n"

            }
            elseif ($sqlcert.Issuer -eq $sqlcert.Subject) {
                $status = "Open"
                $FindingDetails += "But the certificate appears to be self-signed.`n"

            }
            elseif ($sqlcert.HasPrivateKey -eq $false) {
                $status = "Open"
                $FindingDetails += "But the certificate does not appear to have a private key.`n"

            }
            elseif ($sqlcert.Subject -notlike "CN=$sqlFQDN*") {
                $sSAN = ($sqlcert.Extensions | Where-Object {$_.oid.friendlyname -eq 'Subject Alternative Name'}).format($true)
                $arrSAN = ($sSAN -split "`r?`n").Trim() -notmatch "^$"
                if (!($arrSAN -like "DNS Name=$sqlFQDN")) {
                    $status = "Open"
                    $FindingDetails += "But neither the certificate's subject nor its alternate includes $sqlFQDN.`n"
                }
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += "Thumbprint $Thumbprint not found on an installed cert.`n"
        } # if ($sqlcert)

        if (Get-Service clussvc -ErrorAction SilentlyContinue) {
            # We are running on a cluster, and the current node looks OK. See if the other nodes have the same config...
            $sqlnodelist = $(get-clusternode | Where-Object name -NE $sqlHost).Name
            foreach ($sqlnode in $sqlnodelist) {
                $FindingDetails += "`nChecking SQL configuration on node $sqlnode...`n"
                $SQLReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $sqlnode)

                #Get cert/encryption info...
                $SQLSNL = $SQLReg.OpenSubKey("$sRegKey\SuperSocketNetLib")
                $NodeThumb = $SQLSNL.GetValue("Certificate")
                $fForceEnc = $SQLSNL.GetValue("ForceEncryption")

                #Examine what we found...
                If ([string]::IsNullOrEmpty($NodeThumb)) {
                    $Status = "Open"
                    $FindingDetails += "No certificate is assigned for encryption on node $sqlnode.`n"

                }
                ElseIf ($fForceEnc -eq 0) {
                    $Status = "Open"
                    $FindingDetails += "Force Encryption value is 0 (no encryption) on node $sqlnode.`n"

                }
                else {
                    $FindingDetails += "Force Encryption value is 1.`n"
                    if ($Thumbprint -eq $NodeThumb) {
                        $FindingDetails += "The encryption cert matches the one on $sqlHost.`n"
                    }
                    else {
                        $Status = "Open"
                        $FindingDetails += "The encryption cert on $sqlnode does not match the one on $sqlHost.`n"
                    }
                }
            }
        }
    }
    $FIPSEnabled = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' 'Enabled'
    If ($FIPSEnabled -eq "1" -and $Status -match 'NotAFinding') {
        $FindingDetails += "Fips is enabled, SQL server is using a valid DoD issued certificate with Force Encryption on.  These settings satisfy the requirement that the confidentiality and integrity of information managed by SQL Server must be maintained during preparation for transmission and reception.`n"
    }
    else {
        $FindingDetails += "Fips must be enabled and SQL server must use a valid DoD issued certificate with Force Encryption on.  These settings would satisfy the requirement that the confidentiality and integrity of information managed by SQL Server must be maintained during preparation for transmission and reception.   Check the system documentation to see if the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.  If there is no such requirement, this is not a finding.`n"

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

Function Get-V213878 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213878
        STIG ID    : SQL4-00-035100
        Rule ID    : SV-213878r961641_rule
        CCI ID     : CCI-002422
        Rule Name  : SRG-APP-000442-DB-000379
        Rule Title : The confidentiality and integrity of information managed by SQL Server must be maintained during reception.
        DiscussMD5 : B56BD71A2BA81A6A4CB9794D13A257D8
        CheckMD5   : 426AC2A64681AB720C87ADFCACBC098F
        FixMD5     : 2A40E91805220862B16BF5E7ACD2009D
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
    $Status = 'NotAFinding' # if we make it through all the tests unscathed, then NaF

    # Get the FQDN of the Instance's Server name for later use...
    $sqlSvr = $(Get-ISQL -ServerInstance $Instance -Database $Database "select machine = serverproperty('MachineName')").machine
    $sqlFQDN = [system.net.dns]::GetHostByName($sqlSvr).Hostname

    #The check says to look at SQL config mgr, but we cannot automate that, so let's look at the registry...
    $sqlHost = $env:COMPUTERNAME
    $FindingDetails = "Checking encryption settings on host $sqlhost...`n"
    $SQLReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $sqlHost)

    #Get the registry key/path for the instance...
    $sRegKey = $(Get-ISQL -ServerInstance $Instance -Database $Database "
        select registry_key from sys.dm_server_registry where value_name = 'CurrentVersion'
        ").registry_key -replace '\\CurrentVersion$', '' -replace '^HKLM\\Software', 'SOFTWARE'

    #Get cert/encryption info...
    $SQLSNL = $SQLReg.OpenSubKey("$sRegKey\SuperSocketNetLib")
    $Thumbprint = $SQLSNL.GetValue("Certificate")
    $fForceEnc = $SQLSNL.GetValue("ForceEncryption")

    #Examine what we found...
    If ([string]::IsNullOrEmpty($Thumbprint)) {
        $Status = "Open"
        $FindingDetails += "No certificate is assigned for encryption.`n"

    }
    ElseIf ($fForceEnc -eq 0) {
        $Status = "Open"
        $FindingDetails += "Force Encryption value is 0 -- no encryption.`n"

    }
    Else {
        $FindingDetails += "Force Encryption value is 1.`n"
        $sqlcert = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object Thumbprint -ieq $Thumbprint
        if ($sqlcert) {
            $FindingDetails += "Encryption uses this cert:`n$(
            $sqlcert | Format-List Subject, Issuer, Thumbprint, FriendlyName, NotBefore, NotAfter, HasPrivateKey | Out-String
        )"
            $resTest = Test-Certificate $sqlcert -ErrorAction SilentlyContinue 3>&1 # send warning info to stdout
            if (!($?)) {
                # Test-Cert must have failed.
                $status = "Open"
                $FindingDetails += "But the certificate is not valid because of the following error:`n$(
                $resTest.message
                $Error[0].exception
            )`n"

            }
            elseif ($sqlcert.Issuer -eq $sqlcert.Subject) {
                $status = "Open"
                $FindingDetails += "But the certificate appears to be self-signed.`n"

            }
            elseif ($sqlcert.HasPrivateKey -eq $false) {
                $status = "Open"
                $FindingDetails += "But the certificate does not appear to have a private key.`n"

            }
            elseif ($sqlcert.Subject -notlike "CN=$sqlFQDN*") {
                $sSAN = ($sqlcert.Extensions | Where-Object {$_.oid.friendlyname -eq 'Subject Alternative Name'}).format($true)
                $arrSAN = ($sSAN -split "`r?`n").Trim() -notmatch "^$"
                if (!($arrSAN -like "DNS Name=$sqlFQDN")) {
                    $status = "Open"
                    $FindingDetails += "But neither the certificate's subject nor its alternate includes $sqlFQDN.`n"
                }
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += "Thumbprint $Thumbprint not found on an installed cert.`n"
        } # if ($sqlcert)

        if (Get-Service clussvc -ErrorAction SilentlyContinue) {
            # We are running on a cluster, and the current node looks OK. See if the other nodes have the same config...
            $sqlnodelist = $(get-clusternode | Where-Object name -NE $sqlHost).Name
            foreach ($sqlnode in $sqlnodelist) {
                $FindingDetails += "`nChecking SQL configuration on node $sqlnode...`n"
                $SQLReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $sqlnode)

                #Get cert/encryption info...
                $SQLSNL = $SQLReg.OpenSubKey("$sRegKey\SuperSocketNetLib")
                $NodeThumb = $SQLSNL.GetValue("Certificate")
                $fForceEnc = $SQLSNL.GetValue("ForceEncryption")

                #Examine what we found...
                If ([string]::IsNullOrEmpty($NodeThumb)) {
                    $Status = "Open"
                    $FindingDetails += "No certificate is assigned for encryption on node $sqlnode.`n"

                }
                ElseIf ($fForceEnc -eq 0) {
                    $Status = "Open"
                    $FindingDetails += "Force Encryption value is 0 (no encryption) on node $sqlnode.`n"

                }
                else {
                    $FindingDetails += "Force Encryption value is 1.`n"
                    if ($Thumbprint -eq $NodeThumb) {
                        $FindingDetails += "The encryption cert matches the one on $sqlHost.`n"
                    }
                    else {
                        $Status = "Open"
                        $FindingDetails += "The encryption cert on $sqlnode does not match the one on $sqlHost.`n"
                    }
                }
            }
        }
    }
    $FIPSEnabled = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' 'Enabled'
    If ($FIPSEnabled -eq "1" -and $Status -match 'NotAFinding') {
        $FindingDetails += "Fips is enabled, SQL server is using a valid DoD issued certificate with Force Encryption on.  These settings satisfy the requirement that the confidentiality and integrity of information managed by SQL Server must be maintained during preparation for transmission and reception.`n"
    }
    else {
        $FindingDetails += "Fips must be enabled and SQL server must use a valid DoD issued certificate with Force Encryption on.  These settings would satisfy the requirement that the confidentiality and integrity of information managed by SQL Server must be maintained during preparation for transmission and reception.   Check the system documentation to see if the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.  If there is no such requirement, this is not a finding.`n"

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

Function Get-V213881 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213881
        STIG ID    : SQL4-00-035600
        Rule ID    : SV-213881r961791_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000492-DB-000332
        Rule Title : SQL Server must produce Trace or Audit records when security objects are accessed.
        DiscussMD5 : E0DB7A72C2CE379EAA47478B824A919E
        CheckMD5   : D81521EF6785F7BBC31C7D9ABA03BE49
        FixMD5     : EEE87DC9F955DE582377D4CBE2B59F0D
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
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND d.audited_result = 'SUCCESS AND FAILURE'
        "
        If ($res) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either no audits are being done or the audit is missing SUCCESS and FAILURE. Review your system documentation, if there are no locally-defined security tables, functions, or procedures, this is not applicable (NA).`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "
        If ($res.eventid -contains '42' -and $res.eventid -contains '43' -and $res.eventid -contains '90' -and $res.eventid -contains '162') {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation, if there are no locally-defined security tables, functions, or procedures, this is not applicable (NA).`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213882 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213882
        STIG ID    : SQL4-00-035700
        Rule ID    : SV-213882r961791_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000492-DB-000333
        Rule Title : SQL Server must produce Trace or Audit records when unsuccessful attempts to access security objects occur.
        DiscussMD5 : C70B81AE172A9002E38E04E92E0C3CEA
        CheckMD5   : 90B26E6E10ACD2CEB22D4BFFF8F4EC75
        FixMD5     : 2FDAF6DB3D7D68B709BD476A405391CA
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
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' AND d.audited_result = 'SUCCESS AND FAILURE'
        "
        If ($res) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either no audits are being done or the audit is missing SUCCESS and FAILURE. Review your system documentation, if there are no locally-defined security tables, functions, or procedures, this is not applicable (NA).`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "
        If ($res.eventid -contains '42' -and $res.eventid -contains '43' -and $res.eventid -contains '90' -and $res.eventid -contains '162') {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text. Review your system documentation, if there are no locally-defined security tables, functions, or procedures, this is not applicable (NA).`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213883 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213883
        STIG ID    : SQL4-00-036000
        Rule ID    : SV-213883r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000326
        Rule Title : SQL Server must generate Trace or Audit records when privileges/permissions are added.
        DiscussMD5 : 06488FB05A967BF8B9DD7B65401E4A3E
        CheckMD5   : D887881A9FB84EA8A1F6961ADCD85ABC
        FixMD5     : 1CDFD0621E63D5B6EA4D82DF8D4BE965
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
        $AANames =  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                    'DATABASE_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_PERMISSION_CHANGE_GROUP',
                    'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_PERMISSION_CHANGE_GROUP',
                    'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_ACCESS_GROUP'
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_ACCESS_GROUP'
            );
        "

        $AANamesRC = Compare-Object $AANames $res.audit_action_name
        $AResultSF = $res.audited_result -eq "SUCCESS AND FAILURE"

        If ($res -and !$AANamesRC -and $AResultSF) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            42
            43
            90
            102
            103
            104
            105
            108
            109
            110
            111
            162
            170
            171
            172
            173
            177
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213884 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213884
        STIG ID    : SQL4-00-036100
        Rule ID    : SV-213884r961800_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000327
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to add privileges/permissions occur.
        DiscussMD5 : 545EA3C3B6BCA171BC148B21B48B8C1A
        CheckMD5   : 3362D9F4B784A60E4C3601BCC3C63844
        FixMD5     : 1CDFD0621E63D5B6EA4D82DF8D4BE965
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
        $AANames =  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                    'DATABASE_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_PERMISSION_CHANGE_GROUP',
                    'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_PERMISSION_CHANGE_GROUP',
                    'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_ACCESS_GROUP'
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_ACCESS_GROUP'
            );
        "

        $AANamesRC = Compare-Object $AANames $res.audit_action_name
        $AResultSF = $res.audited_result -eq "SUCCESS AND FAILURE"

        If ($res -and !$AANamesRC -and $AResultSF) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            42
            43
            90
            102
            103
            104
            105
            108
            109
            110
            111
            162
            170
            171
            172
            173
            177
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213885 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213885
        STIG ID    : SQL4-00-036900
        Rule ID    : SV-213885r961812_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-DB-000330
        Rule Title : SQL Server must generate Trace or Audit records when privileges/permissions are deleted.
        DiscussMD5 : DC2270964CB25C50770D8E4AE070F30C
        CheckMD5   : 2FD3BBF98C934028B74A5C333537E007
        FixMD5     : C214E8997638FB46069E3AA1D10752C8
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
        $AANames =  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                    'DATABASE_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_PERMISSION_CHANGE_GROUP',
                    'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_PERMISSION_CHANGE_GROUP',
                    'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_ACCESS_GROUP'
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_ACCESS_GROUP'
            );
        "

        $AANamesRC = Compare-Object $AANames $res.audit_action_name
        $AResultSF = $res.audited_result -eq "SUCCESS AND FAILURE"

        If ($res -and !$AANamesRC -and $AResultSF) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            42
            43
            90
            102
            103
            104
            105
            108
            109
            110
            111
            162
            170
            171
            172
            173
            177
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213886 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213886
        STIG ID    : SQL4-00-037000
        Rule ID    : SV-213886r961812_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-DB-000331
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to delete privileges/permissions occur.
        DiscussMD5 : D992DB8B9936B84F054B93BE267FB679
        CheckMD5   : 06A39011A0284AB8D82ECAD6678FF66E
        FixMD5     : 23D9D1D2BFD7BC2B3C31AA4A5F4F96D9
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
        $AANames =  'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
                    'DATABASE_OWNERSHIP_CHANGE_GROUP',
                    'DATABASE_PERMISSION_CHANGE_GROUP',
                    'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
                    'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
                    'SERVER_PERMISSION_CHANGE_GROUP',
                    'SERVER_ROLE_MEMBER_CHANGE_GROUP',
                    'SCHEMA_OBJECT_ACCESS_GROUP'
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
            'DATABASE_OWNERSHIP_CHANGE_GROUP',
            'DATABASE_PERMISSION_CHANGE_GROUP',
            'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
            'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
            'SERVER_PERMISSION_CHANGE_GROUP',
            'SERVER_ROLE_MEMBER_CHANGE_GROUP',
            'SCHEMA_OBJECT_ACCESS_GROUP'
            );
        "

        $AANamesRC = Compare-Object $AANames $res.audit_action_name
        $AResultSF = $res.audited_result -eq "SUCCESS AND FAILURE"

        If ($res -and !$AANamesRC -and $AResultSF) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            42
            43
            90
            102
            103
            104
            105
            108
            109
            110
            111
            162
            170
            171
            172
            173
            177
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213887 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213887
        STIG ID    : SQL4-00-037500
        Rule ID    : SV-213887r961824_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-DB-000350
        Rule Title : SQL Server must generate Trace or Audit records when successful logons or connections occur.
        DiscussMD5 : 4258C5233A7D6A70C8D37313F5680714
        CheckMD5   : AFAA1AA7EDEF5189B303E5C14280902D
        FixMD5     : E61661DA69EAC53DEA6F5B7008DC90A3
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
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'SUCCESSFUL_LOGIN_GROUP'
            );
        "

        If ($res.audited_result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            14
            15
            16
            17
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213888 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213888
        STIG ID    : SQL4-00-037600
        Rule ID    : SV-213888r961824_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-DB-000351
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful logons or connection attempts occur.
        DiscussMD5 : 6A1374D39B7D5F354AC0544ECC2C9D2C
        CheckMD5   : 040C4670BD44804AF1878FD9B05F88F1
        FixMD5     : 2A0E7E5D306F8E7063FE8120641191DA
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
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'FAILED_LOGIN_GROUP'
            );
        "

        If ($res.audited_result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            20
        "

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
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213889 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213889
        STIG ID    : SQL4-00-037700
        Rule ID    : SV-213889r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000354
        Rule Title : SQL Server must generate Trace or Audit records for all privileged activities or other system-level access.
        DiscussMD5 : FC6D8D572655FFA8DA7072C3D8322ED8
        CheckMD5   : CF385FC9317A21B8F5558567BF36B13C
        FixMD5     : BBE1DC2562198C001B967ABB9CE69DBE
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
        $AANames =  'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
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
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            46
            47
            90
            115
            116
            117
            118
            128
            129
            130
            131
            164
            170
            171
            172
            173
            175
            176
            177
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213890 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213890
        STIG ID    : SQL4-00-037800
        Rule ID    : SV-213890r961827_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000355
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.
        DiscussMD5 : A9AE5E85350CF82794D045C9C550596B
        CheckMD5   : 99AB93668398D48567C8A1D986A2EE1F
        FixMD5     : BBE1DC2562198C001B967ABB9CE69DBE
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
        $AANames =  'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
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
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            46
            47
            90
            115
            116
            117
            118
            128
            129
            130
            131
            164
            170
            171
            172
            173
            175
            176
            177
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213891 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213891
        STIG ID    : SQL4-00-037900
        Rule ID    : SV-213891r961830_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000505-DB-000352
        Rule Title : SQL Server must generate Trace or Audit records when logoffs or disconnections occur.
        DiscussMD5 : 44586DECECBD8E24FA8A22CC0C94F9BC
        CheckMD5   : 7E38D7E91023835A1DE0119665EF32D9
        FixMD5     : 092171863749C871BC0830F3D134DCD2
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
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'LOGOUT_GROUP'
            );
        "

        If ($res.audited_result -eq "SUCCESS AND FAILURE") {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            14
            15
            16
            17
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Trace exists and does not contain the event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213892 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213892
        STIG ID    : SQL4-00-038000
        Rule ID    : SV-213892r961833_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000506-DB-000353
        Rule Title : SQL Server must generate Trace or Audit records when concurrent logons/connections by the same user from different workstations occur.
        DiscussMD5 : ED9B6AD0656843C188D0333F2D5EB1C5
        CheckMD5   : 16AAF99B39F220B3D6DE32B9A0BFEAD4
        FixMD5     : CC91273B85593C268475833C39CF700B
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
        $AANames =  'SUCCESSFUL_LOGIN_GROUP',
                    'LOGOUT_GROUP'
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT audit_action_name, audited_result FROM sys.server_audit_specification_details WHERE audit_action_name IN
            (
            'SUCCESSFUL_LOGIN_GROUP',
            'LOGOUT_GROUP'
            );
        "

        $AANamesRC = Compare-Object $AANames $res.audit_action_name
        $AResultSF = $res.audited_result -eq "SUCCESS AND FAILURE"

        If ($res -and !$AANamesRC -and $AResultSF) {
            $Status = 'NotAFinding'
            $FindingDetails = "The audits are performed with SUCCESS and FAILURE.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $FindingDetails = "Audit exists however either audits or SUCCESS and FAILURE is missing. Review your system documentation.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }

    If ($NonDefTrace -AND $Status -eq "Not_Reviewed") {
        $TraceEIDs = "
            14
            15
            16
            17
        "

        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo($TraceID);
        "

        Foreach ($item in $TraceEIDs) {
            If ($res.eventid -notcontains $item) {
                $IsContainedIn = $false
                Break
            }
        }#If all required traceids are present $iscontainedin will not exist

        If (!$IsContainedIn) {
            $Status = "NotAFinding"
            $FindingDetails = "Trace exists and contains event ids specified in the check text.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
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

Function Get-V213894 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213894
        STIG ID    : SQL4-00-038900
        Rule ID    : SV-213894r981946_rule
        CCI ID     : CCI-000192, CCI-000193, CCI-000194, CCI-000195, CCI-000205, CCI-001619
        Rule Name  : SRG-APP-000164-DB-000401
        Rule Title : If SQL Server authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password complexity.
        DiscussMD5 : 83C828BC7D49296F9579FA1A2059CBE2
        CheckMD5   : 636BFB0EDCE9AD4A73545DD95B2DD6F2
        FixMD5     : 16B235684ABF21D5F4728177D3106F3D
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
    SELECT [name], is_disabled, is_policy_checked
        FROM sys.sql_logins
        WHERE
            type_desc = 'SQL_LOGIN'
            AND is_disabled = 0
            AND is_policy_checked = 0 ; "
    If (!$res) {
        $Status = "NotAFinding"
        $FindingDetails = "No account names are listed from the check query, this is not a finding."
    }
    Else {
        $FindingDetails = "For each account name listed, determine whether it is documented as requiring exemption from the standard password complexity rules, if it is not, this is a finding.:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213895 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213895
        STIG ID    : SQL4-00-038910
        Rule ID    : SV-213895r981946_rule
        CCI ID     : CCI-000198, CCI-000199, CCI-000200
        Rule Name  : SRG-APP-000164-DB-000401
        Rule Title : If SQL Server authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password lifetime.
        DiscussMD5 : 485BB1CB8C2ACAE78A458CFC06116185
        CheckMD5   : 3B89D487FDF8364FE0E4B5DCC2E291F9
        FixMD5     : C0CE6BD145D7B5D40A046870038D1961
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
    SELECT [name], is_disabled, is_expiration_checked
        FROM sys.sql_logins
        WHERE
            type_desc = 'SQL_LOGIN'
            AND is_disabled = 0
            AND is_expiration_checked = 0 ; "
    If (!$res) {
        $Status = "NotAFinding"
        $FindingDetails = "No account names are listed from the check query, this is not a finding."
    }
    Else {
        $FindingDetails = "For each account name listed, determine whether it is documented as requiring exemption from the standard password lifetime rules, if it is not, this is a finding.:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213897 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213897
        STIG ID    : SQL4-00-039020
        Rule ID    : SV-213897r961047_rule
        CCI ID     : CCI-000206
        Rule Name  : SRG-APP-000178-DB-000083
        Rule Title : When using command-line tools such as SQLCMD in a mixed-mode authentication environment, users must use a logon method that does not expose the password.
        DiscussMD5 : 70CB57DE6C0D76A13EEFC565DE4E82DF
        CheckMD5   : 2AC06085EEB097A4A4AD1822B3E23EE1
        FixMD5     : 910263D603463E59EC44A101FF7A2DA5
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
    # Changed to use the passed-in instance name instead of asking SQL for a list of instances. Ken Row, 04/04/25, Issue 2188

    $res = Get-ISQL -ServerInstance $Instance "EXEC master.sys.XP_LOGINCONFIG 'login mode'"
    if ($res.config_value -ne 'Windows NT Authentication') {
        $Status = "Open"
        $FindingDetails += "Instance $h's login authention mode is $($res.config_value) instead of Windows Authentication.`n"
    }
    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "Windows NT Authentication is being used."
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

Function Get-V213898 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213898
        STIG ID    : SQL4-00-039100
        Rule ID    : SV-213898r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : The SQL Server Browser service must be disabled if its use is not necessary..
        DiscussMD5 : 7F2B5C79D86E3859AB596E26B9A3A2C2
        CheckMD5   : 0741FDEA64FC6C947694F069391F8DA7
        FixMD5     : 6AA719BFC7850F665DFA451E06521AAE
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
    $res = Get-Service SQLBrowser | Select-Object name, status, startType
    if ($res) {
        if ($res.StartType -eq 'Disabled') {
            $Status = "NotAFinding"
            $FindingDetails = "The SQL Browser is disabled.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        else {
            $Status = "Not_Reviewed"
            $FindingDetails = "The SQL Browser service is not disabled, but if it has been documented and approved as required, this is not a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        }
    }
    else {
        $Status = "Not_Reviewed"
        $FindingDetails = "Could not find the SQL Browser service."
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

Function Get-V265639 {
    <#
    .DESCRIPTION
        Vuln ID    : V-265639
        STIG ID    : SQL4-00-039200
        Rule ID    : SV-265639r998191_rule
        CCI ID     : CCI-003376
        Rule Name  : SRG-APP-000456-DB-000400
        Rule Title : Microsoft SQL Server products must be a version supported by the vendor.
        DiscussMD5 : 00404D707506EF90504F0639D347FBE7
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC9XzNjndCOmUE5
# kt7PYxFlKMigTr6kNHAinLkJgR+YRKCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCChutxWMWplywXsMwtv7PwEZjLsQIukRTisNy8KOzZXYjANBgkqhkiG9w0BAQEF
# AASCAQCFvrA7twNKdmJnnFmfPw8wEVKgmH1wbOKAWMNlr7Jf/WfZs4IKYAI/VZ70
# 0anD1pewqYsBL5n7jF7frVVS9pKS1h+BMB2cwK0yBoAeODehDEP9FGwi5QIuCpgK
# Uklpb1iczRt+gRL5uySUxG0GrDve9uL7myb9pCRnpLawcKb38OXHpPakoSK1WLPN
# oIx6ozAHA2xIqHyIQir+Z+FU9Ep6pDVTk9sNA0WvLarcPGvser7GIjr23aN8tGui
# h55Iulv3iCXBTUva9WSq7I/eo19GxFZxzGXWXemraucfMm8Nnldm6rgW3MYnCNT6
# KvlwlHGxbMRybM0YYiLm6ht5LjZfoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTc1OFowLwYJKoZIhvcNAQkEMSIEID+inlImTsuQYOQZEeMMqzo1qQN3
# lASXejgADBdhQUjGMA0GCSqGSIb3DQEBAQUABIICAE09jskt/g9nIP5Rl84X9cr2
# rEbx2o7kVb/QmOTpiP8XsaJNsNXlI0waAX3cnCmxHse2wOIeRiiCfUhLGIcCQK91
# qQsQaaEkilfAiw9QES/Nbyt8ffKcQ1ev/5OSb5AAthQgnVwoXrOGRMH7qQOYWsp6
# yp2dg62aymaQIH9Zu9jR6yy+byldZVstlbPn+cZNTe2wJ9iqoVW9K4fyPIsWO/xb
# YCedQJtq4wVuELgJ+7MLF4LZ3OCAsMZXMkjG7HZ6DVrJj59joWVXJ6gCrmNcvhsh
# 80+ycBrPRUUTf1x38p1LjhVyw8M6IdzQDrNgSjeO/gFz1phB/vmfL/4AGZ2Lriht
# dF2pprY/ovpWxj9+v2IW6XXyeZJulWqhTxWcB8aB/bTVHFYjWLf/dJawBcaTE/t+
# pcvcQJCl86nK+Mr3KVYEzVphQY58t/MxTpS25t0ZC6rwBThGdF61ioHSXHKyDxpT
# 08rDBwnViKTMGo8glkCn2LEWuN0JY45Gih9JFK+Rm+Xt5VySLHtKqut9eMVN2U9+
# l68nrFQ9rfV7nGnblNxVYT08QHUXq4ICTxuZFNHDLMT3gtV0tH5UkYscVFVPrX6N
# V7o+g1U2Rm14upOr43W5X79lrOLTK5nEl0iPmUG12TUYNmiV6omSwGYc/GesqTOO
# nRUgwKt8vw4k1bEvkzDl
# SIG # End signature block
