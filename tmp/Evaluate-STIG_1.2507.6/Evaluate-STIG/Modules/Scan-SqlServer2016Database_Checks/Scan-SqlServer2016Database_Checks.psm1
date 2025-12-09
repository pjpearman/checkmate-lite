##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MS SQL Server 2016 Database
# Version:  V3R3
# Class:    UNCLASSIFIED
# Updated:  9/10/2025
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

$PSDefaultParameterValues['out-string:width'] = 200

$sqldbLastInstance = ''
$sqldbAdmin = $false

Function sqldbCheckAdmin {
    # New function to adjust FindingDetails and Status if the user is not a SysAdmin.
    param (
        [Parameter(Mandatory = $true)][String]$Instance,
        [Parameter(Mandatory = $true)][Ref]$FindingDetails,
        [Parameter(Mandatory = $true)][Ref]$Status
    )

    if ($sqldbLastInstance -ne $Instance) {
        $res = Get-ISQL -ServerInstance $Instance -Database 'master' "select 1 where IS_SRVROLEMEMBER('sysadmin') = 1"
        $sqldbadmin = [bool]($res)
    }
    if (! $sqldbadmin) {
        $fd = $FindingDetails.Value
        $FindingDetails.Value = "Note: Eval-STIG was run without SQL SysAdmin privileges, so these results might not be accurate. Rerun Eval-STIG using an account with SysAdmin privileges.`n`n$fd"
        if ($Status.Value -in 'NotaFinding','Not_Applicable') {
            $Status.Value = "Not_Reviewed"
        }
    }
}

Function Get-V213900 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213900
        STIG ID    : SQL6-D0-000100
        Rule ID    : SV-213900r1043176_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : SQL Server databases must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.
        DiscussMD5 : 7FC4C2C0F6D9636B40A83E1363B6210C
        CheckMD5   : 1127A92D57D25353BFBB00A96BA0B0D5
        FixMD5     : 47D9DE68DEB3FA4318AFDF1C2FBCB7EB
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737
    # Revised to Y25M07. Ken Row, 7/24/25, Issue 2409

    # Check for contained databases...
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "EXEC sp_configure 'contained database authentication'"
    if ($res.run_value -eq 0 -and $res.config_value -eq 0) {
        $FindingDetails += "Instance does not have Contained Databases enabled.`n"
        $status = 'NotAFinding'
    }
    else {
        # Check authentication mode...
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
                WHEN 1 THEN 'Windows Authentication'
                WHEN 0 THEN 'Windows and SQL Server Authentication'
            END as AuthenticationMode
        "
        if ($res.AuthenticationMode -eq 'Windows Authentication') {
            $FindingDetails += "Contained Databases are enabled, but Windows Authentication is used.`n"
            $status = 'NotAFinding'
        }
        else {
            $FindingDetails += "The instance allows Mixed Authentication. Confirm this is documented as necessary and approved by the ISSO/ISSM.`n"

            # List the accounts managed by SQL server...
            $res = Get-ISQL -ServerInstance $Instance -Database $Database "
                select @@servername, name
                    from sys.database_principals
                WHERE type_desc = 'SQL_USER'
                    AND authentication_type_desc = 'DATABASE'
            "
            if ($res) {
                $FindingDetails += "Also, ensure the following accounts are documented as authorized to be managed by SQL Server:`n$($res | Format-Table -AutoSize | Out-String)"
            }
        }
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213901 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213901
        STIG ID    : SQL6-D0-000300
        Rule ID    : SV-213901r1112497_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-DB-000084
        Rule Title : SQL Server must enforce approved authorizations for logical access to database information and system resources in accordance with applicable access control policies.
        DiscussMD5 : 7DF88A644477D5202A9EEEAB5D2F9640
        CheckMD5   : 47E52A601973184C5C729210B4CE51BD
        FixMD5     : 34E7EF8E07AB1BF83551B1C9B9947C55
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
    # Changed to run the supplemental queries and put the results in the finding details. Ken Row, 4/29/2025, Issue 1835
    # Revised to Y25M07. Ken Row, 7/24/25, Issue 2409

    If ($Database -eq "tempdb") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is the '$Database' database so this requirement is NA."
    } else {
        $qryOwner = "
            SELECT ISNULL(SUSER_SNAME(owner_sid),'*** Unknown Database Owner ***') AS database_owner
              FROM sys.databases
             WHERE database_id = DB_ID() AND database_id <> 2
        "
        $qryPrivs = "
            SELECT
	            CASE
		            WHEN P1.type_desc IS NULL THEN '*** Unknown Grantee Type : ' + CONVERT(VARCHAR,DP.grantee_principal_id) + ' ***'
		            ELSE P1.type_desc
	            END AS grantee_type,
	            CASE
		            WHEN P1.name IS NULL THEN '*** Unknown Grantee : ' + CONVERT(VARCHAR,DP.grantee_principal_id) + ' ***'
		            ELSE P1.name
	            END AS grantee,
	            DP.state_desc,
	            DP.permission_name,
	            CASE
		            WHEN DP.class_desc = 'OBJECT_OR_COLUMN' AND DP.minor_id = 0 THEN COALESCE(AO.type_desc,'OBJECT')
		            WHEN DP.class_desc = 'OBJECT_OR_COLUMN' AND DP.minor_id > 0 THEN 'COLUMN'
		            ELSE DP.class_desc
	            END AS securable_class,
	            CASE
		            WHEN DP.class_desc = 'DATABASE' THEN ''
		            WHEN DP.class_desc = 'OBJECT_OR_COLUMN' AND SCHEMA_NAME(AO.schema_id) IS NULL THEN ''
		            WHEN DP.class_desc = 'OBJECT_OR_COLUMN' THEN SCHEMA_NAME(AO.schema_id)
		            WHEN DP.class_desc = 'SCHEMA' THEN (SELECT sdp.name FROM sys.schemas s JOIN sys.database_principals sdp ON s.principal_id = sdp.principal_id WHERE s.schema_id = DP.major_id)
		            WHEN DP.class_desc = 'DATABASE_PRINCIPAL' THEN ''
		            WHEN DP.class_desc = 'ASSEMBLY' THEN (SELECT adp.name FROM sys.assemblies a JOIN sys.database_principals adp ON a.principal_id = adp.principal_id WHERE a.assembly_id = DP.major_id)
		            WHEN DP.class_desc = 'TYPE' THEN (SELECT SCHEMA_NAME(schema_id) FROM sys.types WHERE user_type_id = DP.major_id)
		            WHEN DP.class_desc = 'XML_SCHEMA_COLLECTION' THEN (SELECT SCHEMA_NAME(schema_id) FROM sys.xml_schema_collections WHERE xml_collection_id = DP.major_id)
		            WHEN DP.class_desc = 'MESSAGE_TYPE' THEN (SELECT mtdp.name FROM sys.service_message_types mt JOIN sys.database_principals mtdp ON mt.principal_id = mtdp.principal_id WHERE mt.message_type_id = DP.major_id)
		            WHEN DP.class_desc = 'SERVICE_CONTRACT' THEN (SELECT scdp.name FROM sys.service_contracts sc JOIN sys.database_principals scdp ON sc.principal_id = scdp.principal_id WHERE sc.service_contract_id = DP.major_id)
		            WHEN DP.class_desc = 'SERVICE' THEN (SELECT svdp.name FROM sys.services sv JOIN sys.database_principals svdp ON sv.principal_id = svdp.principal_id WHERE sv.service_id = DP.major_id)
		            WHEN DP.class_desc = 'REMOTE_SERVICE_BINDING' THEN (SELECT rsbdp.name FROM sys.remote_service_bindings rsb JOIN sys.database_principals rsbdp ON rsb.principal_id = rsbdp.principal_id WHERE rsb.remote_service_binding_id = DP.major_id)
		            WHEN DP.class_desc = 'ROUTE' THEN (SELECT rdp.name FROM sys.routes r JOIN sys.database_principals rdp ON r.principal_id = rdp.principal_id WHERE r.route_id = DP.major_id)
		            WHEN DP.class_desc = 'FULLTEXT_CATALOG' THEN (SELECT ftdp.name FROM sys.fulltext_catalogs ft JOIN sys.database_principals ftdp ON ft.principal_id = ftdp.principal_id WHERE ft.fulltext_catalog_id = DP.major_id)
		            WHEN DP.class_desc = 'SYMMETRIC_KEYS' THEN (SELECT skdp.name FROM sys.symmetric_keys sk JOIN sys.database_principals skdp ON sk.principal_id = skdp.principal_id WHERE sk.symmetric_key_id = DP.major_id)
		            WHEN DP.class_desc = 'CERTIFICATE' THEN (SELECT cdp.name FROM sys.certificates c JOIN sys.database_principals cdp ON c.principal_id = cdp.principal_id WHERE c.certificate_id = DP.major_id)
		            WHEN DP.class_desc = 'ASYMMETRIC_KEY' THEN (SELECT akdp.name FROM sys.asymmetric_keys ak JOIN sys.database_principals akdp ON ak.principal_id = akdp.principal_id WHERE ak.asymmetric_key_id = DP.major_id)
		            WHEN DP.class_desc = 'FULLTEXT_STOPLIST' THEN (SELECT ftsdp.name FROM sys.fulltext_stoplists fts JOIN sys.database_principals ftsdp ON fts.principal_id = ftsdp.principal_id WHERE fts.stoplist_id = DP.major_id)
		            WHEN DP.class_desc = 'SEARCH_PROPERTY_LIST' THEN (SELECT spdp.name FROM sys.registered_search_property_lists sp JOIN sys.database_principals spdp ON sp.principal_id = spdp.principal_id WHERE sp.property_list_id = DP.major_id)
		            ELSE '*** Unknown ***'
	            END AS schema_or_owner,
	            CASE
		            WHEN DP.class_desc = 'DATABASE' THEN DB_NAME()
		            WHEN DP.class_desc = 'OBJECT_OR_COLUMN' AND SCHEMA_NAME(AO.schema_id) IS NULL THEN '*** Internal Hidden Object : ' + CONVERT(VARCHAR,DP.major_id) + ' ***'
		            WHEN DP.class_desc = 'OBJECT_OR_COLUMN' THEN OBJECT_NAME(AO.object_id)
		            WHEN DP.class_desc = 'SCHEMA' THEN (SELECT SCHEMA_NAME(schema_id) FROM sys.schemas WHERE schema_id = DP.major_id)
		            WHEN DP.class_desc = 'DATABASE_PRINCIPAL' THEN (SELECT dp1dp.name FROM sys.database_permissions dp1 JOIN sys.database_principals dp1dp ON dp1dp.principal_id = dp1.major_id WHERE dp1dp.principal_id = DP.major_id AND dp1.grantee_principal_id = DP.grantee_principal_id)
		            WHEN DP.class_desc = 'ASSEMBLY' THEN (SELECT a.name FROM sys.assemblies a JOIN sys.database_principals adp ON a.principal_id = adp.principal_id WHERE a.assembly_id = DP.major_id)
		            WHEN DP.class_desc = 'TYPE' THEN (SELECT name from sys.types WHERE user_type_id = DP.major_id)
		            WHEN DP.class_desc = 'XML_SCHEMA_COLLECTION' THEN (SELECT name FROM sys.xml_schema_collections WHERE xml_collection_id = DP.major_id)
		            WHEN DP.class_desc = 'MESSAGE_TYPE' THEN (SELECT name FROM sys.service_message_types WHERE message_type_id = DP.major_id)
		            WHEN DP.class_desc = 'SERVICE_CONTRACT' THEN (SELECT name from sys.service_contracts WHERE service_contract_id = DP.major_id)
		            WHEN DP.class_desc = 'SERVICE' THEN (SELECT name FROM sys.services WHERE service_id = DP.major_id)
		            WHEN DP.class_desc = 'REMOTE_SERVICE_BINDING' THEN (SELECT name FROM sys.remote_service_bindings WHERE remote_service_binding_id = DP.major_id)
		            WHEN DP.class_desc = 'ROUTE' THEN (SELECT name FROM sys.routes WHERE route_id = DP.major_id)
		            WHEN DP.class_desc = 'FULLTEXT_CATALOG' THEN (SELECT name FROM sys.fulltext_catalogs WHERE fulltext_catalog_id = DP.major_id)
		            WHEN DP.class_desc = 'SYMMETRIC_KEYS' THEN (SELECT name FROM sys.symmetric_keys WHERE symmetric_key_id = DP.major_id)
		            WHEN DP.class_desc = 'CERTIFICATE' THEN (SELECT name FROM sys.certificates WHERE certificate_id = DP.major_id)
		            WHEN DP.class_desc = 'ASYMMETRIC_KEY' THEN (SELECT name FROM sys.asymmetric_keys WHERE asymmetric_key_id = DP.major_id)
		            WHEN DP.class_desc = 'FULLTEXT_STOPLIST' THEN (SELECT name FROM sys.fulltext_stoplists WHERE stoplist_id = DP.major_id)
		            WHEN DP.class_desc = 'SEARCH_PROPERTY_LIST' THEN (SELECT name FROM sys.registered_search_property_lists WHERE property_list_id = DP.major_id)
		            ELSE '*** Unknown ***'
	            END COLLATE DATABASE_DEFAULT AS securable,
	            CASE
		            WHEN DP.minor_id > 0 THEN AC.name
		            ELSE ''
	            END AS column_name,
                P2.type_desc AS grantor_type,
	            P2.name AS grantor
            FROM
                sys.database_permissions DP
	            LEFT OUTER JOIN sys.all_objects AO
		            ON  DP.major_id = AO.object_id
	            LEFT OUTER JOIN sys.all_columns AC
                    ON  AC.object_id = DP.major_id
                    AND AC.column_id = DP.minor_id
                LEFT OUTER JOIN sys.database_principals P1
                    ON  P1.principal_id = DP.grantee_principal_id
                LEFT OUTER JOIN sys.database_principals P2
                    ON  P2.principal_id = DP.grantor_principal_id
            WHERE
	            (DB_ID() <> 2 AND (DP.major_id >= 0 OR P1.name <> 'public'))
	            OR DB_ID() = 1
        "
        $qryRoles = "
            SELECT
                R.name  AS database_role,
                M.name  AS role_member
            FROM
                sys.database_role_members X
                INNER JOIN sys.database_principals R ON R.principal_id = X.role_principal_id
                INNER JOIN sys.database_principals M ON M.principal_id = X.member_principal_id
            WHERE DB_ID() <> 2
        "

        $resOwner = Get-ISQL -ServerInstance $Instance -Database $Database  $qryOwner
        $resPrivs = Get-ISQL -ServerInstance $Instance -Database $Database "$qryPrivs ORDER BY grantee, schema_or_owner, securable"
        $resRoles = Get-ISQL -ServerInstance $Instance -Database $Database  $qryRoles
        $resCount = Get-ISQL -ServerInstance $Instance -Database $Database "
            select QueryType = 'Owner',      ResultCount = count(*), CheckSum = checksum_agg(checksum(*)) from ($qryOwner) as subOwner
            union all
            select QueryType = 'Privileges', ResultCount = count(*), CheckSum = checksum_agg(checksum(*)) from ($qryPrivs) as subPrivs
            union all
            select QueryType = 'Roles',      ResultCount = count(*), CheckSum = checksum_agg(checksum(*)) from ($qryRoles) as subRoles
            order by 1
        "

        $FindingDetails = "Review the system documentation to determine the required levels of protection for securables in the database by type of user, then compare that against the following permissions actually in place in the database. If the actual permissions do not match the documented requirements, this is a finding.

Here are the row counts and checksums for the three queries in the supplemental STIG file 'Database permission assignments to users and roles.sql':`n$($resCount | Format-Table -AutoSize | Out-String)
Details for the Database Owner query:`n$($resOwner | Format-Table -AutoSize| Out-String)
Details for the Database Roles query:`n$($resRoles | Format-Table -AutoSize| Out-String)
Details for the Privileges query:    `n$($resPrivs | Format-Table -AutoSize| Out-String)
"
    } # If ($Database -eq "tempdb")
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

Function Get-V213902 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213902
        STIG ID    : SQL6-D0-000400
        Rule ID    : SV-213902r960864_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the database.
        DiscussMD5 : 65D29485673D50AB20BF56A9FE981C15
        CheckMD5   : 489BEA7B6637CBFA62B505A924157D1C
        FixMD5     : 8B9142449F0FC17EB620EFC3E8D4C177
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $fComputer = $fUnknown = $false
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT name as UserName
          FROM sys.database_principals
         WHERE type in ('U','G')
           AND name LIKE '%$'
    "
    if ($res) {
        $outarray = @()
        $res | ForEach-Object {
            $sUID = $_.username
            $sShortUID = $sUID -replace '^.*\\', '' -replace '\$$', ''

            try {
                $sType = ([ADSISearcher]"(name=${sShortUID})").findone().Properties['ObjectCategory'].item(0) -replace ',.*$', '' -replace '^CN=', ''
            }
            catch {
                $sType = ''
            }
            if ($sType) {
                $outarray += [pscustomobject]@{Name = $sUID; ADType = $sType}
                if ($stype -eq 'Computer') {
                    $fComputer = $true
                }
            }
            else {
                $outarray += [pscustomobject]@{name = $sUID; ADType = 'Indeterminable, needs analyst review'}
                $fUnknown = $true
            }
        }

        $FindingDetails = "The following accounts were found in SQL and checked against AD:`n$($outarray | Format-Table -HideTableHeaders -AutoSize| Out-String)"
        if ($fUnknown) {
            $FindingDetails += "At least one account NEEDS REVIEWED."
            $Status = "Not_Reviewed"
        }
        elseif ($fComputer) {
            $FindingDetails += "OPEN because at least one computer account was found."
            $Status = "Open"
        }
        else {
            $FindingDetails += "NOT A FINDING: No computer accounts were found."
            $Status = "NotAFinding"
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "NOT A FINDING: The check query returned no results."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213903 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213903
        STIG ID    : SQL6-D0-000500
        Rule ID    : SV-213903r960864_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by use of system-versioned tables (Temporal Tables).
        DiscussMD5 : 7441CAD39A3A04034F8B9DC32ED8C37C
        CheckMD5   : 6D96FD5E6353E1162A4926F88C14802A
        FixMD5     : 04D7D8FBD50CAEE7D6E9EBBD24D5A3B4
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc, SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
        FROM sys.tables T
        JOIN sys.tables H ON T.history_table_id = H.object_id
        WHERE T.temporal_type != 0
        ORDER BY schema_name, table_name
    "
    $FindingDetails += "DBA, Using the system documentation, determine which tables in this database are required to be temporal tables.`n`n"
    if ($res) {
        $FindingDetails += "If any tables listed in the documentation are not in this list, this is a finding.:`n$($res | Format-Table -AutoSize| Out-String)"
    } else {
        $FindingDetails += "If the documentation lists any tables at all, mark this vulnerability as a finding because no such tables exist."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213904 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213904
        STIG ID    : SQL6-D0-000600
        Rule ID    : SV-213904r960864_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by ensuring databases are not in a trust relationship.
        DiscussMD5 : EF61961F0A45A02D8F40A7DC7D4463F8
        CheckMD5   : 22CC6947EBA9D7403460DD0A7E56BB6B
        FixMD5     : D3E964A7163F4E4CB7761773B7790EC3
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@SERVERNAME               as InstanceName
            , DB_NAME()                  AS [Database]
            , SUSER_SNAME(d.owner_sid)   AS DatabaseOwner
            , CASE
                WHEN role.name IN ('sysadmin','securityadmin')
                OR permission.permission_name = 'CONTROL SERVER'
                THEN 'YES'
                ELSE 'No'
            END AS 'IsOwnerPrivileged'
        FROM sys.databases d
        LEFT JOIN sys.server_principals login ON d.owner_sid = login.sid
        LEFT JOIN sys.server_role_members rm ON login.principal_id = rm.member_principal_id
        LEFT JOIN sys.server_principals role ON rm.role_principal_id = role.principal_id
        LEFT JOIN sys.server_permissions permission ON login.principal_id = permission.grantee_principal_id
        WHERE d.name = DB_NAME()
        AND DB_NAME() <> 'msdb'
        AND D.is_trustworthy_on = 1
    "
    if (!$res) {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    else {
        $FindingDetails = "DBA, Confirm that an approved server documentation documents the need for TRUSTWORTHY in the following:$($res | Format-Table | Out-String)"
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213905 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213905
        STIG ID    : SQL6-D0-000700
        Rule ID    : SV-213905r960882_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
        DiscussMD5 : 399867828DF606C19B45A8014399DEE3
        CheckMD5   : ED8D4962CDD3D8045AD1D17B2B283C3E
        FixMD5     : 6CEAE3AF9B65200A1B70608302D3FC2C
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    # Check for accounts with the db_owner role...
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT
        R.name AS role_name,
        RM.name AS role_member_name,
        RM.type_desc
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON
        R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals RM ON
        DRM.member_principal_id = RM.principal_id
        WHERE R.type = 'R'
        AND R.name = 'db_owner'
        ORDER BY role_member_name
    " | Sort-Object -Unique role_member_name
    if ($res) {
        if ($res.role_name.count -eq 1 -and $res.role_member_name -eq 'dbo') {
            $FindingDetails = "The only account authorized to act as a db owner is 'dbo', but DISA still requires it be documented as authorized:`n$($res | Format-Table | Out-String)"
        }
        else {
            $FindingDetails = "DBA, Confirm that the following accounts are documented as authorized to act as database owners:`n$($res | Format-Table | Out-String)"
        }
    } # if ($res)

    # Check for accounts with the CONTROL or ALTER ANY DATABASE AUDIT privileges...
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT
        PERM.permission_name,
        DP.name AS principal_name,
        DP.type_desc AS principal_type,
        DBRM.role_member_name
        FROM sys.database_permissions PERM
        JOIN sys.database_principals DP ON PERM.grantee_principal_id = DP.principal_id
        LEFT OUTER JOIN (
        SELECT
        R.principal_id AS role_principal_id,
        R.name AS role_name,
        RM.name AS role_member_name
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals RM ON DRM.member_principal_id = RM.principal_id
        WHERE R.type = 'R'
        ) DBRM ON DP.principal_id = DBRM.role_principal_id
        WHERE PERM.permission_name IN ('CONTROL','ALTER ANY DATABASE AUDIT')
        ORDER BY
        permission_name,
        principal_name,
        role_member_name
    " | Sort-Object -Unique permission_name, principal_name, role_member_name
    if ($res) {
        if ($res.permission_name.count -eq 1) {
            $FindingDetails += "DBA, Confirm that the following account is documented as authorized to administer audits:`n$($res | Format-Table | Out-String)"
        }
        else {
            $FindingDetails += "DBA, Confirm that the following accounts are documented as authorized to administer audits:`n$($res | Format-Table | Out-String)"
        }
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213906 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213906
        STIG ID    : SQL6-D0-001100
        Rule ID    : SV-213906r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must limit privileges to change software modules, to include stored procedures, functions, and triggers.
        DiscussMD5 : 39B6782765F128EC0472D2F036E28EA9
        CheckMD5   : 2513A93FF04F36CC007391EB3B946EB5
        FixMD5     : F6BACF21AD37E05EDCE860A7854E1131
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , P.type_desc AS principal_type
            , P.name AS principal_name
            , O.type_desc
            , CASE class
                WHEN 0 THEN DB_NAME()
                WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
                WHEN 3 THEN SCHEMA_NAME(major_id)
                ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
            END AS securable_name, DP.state_desc, DP.permission_name
        FROM sys.database_permissions DP
            JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
            LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id
                AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
        WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
    "
    if ($res) {
        $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to change procedures, functions and triggers:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , R.name AS role_name
            , M.type_desc AS principal_type
            , M.name AS principal_name
        FROM sys.database_principals R
            JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
            JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
        WHERE R.name IN ('db_ddladmin','db_owner')
            AND M.name != 'dbo'
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #If the second query is the only query to return results, add the message to the DBA.
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to change procedures, functions and triggers:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213907 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213907
        STIG ID    : SQL6-D0-001200
        Rule ID    : SV-213907r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must limit privileges to change software modules, to include stored procedures, functions, and triggers, and links to software external to SQL Server.
        DiscussMD5 : 39B6782765F128EC0472D2F036E28EA9
        CheckMD5   : 4452EFC1E53D9B375346AE45ED37710A
        FixMD5     : 2B76A81FC685ACBD10A9D4BEDDD3884B
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    # Fixed "multi-part identifier could not be bound" that happened on case-sensitive databases. Ken Row, 5/22/25, Issue 2322

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        select s.name AS schema_name
             , p.name AS owning_principal
          FROM sys.schemas s
          JOIN sys.database_principals p ON s.principal_id = p.principal_id
         where p.name != 'dbo'
           and (s.name != p.name
                or p.name not in
                 ( 'db_accessadmin'
                 , 'db_backupoperator'
                 , 'db_datareader'
                 , 'db_datawriter'
                 , 'db_ddladmin'
                 , 'db_denydatareader'
                 , 'db_denydatawriter'
                 , 'db_owner'
                 , 'db_securityadmin'
                 , 'guest'
                 , 'INFORMATION_SCHEMA'
                 , 'sys'
                 , 'TargetServersRole'
                 , 'SQLAgentUserRole'
                 , 'SQLAgentReaderRole'
                 , 'SQLAgentOperatorRole'
                 , 'DatabaseMailUserRole'
                 , 'db_ssisadmin'
                 , 'db_ssisltduser'
                 , 'db_ssisoperator'
                 , 'replmonitor'
                 , '##MS_SSISServerCleanupJobLogin##'
                 )
               )
         order by schema_name
    "
    if ($res) {
        $FindingDetails += "DBA, ensure the following principals are authorized in the server documentation to own schemas:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No principals other than the standard MSSQL principals own database schemas."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213908 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213908
        STIG ID    : SQL6-D0-001300
        Rule ID    : SV-213908r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000200
        Rule Title : Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be owned by database/DBMS principals authorized for ownership.
        DiscussMD5 : 8B9C1DDE3BEE6081210CCE4DA6722CF5
        CheckMD5   : D44CBE32042C5E36D44A45F51C0EEA6E
        FixMD5     : 40520C2C65EF62295706838A0B750DFB
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    # Check for accounts with the db_owner role...
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        ;with objects_cte as
        (SELECT o.name, o.type_desc,
        CASE
        WHEN o.principal_id is null then s.principal_id
        ELSE o.principal_id
        END as principal_id
        FROM sys.objects o
        INNER JOIN sys.schemas s
        ON o.schema_id = s.schema_id
        WHERE o.is_ms_shipped = 0
        )
        SELECT cte.name, cte.type_desc, dp.name as ObjectOwner
        FROM objects_cte cte
        INNER JOIN sys.database_principals dp
        ON cte.principal_id = dp.principal_id
        where dp.name != 'dbo'
        ORDER BY dp.name, cte.name
    " | Where-Object ObjectOwner -NE 'dbo'
    if ($res) {
        $FindingDetails += "DBA, Confirm that an approved server documentation documents the following accounts as authorized to own database objects:`n$($res | Format-Table | Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213909
        STIG ID    : SQL6-D0-001400
        Rule ID    : SV-213909r960960_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000362
        Rule Title : The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be restricted to authorized users.
        DiscussMD5 : 978959640256E1378015BF8DB91A4E1E
        CheckMD5   : 2087000BE0DDCC381BA9B432628FC5A2
        FixMD5     : 52E96BE4F6968CFE0C8A49E5EFE7CBE7
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

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
        # Per #304 return NR in case server documentation supports the settings
        # $Status = 'Open'
        $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to modify objects:`n$($res | Format-Table -AutoSize| Out-String)"
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
            # Per #304 return NR in case server documentation supports the settings
            # $Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to modify objects:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213910 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213910
        STIG ID    : SQL6-D0-001500
        Rule ID    : SV-213910r961125_rule
        CCI ID     : CCI-001665
        Rule Name  : SRG-APP-000226-DB-000147
        Rule Title : In the event of a system failure, hardware loss or disk failure, SQL Server must be able to restore necessary databases with least disruption to mission processes.
        DiscussMD5 : D3A0EFF900E4D54CB29E4136BC37B021
        CheckMD5   : DAEEB41AD29C9023BCB9A2C9DBFD5C94
        FixMD5     : B8F652DC1E84DBF27B62D6F60ADB3826
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    # Changed to specify the database via the Get-ISQL parameter instead of a USE statement. Ken Row, 5/5/25, Issue 2281

    $res = Get-ISQL -ServerInstance $Instance -Database master "
        SELECT name, recovery_model_desc
        FROM sys.databases
        WHERE name = '$($Database)'
        ORDER BY name
    "

    $FindingDetails += "DBA, Using the system documentation, confirm, the following recovery models."
    if ($res) {
        $FindingDetails += "If the recovery model description does not match the documented recovery model, this is a finding.:`n$($res | Format-Table -AutoSize| Out-String)"
    } else {
        $FindingDetails += "No results were returned by the recovery model check query."
    }

    $res = Get-ISQL -ServerInstance $Instance -Database msdb "
        SELECT database_name,
        CASE type
        WHEN 'D' THEN 'Full'
        WHEN 'I' THEN 'Differential'
        WHEN 'L' THEN 'Log'
        ELSE type
        END AS backup_type,
        is_copy_only,backup_start_date, backup_finish_date
        FROM dbo.backupset
        WHERE (backup_start_date >= dateadd(day, - 30, getdate())) AND
        (database_name = '$($Database)')
        ORDER BY database_name, backup_start_date DESC
    "

    $FindingDetails += "DBA, Review the jobs set up to implement the backup plan. If they are absent, this is a finding.`n"
    if ($res) {
        $FindingDetails += "Jobs set up to implement the backup plan:`n$($res | Format-Table -AutoSize| Out-String)"
    } else {
        $FindingDetails += "No results were returned by the backup plan check query."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213911 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213911
        STIG ID    : SQL6-D0-001600
        Rule ID    : SV-213911r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : The Database Master Key encryption password must meet DOD password complexity requirements.
        DiscussMD5 : 6DB1720E47256E1D39E45A10BEB1F948
        CheckMD5   : 8FF290AA00A14E9728234B7B20EF516B
        FixMD5     : 4D5F529F01B53EFEFCFD26046322E8A2
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as Instance
            , db_name() as DatabaseName
            , COUNT(name)  keycount
    FROM sys.symmetric_keys s, sys.key_encryptions k
    WHERE s.name = '##MS_DatabaseMasterKey##'
    AND s.symmetric_key_id = k.key_id
    AND k.crypt_type in ('ESKP', 'ESP2', 'ESP3')"
    if ($res) {
        $res2 = $res | Where-Object keycount -GT 0
        if ($res2) {
            $FindingDetails = "Review procedures and evidence of password requirements used to encrypt the following Database Master Keys:`n$($res2 | Format-Table -AutoSize| Out-String)"
        }
    }
    if ($FindingDetails -eq "") {
        $Status = "Not_Applicable"
        $FindingDetails = "No database master keys exist."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213912 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213912
        STIG ID    : SQL6-D0-001700
        Rule ID    : SV-213912r961128_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : The Database Master Key must be encrypted by the Service Master Key, where a Database Master Key is required and another encryption method has not been specified.
        DiscussMD5 : E20E1D2CC9839DC27B64F09DFB76F6DD
        CheckMD5   : 25A67476861EB638F52679DCFD298620
        FixMD5     : CFDA680ABB86823956A93B86BDD4C75B
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT name
    FROM [master].sys.databases
    WHERE is_master_key_encrypted_by_server = 1
    AND owner_sid <> 1
    AND state = 0;
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the server documentation has approved the encryption of these database master keys using the service master keys:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213914 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213914
        STIG ID    : SQL6-D0-001900
        Rule ID    : SV-213914r961131_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-DB-000124
        Rule Title : SQL Server must isolate security functions from non-security functions.
        DiscussMD5 : 3C4897D983873B453A50F0FC5F362181
        CheckMD5   : 1452CEE7916954A9AC8F77A1EEEC5810
        FixMD5     : 8EB21B5D5DF9FEC31B9EF3B9A0EB3E38
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is the '$Database' database so this requirement is NA."
    } else {
        $res = Get-ISQL -ServerInstance $Instance -Database master "
        SELECT Name
        FROM sys.databases
        WHERE (database_id > 4) AND
        ( name = '$($Database)')
        ORDER BY 1;
        "
        if ($res) {
            $FindingDetails += "DBA, Review the database structure to determine where security related functionality is stored.`n If security-related database objects or code are not kept separate, this is a finding:`n$($res | Format-Table -AutoSize| Out-String)"
        }
        $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213918 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213918
        STIG ID    : SQL6-D0-002500
        Rule ID    : SV-213918r961269_rule
        CCI ID     : CCI-002262
        Rule Name  : SRG-APP-000311-DB-000308
        Rule Title : SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in storage.
        DiscussMD5 : 3F0C4A4681CEFCCB6281795EA4C61B36
        CheckMD5   : B193BB17CF9A2B56073ED23828F79ECD
        FixMD5     : C1F5D2371A244B7B709D6D59F4E32F9F
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
    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "NotAFinding"
        $FindingDetails += "This is the '$Database' database so per STIG Support modifying the default databases not required nor recommended. For the default databases this check is an automatic 'Not A Finding'"
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

Function Get-V213919 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213919
        STIG ID    : SQL6-D0-002600
        Rule ID    : SV-213919r961272_rule
        CCI ID     : CCI-002263
        Rule Name  : SRG-APP-000313-DB-000309
        Rule Title : SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in process.
        DiscussMD5 : 27AE610739A6ECCC98A928FD913C5CE9
        CheckMD5   : F35188C0168F570BA3C5F104647D925A
        FixMD5     : 8F8187CB697CAAAE56DCA803B3B3FB5F
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
    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "NotAFinding"
        $FindingDetails += "This is the '$Database' database so per STIG Support modifying the default databases not required nor recommended. For the default databases this check is an automatic 'Not A Finding'"
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

Function Get-V213920 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213920
        STIG ID    : SQL6-D0-002700
        Rule ID    : SV-213920r961275_rule
        CCI ID     : CCI-002264
        Rule Name  : SRG-APP-000314-DB-000310
        Rule Title : SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in transmission.
        DiscussMD5 : 849F4CA5E2D05A3277EB6F43B07AC3B0
        CheckMD5   : 546C833914D0138D4FBE0E9E9D24A11D
        FixMD5     : 41D1DDDB6C0BA366F9049F3D0C1B0EC8
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
    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "NotAFinding"
        $FindingDetails += "This is the '$Database' database so per STIG Support modifying the default databases not required nor recommended. For the default databases this check is an automatic 'Not A Finding'"
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

Function Get-V213921 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213921
        STIG ID    : SQL6-D0-002800
        Rule ID    : SV-213921r961317_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-APP-000328-DB-000301
        Rule Title : SQL Server must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.
        DiscussMD5 : 597921AC57B1918582E4F7C64889A15B
        CheckMD5   : 8940CDE89ACD7C09A1DABA4DE6007B38
        FixMD5     : 4E66F0FEEE6B81F36689123D9B6EE437
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , name AS schema_name
            , USER_NAME(principal_id) AS schema_owner
        FROM sys.schemas
        WHERE schema_id != principal_id
        AND principal_id != 1
    "
    if ($res) {
        #$Status = 'Open'
        $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to own schemas:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , object_id
            , name AS securable
            , USER_NAME(principal_id) AS object_owner
            , type_desc
        FROM sys.objects
        WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL
        ORDER BY type_desc, securable, object_owner
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #$Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to own objects:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , U.type_desc
            , U.name AS grantee
            , DP.class_desc AS securable_type
            , CASE DP.class
                WHEN 0 THEN DB_NAME()
                WHEN 1 THEN OBJECT_NAME(DP.major_id)
                WHEN 3 THEN SCHEMA_NAME(DP.major_id)
                ELSE CAST(DP.major_id AS nvarchar)
            END AS securable
            , permission_name
            , state_desc
        FROM sys.database_permissions DP
        JOIN sys.database_principals U ON DP.grantee_principal_id = U.principal_id
        WHERE DP.state = 'W'
        ORDER BY grantee, securable_type, securable
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #$Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to assig additional permissions:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213922 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213922
        STIG ID    : SQL6-D0-002900
        Rule ID    : SV-213922r961359_rule
        CCI ID     : CCI-002233
        Rule Name  : SRG-APP-000342-DB-000302
        Rule Title : Execution of stored procedures and functions that utilize execute as must be restricted to necessary cases only.
        DiscussMD5 : 5D7FC57D87D2245548BC6AC3C58C0621
        CheckMD5   : 6EA16EBC32CE7C95CAD5310D98261BFF
        FixMD5     : A2B2D7210B1E1372F49B47F1DF9616F2
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    # Fixed "multi-part identifier could not be bound" that happened on case-sensitive databases. Ken Row, 5/22/25, Issue 2322

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT s.name AS schema_name
             , o.name AS module_name
             , execute_as = USER_NAME(
                 CASE m.execute_as_principal_id
                   WHEN -2 THEN ISNULL(o.principal_id, s.principal_id)
                   ELSE m.execute_as_principal_id
                 END
               )
          FROM sys.sql_modules m
          JOIN sys.objects o ON m.object_id = o.object_id
          JOIN sys.schemas s ON o.schema_id = s.schema_id
         WHERE m.execute_as_principal_id IS NOT NULL
           and o.name not in (
                 'fn_sysdac_get_username',
                 'fn_sysutility_ucp_get_instance_is_mi',
                 'sp_send_dbmail',
                 'sp_SendMailMessage',
                 'sp_syscollector_create_collection_set',
                 'sp_syscollector_delete_collection_set',
                 'sp_syscollector_disable_collector',
                 'sp_syscollector_enable_collector',
                 'sp_syscollector_get_collection_set_execution_status',
                 'sp_syscollector_run_collection_set',
                 'sp_syscollector_start_collection_set',
                 'sp_syscollector_update_collection_set',
                 'sp_syscollector_upload_collection_set',
                 'sp_syscollector_verify_collector_state',
                 'sp_syspolicy_add_policy',
                 'sp_syspolicy_add_policy_category_subscription',
                 'sp_syspolicy_delete_policy',
                 'sp_syspolicy_delete_policy_category_subscription',
                 'sp_syspolicy_update_policy',
                 'sp_sysutility_mi_add_ucp_registration',
                 'sp_sysutility_mi_disable_collection',
                 'sp_sysutility_mi_enroll',
                 'sp_sysutility_mi_initialize_collection',
                 'sp_sysutility_mi_remove',
                 'sp_sysutility_mi_remove_ucp_registration',
                 'sp_sysutility_mi_upload',
                 'sp_sysutility_mi_validate_enrollment_preconditions',
                 'sp_sysutility_ucp_add_mi',
                 'sp_sysutility_ucp_add_policy',
                 'sp_sysutility_ucp_calculate_aggregated_dac_health',
                 'sp_sysutility_ucp_calculate_aggregated_mi_health',
                 'sp_sysutility_ucp_calculate_computer_health',
                 'sp_sysutility_ucp_calculate_dac_file_space_health',
                 'sp_sysutility_ucp_calculate_dac_health',
                 'sp_sysutility_ucp_calculate_filegroups_with_policy_violations',
                 'sp_sysutility_ucp_calculate_health',
                 'sp_sysutility_ucp_calculate_mi_file_space_health',
                 'sp_sysutility_ucp_calculate_mi_health',
                 'sp_sysutility_ucp_configure_policies',
                 'sp_sysutility_ucp_create',
                 'sp_sysutility_ucp_delete_policy',
                 'sp_sysutility_ucp_delete_policy_history',
                 'sp_sysutility_ucp_get_policy_violations',
                 'sp_sysutility_ucp_initialize',
                 'sp_sysutility_ucp_initialize_mdw',
                 'sp_sysutility_ucp_remove_mi',
                 'sp_sysutility_ucp_update_policy',
                 'sp_sysutility_ucp_update_utility_configuration',
                 'sp_sysutility_ucp_validate_prerequisites',
                 'sp_validate_user',
                 'syscollector_collection_set_is_running_update_trigger',
                 'sysmail_help_status_sp'
               )
         ORDER BY schema_name, module_name
    "
    if ($res) {
        $FindingDetails += "DBA, ensure the following SQL modules are authorized in the server documentation to utilize impersonation:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213923 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213923
        STIG ID    : SQL6-D0-003000
        Rule ID    : SV-213923r1018608_rule
        CCI ID     : CCI-001812, CCI-003980
        Rule Name  : SRG-APP-000378-DB-000365
        Rule Title : SQL Server must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.
        DiscussMD5 : 9B6725BEA3A1DACA9B4CAE0A8A6BE949
        CheckMD5   : 00DB8FECD54757974FFD2E733F250904
        FixMD5     : 911DA2634542FC8D6A795E43484A0192
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , P.type_desc AS principal_type
            , P.name AS principal_name
            , O.type_desc
            , CASE class
                WHEN 0 THEN DB_NAME()
                WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
                WHEN 3 THEN SCHEMA_NAME(major_id)
                ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
            END AS securable_name, DP.state_desc
            , DP.permission_name
        FROM sys.database_permissions DP
        JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
        LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
        WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
    "
    if ($res) {
        #$Status = 'Open'
        $FindingDetails += "DBA, ensure the following principals are authorized in the server documentation to modify the specified object or type:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , R.name AS role_name
            , M.type_desc AS principal_type
            , M.name AS principal_name
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
        WHERE R.name IN ('db_ddladmin','db_owner')
        AND M.name != 'dbo'
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #$Status = 'Open'
            $FindingDetails += "DBA, ensure the following user/role memberships are authorized in the server documentation:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213924 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213924
        STIG ID    : SQL6-D0-003100
        Rule ID    : SV-213924r961461_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : SQL Server must enforce access restrictions associated with changes to the configuration of the database(s).
        DiscussMD5 : 95FAB93A0921985CD613247A78F88442
        CheckMD5   : 5672CC23A186BCEB0208C20604F06C79
        FixMD5     : A9DD431780198FEB7EE0BD6041434963
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT D.name AS database_name, SUSER_SNAME(D.owner_sid) AS owner_name,
    FRM.is_fixed_role_member
   FROM sys.databases D
   OUTER APPLY (
    SELECT MAX(fixed_role_member) AS is_fixed_role_member
    FROM (
    SELECT IS_SRVROLEMEMBER(R.name, SUSER_SNAME(D.owner_sid)) AS fixed_role_member
    FROM sys.server_principals R
    WHERE is_fixed_role = 1
    ) A
   ) FRM
   WHERE (D.database_id > 4)
    AND (FRM.is_fixed_role_member = 1
    OR FRM.is_fixed_role_member IS NULL)
    AND (D.name = '$($Database)')
    ORDER BY database_name
    "
    if ($res) {
        $FindingDetails += "DBA, Remove unauthorized users from roles`n$($res | Format-Table -AutoSize | Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213926 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213926
        STIG ID    : SQL6-D0-003300
        Rule ID    : SV-213926r1018576_rule
        CCI ID     : CCI-002475
        Rule Name  : SRG-APP-000428-DB-000386
        Rule Title : SQL Server must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.
        DiscussMD5 : C968AE1A06911A9B683DE5B2C85E725D
        CheckMD5   : DBF34A0BE998841E36A79116F6AAB229
        FixMD5     : 3AF67BC7DD663FF1055AFE9BC5988782
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT encryption_state,
            encryption_descr = CASE encryption_state
            WHEN 0 THEN 'No database encryption key present, no encryption'
            WHEN 1 THEN 'Unencrypted'
            WHEN 2 THEN 'Encryption in progress'
            WHEN 3 THEN 'Encrypted'
            WHEN 4 THEN 'Key change in progress'
            WHEN 5 THEN 'Decryption in progress'
            WHEN 6 THEN 'Protection change in progress'
            END
        FROM sys.dm_database_encryption_keys
        WHERE database_id = DB_ID('$($Database)')
    "
    if ($res) {
        $tEncState = $res.encryption_state
        $tEncDescr = $res.encryption_descr
        $FindingDetails = "A database encryption key was found with state $tEncState, signifying '$tEncDescr'."
    }
    else {
        $FindingDetails = "No database encryption key was found."
        $tEncDescr = 'NF'
    }

    if ($tEncDescr -eq 'Encrypted') {
        $FindingDetails += "`n`nSince the database shows encrypted, marking this as NOT A FINDING."
        $Status = 'NotAFinding'
    }
    else {
        $FindingDetails += "`n`nDocumentation needs reviewed to see if encryption is required."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V213927 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213927
        STIG ID    : SQL6-D0-003400
        Rule ID    : SV-213927r1018577_rule
        CCI ID     : CCI-002476
        Rule Name  : SRG-APP-000429-DB-000387
        Rule Title : SQL Server must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.
        DiscussMD5 : 7C2502D5D91C786033296A8AC9E29843
        CheckMD5   : F4D441432F9B2A562F3478C98A019792
        FixMD5     : FB27D18186C65E03AE951D82770B64A0
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT encryption_state,
            encryption_descr = CASE encryption_state
            WHEN 0 THEN 'No database encryption key present, no encryption'
            WHEN 1 THEN 'Unencrypted'
            WHEN 2 THEN 'Encryption in progress'
            WHEN 3 THEN 'Encrypted'
            WHEN 4 THEN 'Key change in progress'
            WHEN 5 THEN 'Decryption in progress'
            WHEN 6 THEN 'Protection change in progress'
            END
        FROM sys.dm_database_encryption_keys
        WHERE database_id = DB_ID('$($Database)')
    "
    if ($res) {
        $tEncState = $res.encryption_state
        $tEncDescr = $res.encryption_descr
        $FindingDetails = "A database encryption key was found with state $tEncState, signifying '$tEncDescr'."
    }
    else {
        $FindingDetails = "No database encryption key was found."
        $tEncDescr = 'NF'
    }

    if ($tEncDescr -eq 'Encrypted') {
        $FindingDetails += "`n`nSince the database shows encrypted, marking this as NOT A FINDING."
        $Status = 'NotAFinding'
    }
    else {
        $FindingDetails += "`n`nDocumentation needs reviewed to see if encryption is required."
    }
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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

Function Get-V251040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251040
        STIG ID    : SQL6-D0-003200
        Rule ID    : SV-251040r962034_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000416-DB-000380
        Rule Title : SQL Server must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements.
        DiscussMD5 : 94530902BF995409CD9A678554C66AA2
        CheckMD5   : C52463E1E5CABC2B678AC4EDC1626660
        FixMD5     : 5BC058F8E0F53241DA87EF240C360082
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
    # Changed to adjust FindingDetails and Status if the user is not a SysAdmin. Ken Row, 4/24/25, Issue 1737

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
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        #$RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        #If the registry value does not exist
        If ($SettingNotConfiguredAllowed -eq $true) {
            #And it is allowed to be not configured set to notAFinding
            #$Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            #Or, if it must be configured, set this to Open
            #$Status = "Open"
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
            #$Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                #If the registry result matches the expected value
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-Strings
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
    $null = sqldbCheckAdmin -Instance $Instance -FindingDetails ([ref]$FindingDetails) -Status ([ref]$Status)
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAWXJwOgPGx7Xa3
# 5YzZGaLYC72/Zh0reMI0vGMg1CclJqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCD9uYReDb8G1XOjqAN+noPSp3NaiKtrrwuvwYoy43o0CjANBgkqhkiG9w0BAQEF
# AASCAQBFgsPf/UobgLKwEFaRU8E3l25T3ZmgydtBxZ9Iwi1+KNi9Er4Y8yFypGrF
# 12qm/jqDiQt8FYL5G/E2Az/qJHhA+9VKJp8JVF7lBJhBTJ2oUaOrKY4pihwhupDx
# tgOAkDwbiMtDbjzlqpzbLpkhwisV2TVliDqJ2QuChj/FIs5km0cV/zRrq2KbZ7AK
# kybCJmTr16l8IX2niHS90/tlGFo0FCT+rxrjNPSyEtHXlg9Xfm2pMPl3n3/hIeAT
# pvf34KOhm7lz5CDOlJpfewmHtM/GvTS20Ti0TpxRDAhDMjaaccaSeBOK5+3lU+FU
# fNy3+e8GWh82Of8ehDG9OkYDh9wzoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxNTEwNTgwOFowLwYJKoZIhvcNAQkEMSIEID7eBxH4CANMzGJifUAqWCf0f6xw
# f8Wox/nob2o2l80MMA0GCSqGSIb3DQEBAQUABIICAELRWkurH27RqX5cbmzId3D2
# qSxL7uM33V3kT/IeIMz2RoHryiCEB1Ibj+wGKC+JjDsFW3tWlTsHkIOs79BGoM4e
# tJjaMQpbkZkGbKXku29663Gmy35AQiMtZ9wMA0HOkk3n2Mkj5/oG/FmJHlg6A+E7
# RlLM4+vjZPmmDj6iSPL7CTFFTDaDFDw4hcLWe8yad7Rf7Chsp9k1GDh/loxEdKw3
# 9EVpHut7zUM7Hnes/loCJbi/va08oBsv3tgKw+nFz36KIRP/GQKYUVvYojHVwTcd
# Mj6ZtE6QXrsxxgC5ifzmxPHuHfnKWHQ9cAvuVdR27rMr2c3/XWgcz48nbTART1Qt
# 7VQtzg2SnnkCKqFIdwWPyZTOaiyT+fs0KX2u24kAWQ0XeKG0k8LUbT25y+xASTKG
# hboeHZRMtjxdrDoJRY7yTn2tFhtyPQS9SF6C0t7X2qE/yZy6VRcJ/WbnqqZoIghh
# oMK7DOCedkoBPqlCXefXTXrrpcoDFhi5ygJ8RIPBzHDml7WPk/8fMhQOmD+hX1Rs
# wi42VKHT952UCFhMwgAqEArVuJpt65LBxtR5CsYSMVmYkOs2Jw0lNtCjBqKm5R9Y
# moigECozsPrRhiXS0KOZ+3vDKiBFsHdt+DfX2j0x/UVO0aXjsfZ8Ah9p9Xfp9sPl
# c6/UbhAYt3EVqaPhCHeM
# SIG # End signature block
