############################################
# STIG Manager functions for Evaluate-STIG #
############################################

Function ConvertTo-Base64UrlString {
    <#
      .SYNOPSIS
      Base64url encoder.
      .DESCRIPTION
      Encodes a string or byte array to base64url-encoded string.
      .PARAMETER in
      Specifies the input. Must be string, or byte array.
      .INPUTS
      You can pipe the string input to ConvertTo-Base64UrlString.
      .OUTPUTS
      ConvertTo-Base64UrlString returns the encoded string by default.
      .EXAMPLE
      PS Variable:> '{"alg":"RS256","typ":"JWT"}' | ConvertTo-Base64UrlString
      eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
      .LINK
      https://github.com/SP3269/posh-jwt
      .LINK
      https://jwt.io/
  #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$in
    )
    If ($in -is [string]) {
        Return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($in)) -replace '\+', '-' -replace '/', '_' -replace '='
    }
    ElseIf ($in -is [byte[]]) {
        Return [Convert]::ToBase64String($in) -replace '\+', '-' -replace '/', '_' -replace '='
    }
    Else {
        Return "ConvertTo-Base64UrlString requires string or byte array input, received $($in.GetType())"
    }
}

Function New-Jwt {
    <#
      .SYNOPSIS
      Creates a JWT (JSON Web Token).
      .DESCRIPTION
      Creates signed JWT given a signing certificate and claims in JSON.
      .PARAMETER Payload
      Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.
      .PARAMETER Cert
      Specifies the signing certificate of type System.Security.Cryptography.X509Certificates.X509Certificate2. Must be specified and contain the private key If the algorithm in the header is RS256.

      .LINK
      https://github.com/SP3269/posh-jwt
      .LINK
      https://jwt.io/
  #>
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$PayloadJson,
        [Parameter(Mandatory = $false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )
    $x5t = ConvertTo-Base64UrlString $cert.GetCertHash()
    $Header = '{"alg":"RS256","typ":"JWT","x5t":"' + $x5t + '"}'

    $encodedHeader = ConvertTo-Base64UrlString $Header
    $encodedPayload = ConvertTo-Base64UrlString $PayloadJson

    $jwt = $encodedHeader + '.' + $encodedPayload
    $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)

    $rsa = $Cert.PrivateKey
    $sig = ConvertTo-Base64UrlString $rsa.SignData($toSign, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)

    $jwt = $jwt + '.' + $sig
    Return $jwt
}

Function Get-SMAuthToken {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$LogPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory=$true)]
        [string]$SMImport_API_Base,

        [Parameter(Mandatory = $true)]
        [string]$SMImport_AUTHORITY,

        [Parameter(Mandatory = $true)]
        [string]$SMImport_CLIENT_ID,

        [Parameter(Mandatory = $true)]
        [string]$SMImport_CLIENT_CERT,

        [Parameter(Mandatory = $false)]
        [string]$SMImport_CLIENT_CERT_KEY,

        [Parameter(Mandatory = $false)]
        [securestring]$SMImport_CLIENT_CERT_KEY_PASSPHRASE

    )

    $SMImport_CLIENT_CERT = $SMImport_CLIENT_CERT -replace '"', ''  #Deal with quoted paths being passed

    If (-Not(Test-Path $SMImport_CLIENT_CERT)) {
        Write-Log -Path $LogPath -Message "ERROR: $SMImport_CLIENT_CERT not found." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Return
    }

    If ($SMImport_CLIENT_CERT_KEY) {
        $SMImport_CLIENT_CERT_KEY = $SMImport_CLIENT_CERT_KEY -replace '"', ''  #Deal with quoted paths being passed

        If (-Not(Test-Path $SMImport_CLIENT_CERT_KEY)) {
            Write-Log -Path $LogPath -Message "ERROR: $SMImport_CLIENT_CERT_KEY not found." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            Return
        }
    }

    $apiauthendpoint = Invoke-RestMethod -Method Get -Uri "$SMImport_AUTHORITY/.well-known/openid-configuration" | Select-Object -ExpandProperty token_endpoint

    $oauthScopes = "stig-manager:stig:read stig-manager:collection stig-manager:user:read"
    $contentType = 'application/x-www-form-urlencoded'

    $json = ConvertTo-Json @{
        iss = $SMImport_CLIENT_ID
        sub = $SMImport_CLIENT_ID
        aud = $apiauthendpoint
        jti = (1..16 | ForEach-Object {[byte](Get-Random -Max 256)} | ForEach-Object ToString X2) -join ''
        exp = ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds() + 60 #Expire token in 1 minute (good for repeated calls)
    }

    If ($SMImport_CLIENT_CERT_KEY) {
        $SMImport_PASSPHRASE = ConvertFrom-SecureString $SMImport_CLIENT_CERT_KEY_PASSPHRASE -AsPlainText
        $cert = [system.security.Cryptography.X509Certificates.X509Certificate2]::CreateFromEncryptedPemFile($SMImport_CLIENT_CERT, $SMImport_PASSPHRASE, $SMImport_CLIENT_CERT_KEY)
    }
    Else {
        $cert = [system.security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($SMImport_CLIENT_CERT)
    }

    $signed = New-Jwt -Cert $Cert -PayloadJson $json

    $body = @{
        resource              = $SMImport_API_Base
        grant_type            = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $signed
        scope                 = $oauthScopes
    }

    Try {
        $accessRequest = Invoke-RestMethod -Method POST -Uri $apiauthendpoint -Body $body -ContentType $contentType -ErrorAction STOP
    }
    Catch {
        Write-Log -Path $LogPath -Message "ERROR: Unable to create Access Request Token." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Return
    }

    $AccessToken = $accessRequest.access_token

    $authheader = @{
        Authorization = "Bearer $AccessToken"
    }

    Return $authheader
}

Function Get-SMAuthClient {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$LogPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,
        
        [Parameter(Mandatory=$true)]
        [string]$SMImport_API_Base,

        [Parameter(Mandatory=$true)]
        [string]$SMImport_AUTHORITY,

        [Parameter(Mandatory=$true)]
        [string]$SMImport_CLIENT_ID,

        [Parameter(Mandatory=$false)]
        [securestring]$SMImport_CLIENT_CERT_KEY_PASSPHRASE
  ) 

  $apiauthendpoint = Invoke-RestMethod -Method Get -Uri "$SMImport_AUTHORITY/.well-known/openid-configuration" | Select-Object -ExpandProperty token_endpoint

  $oauthScopes = "stig-manager:stig:read stig-manager:collection stig-manager:user:read"
  $contentType = 'application/x-www-form-urlencoded'

  $body = @{
        grant_type = 'client_credentials'
        client_id = $SMImport_CLIENT_ID
        client_secret = ConvertFrom-SecureString $SMImport_CLIENT_CERT_KEY_PASSPHRASE -AsPlainText
        scope = $oauthScopes
  }

  Try {
    $accessRequest = Invoke-RestMethod -Method POST -Uri $apiauthendpoint -body $body -ContentType $contentType -ErrorAction STOP
  }
  Catch{
    Write-Log -Path $LogPath -Message "Unable to create Access Request Token, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    Return "Unable to create Access Request Token, aborting..."
  }

  $AccessToken = $accessRequest.access_token

  $authheader = @{
    Authorization="Bearer $AccessToken"
  }

  Return $authheader

}

Function Get-SMParameters {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$SMCollection,

        [Parameter(Mandatory = $false)]
        [SecureString]$SMPassphrase,

        [Parameter(Mandatory)]
        [psobject]$ScanObject,

        [Parameter(Mandatory = $true)]
        [String]$ScriptRoot,

        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String]$LogPath
    )

    Write-Log -Path $LogPath -Message "Importing to STIG Manager..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

    #Get Preferences
    $Preferences = (Select-Xml -Path $(Join-Path $ScriptRoot -ChildPath Preferences.xml) -XPath /).Node

    ForEach ($Item in ($Preferences.Preferences.STIGManager | Get-Member -MemberType Property | Where-Object Definition -Match string | Where-Object Name -NE '#comment').Name) {
        $Preferences.Preferences.STIGManager.$Item = $Preferences.Preferences.STIGManager.$Item -replace '"', '' -replace "'", ''
    }

    Try {
        If ($Preferences.Preferences.STIGManager | Select-Object -ExpandProperty SMImport_Collection | Where-Object Name -EQ $SMCollection) {
            $STIGManagerObject = $Preferences.Preferences.STIGManager | Select-Object -ExpandProperty SMImport_Collection | Where-Object Name -EQ $SMCollection
            Write-Log -Path $LogPath -Message "STIGManager Collection: $SMCollection" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Log -Path $LogPath -Message "Uploading to STIG Manager..." -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

            Switch ($OSPlatform) {
                "Windows" {
                    $TempLogDir = Split-Path -Path $LogPath -Parent
                }
                "Linux" {
                    $TempLogDir = "/tmp/Evaluate-STIG"
                }
            }

            $STIGLog_STIGManager = Join-Path -Path $TempLogDir -ChildPath "Evaluate-STIG_STIGManager.log"

            $SMImport_Params = @{
                LogPath                = $STIGLog_STIGManager
                OSPlatform             = $OSPlatform
                SMImport_API_BASE      = $Preferences.Preferences.STIGManager.SMImport_API_BASE
                SMImport_AUTHORITY     = $Preferences.Preferences.STIGManager.SMImport_AUTHORITY
                SMImport_CLIENT_ID     = $STIGManagerObject.SMImport_CLIENT_ID
                SMImport_CLIENT_CERT   = $STIGManagerObject.SMImport_CLIENT_CERT
                SMImport_COLLECTION_ID = $STIGManagerObject.SMImport_COLLECTION_ID
                Scan_Objects           = $ScanObject
            }

            If ($STIGManagerObject.SMImport_CLIENT_CERT_KEY) {
                $SMImport_Params.SMImport_CLIENT_CERT_KEY = $STIGManagerObject.SMImport_CLIENT_CERT_KEY
            }
            $SMImport_Params.SMImport_CLIENT_CERT_KEY_PASSPHRASE = $SMPassphrase

            Return $SMImport_Params
        }
    }
    Catch {
        Write-Log -Path $LogPath -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform

        Throw "Failed to import STIGManager Preferences."
    }
}

Function Import-Asset {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$LogPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [string]$SMImport_API_BASE,

        [Parameter(Mandatory = $true)]
        [string]$SMImport_AUTHORITY,

        [Parameter(Mandatory = $true)]
        [string]$SMImport_CLIENT_ID,

        [Parameter(Mandatory = $false)]
        [string]$SMImport_CLIENT_CERT,

        [Parameter(Mandatory = $false)]
        [string]$SMImport_CLIENT_CERT_KEY,

        [Parameter(Mandatory = $false)]
        [securestring]$SMImport_CLIENT_CERT_KEY_PASSPHRASE,

        [Parameter(Mandatory = $true)]
        [string]$SMImport_COLLECTION_ID,

        [Parameter(Mandatory)]
        [psobject]$Scan_Objects,

        [Parameter(Mandatory = $false)]
        [int]$MaximumRetryCount = 3
    )

    Write-Host "  Processing $(($Scan_Objects.VulnResults | Measure-Object).Count) Vulnerabilities..."

    Foreach ($Scan_Object in ($Scan_Objects | Where-Object {$null -ne $_.STIGInfo})) {
        $Body_Array = New-Object System.Collections.Generic.List[System.Object]

        $CKL_HOST_NAME = $Scan_Object.TargetData.HostName
        If ($Scan_Object.TargetData.WebOrDatabase -eq "true") {
            If ($Scan_Object.TargetData.Site) {
                $CKL_HOST_NAME = "$($CKL_HOST_NAME)-$($Scan_Object.TargetData.Site)"
            }
            Else {
                $CKL_HOST_NAME = "$($CKL_HOST_NAME)-NA"
            }
            If ($Scan_Object.TargetData.Instance) {
                $CKL_HOST_NAME = "$($CKL_HOST_NAME)-$($Scan_Object.TargetData.Instance)"
            }
            Else {
                $CKL_HOST_NAME = "$($CKL_HOST_NAME)-NA"
            }
        }

        $benchmarkId = $Scan_Object.STIGInfo.STIGID

        if ($SMImport_CLIENT_CERT){
            If ($SMImport_CLIENT_CERT_KEY) {
                $authheader = Get-SMAuthToken -LogPath $LogPath -OSPlatform $OSPlatform -SMImport_API_Base $SMImport_API_BASE -SMImport_AUTHORITY $SMImport_AUTHORITY -SMImport_CLIENT_ID $SMImport_CLIENT_ID -SMImport_CLIENT_CERT $SMImport_CLIENT_CERT -SMImport_CLIENT_CERT_KEY $SMImport_CLIENT_CERT_KEY -SMImport_CLIENT_CERT_KEY_PASSPHRASE $SMImport_CLIENT_CERT_KEY_PASSPHRASE
            }
            Else {
                $authheader = Get-SMAuthToken -LogPath $LogPath -OSPlatform $OSPlatform -SMImport_API_Base $SMImport_API_BASE -SMImport_AUTHORITY $SMImport_AUTHORITY -SMImport_CLIENT_ID $SMImport_CLIENT_ID -SMImport_CLIENT_CERT $SMImport_CLIENT_CERT
            }
        }
        else{
            $authheader = Get-SMAuthClient -LogPath $LogPath -OSPlatform $OSPlatform -SMImport_API_Base $SMImport_API_BASE -SMImport_AUTHORITY $SMImport_AUTHORITY -SMImport_CLIENT_ID $SMImport_CLIENT_ID -SMImport_CLIENT_CERT_KEY_PASSPHRASE $SMImport_CLIENT_CERT_KEY_PASSPHRASE
        }

        Try {
            $STIG = Invoke-RestMethod -Uri "$SMImport_API_BASE/stigs/$benchmarkId" -Headers $authHeader -Method GET
        }
        Catch {
            Write-Log -Path $LogPath -Message "ERROR: Unable to obtain stig, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            Return
        }

        $STIG_Data = @{
            title           = $STIG.title
            rulecount       = $STIG.rulecount
            benchmarkId     = $benchmarkID
            revisionStrs    = $STIG.revisionStrs
            lastRevisionStr = $STIG.lastRevisionDate
        }

        $Review_Data = New-Object System.Collections.Generic.List[System.Object]

        Foreach ($Vuln in $Scan_Object.VulnResults) {
            Switch ($Vuln.Status) {
                "NotAFinding" {
                    $result = "pass"
                    $status = $ImportRules.settings.importOptions.autostatus.pass
                }
                "Open" {
                    $result = "fail"
                    $status = $ImportRules.settings.importOptions.autostatus.fail
                }
                "Not_Applicable" {
                    $result = "notapplicable"
                    $status = $ImportRules.settings.importOptions.autostatus.notapplicable
                }
                "Not_Reviewed" {
                    $result = "notchecked"
                    $status = "saved"
                }
            }

            If ($Vuln.STIGMan.AFMod -eq $true) {
                $NewObj = [PSCustomObject]@{
                    ruleId       = $Vuln.RuleID
                    result       = $result
                    detail       = $Vuln.FindingDetails
                    comment      = $Vuln.Comments
                    resultEngine = @{
                        type         = "script"
                        product      = "Evaluate-STIG"
                        version      = ($Scan_Object.ESData.ModuleVersion).ToString()
                        time         = $Scan_Object.ESData.StartTime
                        checkcontent = @{
                            location = $Scan_Object.ESData.ModuleName
                        }
                        overrides    = @{
                            authority = $Vuln.STIGMan.Answerfile
                            oldResult = $Vuln.STIGMan.OldStatus
                            newResult = $Vuln.STIGMan.NewStatus
                            remark    = "Evaluate-STIG Answer File"
                        }
                    }
                    saved        = $status
                }
            }
            Else {
                $NewObj = [PSCustomObject]@{
                    ruleId       = $Vuln.RuleID
                    result       = $result
                    detail       = $Vuln.FindingDetails
                    comment      = $Vuln.Comments
                    resultEngine = @{
                        type         = "script"
                        product      = "Evaluate-STIG"
                        version      = ($Scan_Object.ESData.ModuleVersion).ToString()
                        time         = $Scan_Object.ESData.StartTime
                        checkcontent = @{
                            location = $Scan_Object.ESData.ModuleName
                        }
                    }
                    saved        = $status
                }
            }

            $null = $Review_Data.Add($NewObj)
        }

        Try {
            $Collections = Invoke-RestMethod -Uri "$SMImport_API_BASE/collections" -Headers $authHeader -Method GET
        }
        Catch {
            Write-Log -Path $LogPath -Message "ERROR: Unable to obtain collections, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            Return
        }

        Try {
            $Collection = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets?collectionId=$SMImport_COLLECTION_ID" -Headers $authHeader -Method GET
        }
        Catch {
            Write-Log -Path $LogPath -Message "ERROR: Unable to access $SMImport_COLLECTION_ID, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            Return
        }

        $assetid = ($collection | Where-Object { $_.name -eq $CKL_HOST_NAME }).assetid

        If (-Not($assetid)) {
            Write-Log -Path $LogPath -Message "$CKL_HOST_NAME not found in $(($Collections | Where-Object {$_.collectionID -eq $SMImport_COLLECTION_ID}).Name). Attempting POST..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

            $body = @{
                name         = $CKL_HOST_NAME
                fqdn         = $Scan_Object.TargetData.FQDN
                collectionId = $SMImport_COLLECTION_ID
                description  = ""
                ip           = $Scan_Object.TargetData.IPAddress
                mac          = $Scan_Object.TargetData.MacAddress
                noncomputing = $false
                metadata     = @{
                    cklRole = $Scan_Object.TargetData.Role
                }
                stigs        = @($STIG_Data.benchmarkId)
            }

            if ([bool]::Parse($Scan_Object.TargetData.cklWebOrDatabase)) {
                $body.metadata += @{
                    cklWebOrDatabase = $Scan_Object.TargetData.cklWebOrDatabase
                    cklWebDbSite = $Scan_Object.TargetData.Site
                    cklWebDbInstance = $Scan_Object.TargetData.Instance
                    cklHostName = $Scan_Object.TargetData.Hostname
                }
            }

            Try {
                $null = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets" -Headers $authHeader -ContentType 'application/json' -Method POST -Body (ConvertTo-Json -InputObject $body -Depth 20) -SkipHttpErrorCheck -MaximumRetryCount $MaximumRetryCount

                Write-Log -Path $LogPath -Message "Able to access $CKL_HOST_NAME for POST..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "$CKL_HOST_NAME posted for $($STIG_Data.Title)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            }
            Catch {
                Write-Log -Path $LogPath -Message "ERROR: Unable to access $CKL_HOST_NAME for POST, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Return
            }
            #Get the collection again after POST
            Try {
                $Collections = Invoke-RestMethod -Uri "$SMImport_API_BASE/collections" -Headers $authHeader -Method GET
            }
            Catch {
                Write-Log -Path $LogPath -Message "ERROR: Unable to obtain collections, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Return
            }

            Try {
                $Collection = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets?collectionId=$SMImport_COLLECTION_ID" -Headers $authHeader -Method GET
            }
            Catch {
                Write-Log -Path $LogPath -Message "ERROR: Unable to access $SMImport_COLLECTION_ID, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Return
            }

            $assetid = ($collection | Where-Object { $_.name -eq $CKL_HOST_NAME }).assetid
        }

        $body = @{
            title           = $STIG.title
            rulecount       = $STIG.rulecount
            benchmarkId     = $benchmarkID
            revisionStrs    = $STIG.revisionStrs
            lastRevisionStr = $STIG.lastRevisionDate
        }

        Try {
            $null = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets/$assetId/stigs/$benchmarkId" -Headers $authHeader -ContentType 'application/json' -Method PUT -Body (ConvertTo-Json -InputObject $body -Depth 20) -SkipHttpErrorCheck -MaximumRetryCount $MaximumRetryCount

            Write-Log -Path $LogPath -Message "Able to access $CKL_HOST_NAME for PUT..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Log -Path $LogPath -Message "$CKL_HOST_NAME posted for $($STIG_Data.Title) ($benchmarkId)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Catch {
            Write-Log -Path $LogPath -Message "ERROR: Unable to access $CKL_HOST_NAME for STIG assign, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            Return
        }

        $Review_Data | ForEach-Object {
            If ($_.resultEngine.product -eq "Evaluate-STIG" ) {
                If ($_.resultEngine.overrides) {
                    $body = @{
                        ruleId       = $_.ruleId
                        result       = $_.result
                        detail       = $_.detail
                        comment      = $_.comment
                        resultEngine = @{
                            type         = $_.resultEngine.type
                            product      = $_.resultEngine.product
                            version      = $_.resultEngine.version
                            time         = $_.resultEngine.time
                            checkContent = @{
                                location = $_.resultEngine.checkcontent.location
                            }
                            overrides    = @($_.resultEngine.overrides)
                        }
                        status       = $_.status
                    }
                }
                Else {
                    $body = @{
                        ruleId       = $_.ruleId
                        result       = $_.result
                        detail       = $_.detail
                        comment      = $_.comment
                        resultEngine = @{
                            type         = $_.resultEngine.type
                            product      = $_.resultEngine.product
                            version      = $_.resultEngine.version
                            time         = $_.resultEngine.time
                            checkContent = @{
                                location = $_.resultEngine.checkcontent.location
                            }
                        }
                        status       = $_.status
                    }
                }
            }
            Else {
                $body = @{
                    ruleId  = $_.ruleId
                    result  = $_.result
                    detail  = $_.detail
                    comment = $_.comment
                    status  = $_.status
                }
            }
            $null = $Body_Array.Add($body)
        }

        Try {
            Write-Host "    AssetID: $($assetId) - Uploading $(($Body_Array | Measure-Object).Count) reviews for $benchmarkID..." -ForegroundColor DarkYellow -NoNewline
            Write-Log -Path $LogPath -Message "AssetID: $($assetId) - Uploading $(($Body_Array | Measure-Object).Count) reviews for $benchmarkID" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $null = Invoke-RestMethod -Uri "$SMImport_API_BASE/collections/$SMImport_COLLECTION_ID/reviews/$assetId" -Headers $authHeader -ContentType 'application/json' -Method POST -Body (ConvertTo-Json -InputObject $Body_Array -Depth 20) -SkipHttpErrorCheck -MaximumRetryCount $MaximumRetryCount
            Write-Host " Success" -ForegroundColor Green
        }
        Catch {
            Write-Host " Fail" -ForegroundColor Red
            Write-Log -Path $LogPath -Message "ERROR: Unable to access $CKL_HOST_NAME for Reviews, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        }
    }
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCATKdbpqWXHqluJ
# n43qxC8r+aoFslH4iv6XCkn3AL93GaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCBdujAXjcKHsReTmrbVNaDcRmZsZVjeTloIurooWEZV5jANBgkqhkiG9w0BAQEF
# AASCAQCPv1eMoTTbkPQ1G1Xm2yWN+u8J+Eyw5r0kodcIwUB2iarHS5q54wfSZLMe
# /psPbNhGkZqkvTEGQ6H8l5q7nxX4Pg53OMyi80r6+2rCvPaaf4kmoeenN7ShUKEB
# XNZ6Aw2ZYovV8z9enD8E7rIPDOKiVoXeVyis9U8WGNwtJPUqMELyEodbl9zYSxDN
# uIQwRUaMupWAQk/2cHIDl1OU51gQ0cHt+b0xxyfDoqU5MhIgbb7vnBQDw1v6Hg/U
# lZO+5ew/2+xmiH4AAWOwEp8OG4GfxwbXvodOwcWYLeogO3OPeV44PIdWcYCLqY8+
# YBLPXWq9H0exSxgJILOTIx0Kt5ThoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMjE3MTAwOFowLwYJKoZIhvcNAQkEMSIEIAjNQd34CDGifXfWTP0FKx0RVfPE
# o6vsosGxqXFL0YPZMA0GCSqGSIb3DQEBAQUABIICAIwl2vU2UHSYNjc6y6/QMI20
# Xx58vXoJtyGHed0CxEzCJLbrFqr1awguFOJNX0FNRZWIYqd9kIqiWbY0bq4ivzAO
# 4Gq/Cxt/pews2mrI8K54nSIj44EB/Yr7ApvzNOxZOXhHFsftOgSgiPSNUFKK3eCM
# 5WjsZXnQoi9VtNev915ZDj1Wy5ecM9Xs6Xw+ffAea6MgKcKBlLATq2JyoutcO0VI
# fKHA36B6mDR44zruL+Pu2NlLIwy9mHfYZaDBQdFFlGr8qjueQQqvZdH7plpyX5nr
# L6rf9uwXzy6ACS/sct7nn/qtH1wJtY+QuT6H6ELMLbgg+0ZLOlN+jlwv/EdpqHN+
# VLeAN2fU4h0jVIQr03VpoJ5iG2KFLJn0DsewmqEJ5If9OtZ/AjQS9kumCDFr6Eii
# C1gkkzu2gL+McO5UnaBcAbq8WC4Cc6BTJFPEruQAPrDKXBzXNoirrC/6iMEK38Cj
# HhPVocGRu+c9k3oqg0KbWByHF8ywRguwsAxwAToo8bkbRdTb0lmrRN+Wd32Q+Jzp
# u+/HiErFQsW9TmLqFQ7pbuxbrT9PaiD17h5cZOdcBSAEL0kCNzTcxGr6OS06n9o+
# lN74vPUZ3I+LqfER3ltBkEY7WrL9ZtMbC889XhX6qXaeiqC6mUUJSsVVslfB4jAH
# WSdpW9aq5hToTe1Ck1x0
# SIG # End signature block
