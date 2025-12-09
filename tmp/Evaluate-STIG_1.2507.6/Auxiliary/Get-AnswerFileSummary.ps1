<#
    .Synopsis
    Create a HTML report for specified Answer File(S)
    .DESCRIPTION
    Creates a HTML report from Evaluate-STIG Answer Files.
    .EXAMPLE
    PS C:\> Get-AnswerfileSummary.ps1 -AFPath C:\Evaluate-STIG\AnswerFiles
    .EXAMPLE
    PS C:\> Get-AnswerfileSummary.ps1 -AFFile C:\Evaluate-STIG\AnswerFiles\Windows_10_Answerfile.xml
    .INPUTS
    -AFPath
        Path to the Evaluate-STIG Answer File directory.
    .INPUTS
    -AFFile
        Path to the Evaluate-STIG Answer File.
    .INPUTS
    -OutputPath
        Path to location to save Summary Report.
#>

Param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String[]]$AFPath,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String[]]$AFFile,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]$OutPutpath
)

Function Convert-AFFile {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$AFFile,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$OutPutpath
    )

    [xml]$AFTransform = @'
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
     <xsl:template match="/STIGComments">
          <html>
               <head>
                    <style type="text/css">
                         .styled-table {
                              border-collapse: collapse;
                              margin: 25px 0;
                              font-size: 0.9em;
                              font-family: sans-serif;
                              min-width: 400px;
                              box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
                              width: 100%
                         }
                         .styled-table thead tr {
                              background-color: #2E86C1;
                              color: #ffffff;
                              text-align: left;
                         }
                         .styled-table th,
                         .styled-table td {
                              padding: 12px 15px;
                         }
                         .styled-table tbody tr {
                              border-bottom: thin solid #dddddd;
                         }
                         .styled-table tbody tr:last-of-type {
                              border-bottom: 2px solid #3498DB;
                         }
                         .styled-table tbody tr.active-row {
                              font-weight: bold;
                              color: #3498DB;
                         }
                         .hidden {
                              visibility: hidden;
                         }
                         .button {
                              color: #494949 !important;
                              text-align: center;
                              text-transform: uppercase;
                              text-decoration: none;
                              backgrond: #AED6F1;
                              background-color: #AED6F1;
                              padding: 20px;
                              border: 4px solid #494949 !important;
                              display: inline-block;
                              transition: all 0.4s ease 0s;
                              width: 250px;
                              height: 20px;
                              margin: 5px;
                         }
                         .stig_button {
                              color: #494949 !important;
                              text-align: center;
                              text-transform: uppercase;
                              text-decoration: none;
                              backgrond: #ffffff;
                              padding: 20px;
                              border: 4px solid #494949 !important;
                              display: inline-block;
                              transition: all 0.4s ease 0s;
                              width: 450px;
                              height: 10px;
                         }
                         .button:hover{
                              color: #ffffff !important;
                              background: #f6b93b;
                              border-color: #f6b93b !important;
                              transition: all 0.4s ease 0s;
                              cursor: pointer;
                         }
                         .stig_button:hover{
                              color: #ffffff !important;
                              background: #f6b93b;
                              border-color: #f6b93b !important;
                              transition: all 0.4s ease 0s;
                              cursor: pointer;
                         }
                         #topbtn{
                              position: fixed;
                              bottom: 20px;
                              right: 30px;
                              z-index: 99;
                              font-size: 18px;
                              border: none;
                              outline: none;
                              background-color: red;
                              color: white;
                              cursor: pointer;
                              padding: 15px;
                              border-radius: 4px;
                         }
                         #topbtn:hover{
                              background-color: #555;
                         }
                         code {
                             background-color: #eef;
                             display: block;
                         }
                    </style>
                    <script>
                         var topbutton = document.getElementById("topbtn");
                         window.onscroll = function() {scrollFunction()};

                         function scrollFunction() {
                              if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
                                   topbutton.style.display = "block";
                              } else {
                                   topbutton.style.display = "none";
                              }
                         }
                         function topFunction() {
                              document.body.scrollTop = 0;
                              document.documentElement.scrollTop = 0;
                         }
                         function change(table_value) {
                              var x = document.getElementById(table_value);
                              if (x.style.display === "none") {
                                   x.style.display = "table";
                              } else {
                                   x.style.display = "none";
                              }
                         }
                    </script>
               </head>
               <body>
                    <button onclick="topFunction()" id="topbtn" title="Go to Top">Top</button>
                    <h1 align="center"><xsl:value-of select="@Name" /> STIG Answer File</h1>
                    <p><!--**************************************************************************************<br />
                        <b>This file contains answers for known opens and findings that cannot be evaluated through technical means.<br />
                        <b>&lt;STIGComments Name&gt;</b> must match the STIG name in STIGList.xml.  When a match is found, this answer file will automatically for the STIG.<br />
                        <b>&lt;Vuln ID&gt;</b> is the STIG VulnID.  Multiple Vuln ID sections may be specified in a single Answer File.<br />
                        <b>&lt;AnswerKey Name&gt;</b> is the name of the key assigned to the answer.  "DEFAULT" can be used to apply the comment to any asset.  Multiple AnswerKey Name sections may be configured within a single Vuln ID section.<br />
                        <b> *Note: If the Answer Key matches the hostname *exactly*, it will supersede any other key for the Vulnerability ID.<br />
                        <b>  Multiple hostnames can be used, separated by either a space or a comma.<br />
                        <b>&lt;ExpectedStatus&gt;</b> is the initial status after the checklist is created.  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".<br />
                        <b>&lt;ValidationCode&gt;</b> must be Powershell code that returns a True/False value.  If blank, "true" is assumed.<br />
                        <b> *Note: If Validation Code returns a PSCustomObject, the Object MUST contain both "Results" and "Valid" keys.  "Results" will be written to the Comments field of the STIG check.<br />
                        <b>&lt;ValidTrueStatus&gt;</b> is the status the check should be set to if ValidationCode returns "true".  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".  If blank, <b>&lt;ExpectedStatus&gt;</b> is assumed.<br />
                        <b>&lt;ValidTrueComment&gt;</b> is the verbiage to add to the Comments section if ValidationCode returns "true".<br />
                        <b>&lt;ValidFalseStatus&gt;</b> is the status the check should be set to if ValidationCode DOES NOT return "true".  Valid entries are "Not_Reviewed", "Open", "NotAFinding", and "Not_Applicable".  If blank, <b>&lt;ExpectedStatus&gt;</b> is assumed.<br />
                        <b>&lt;ValidFalseComment&gt;</b> is the verbiage to add to the Comments section if ValidationCode DOES NOT return "true".<br />
                        <br />
                        **************************************************************************************--></p>
                </body>
            </html>
        <xsl:for-each select="Vuln">
                <tbody><tr>
                    <td><div class="button_cont"><a class="stig_button" id="button" onclick="change('{@ID}')" title="Show/Hide {@ID}"><xsl:value-of select="@ID" /></a></div></td>
                </tr></tbody>
                    <td><table id="{@ID}" class="styled-table" style="display:none">
                        <thead><tr>
                            <th>Name</th>
                            <th>Expected Status</th>
                            <th>Validation Code</th>
                            <th>Valid True Status</th>
                            <th>Valid True Comment</th>
                            <th>Valid False Status</th>
                            <th>Valid False Comment</th>
                        </tr></thead>
                        <xsl:for-each select="AnswerKey">
                            <tbody><tr>
                                    <td><xsl:value-of select="@Name" /></td>
                                    <td><xsl:value-of select="ExpectedStatus" /></td>
                                    <td><code><xsl:value-of select="ValidationCode" /></code></td>
                                    <td><xsl:value-of select="ValidTrueStatus" /></td>
                                    <td><xsl:value-of select="ValidTrueComment" /></td>
                                    <td><xsl:value-of select="ValidFalseStatus" /></td>
                                    <td><xsl:value-of select="ValidFalseComment" /></td>
                            </tr></tbody>
                        </xsl:for-each>
                    </table></td>
        </xsl:for-each>
     </xsl:template>
</xsl:stylesheet>
'@

    $AFxslt = New-Object System.Xml.Xsl.XslCompiledTransform
    $AFxslt.load($AFTransform)
    $AFxslt.Transform($AFFile, $(Join-Path $OutPutpath -ChildPath "$($(Split-Path $AFFile -Leaf).replace('.xml','')).html"))

}

if (!($OutPutpath)) {
    $OutPutpath = $PSScriptRoot
}

$Answerfiles = New-Object -TypeName "System.Collections.ArrayList"
$Answerfiles = [System.Collections.ArrayList]@()

if ($AFPath){
    $Answerfiles += $(Get-ChildItem -Path $AFPath -File).FullName
}

if ($AFFile){
    $AFFile | ForEach-Object {
        if ($(Split-Path $_ -Leaf) -notin $(Split-Path $Answerfiles -Leaf)) {
            $Answerfiles += ($_)
        }
        else{
            Write-Host "Duplicate $(Split-Path $_ -Leaf) found in $AFPath.  Skipping."
        }
    }
}

$Answerfiles | Foreach-Object {
    Convert-AFFile -AFFile $_ -OutPutpath $OutPutpath
}

# SIG # Begin signature block
# MIIjzgYJKoZIhvcNAQcCoIIjvzCCI7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBWCEQCOMv+vyTs
# NIU0lnRAnRds4aNQD/qLWcf+yIIFX6CCHe0wggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHFFuwps
# 5lu2IRild4daau8Yeq/4V7pk2KpduKKwhbzKMA0GCSqGSIb3DQEBAQUABIIBAKRm
# ++JHCH3IzMainPnQi73ycRs9BeNly8D4nVWfzCk5Tq0kWKHddT725sOfClFVIZQE
# QH5MP84cHHGwkIm1IP9FWyTYxByLlAvYfTyGb+OXPNXNmLHIwTv8MPyzo+jSDWP5
# 6MO+9CBVpfzaTVBs9CVX8oZ/v/4AFRkhwg0PjaiETrz34ADB8ItYkDzQxGi/iBqg
# kO9rsWfXZn3MWJ/b/TNSEaMSdd2gbSNTnYl4XEWsjxj3Iv0ZedgBfcYgfxMyVGx+
# hVWYwjiUVhOKsq/x/iIJDAvGcBzerJmqPh841mgPn9ezSIQhbtCYtr9JoQT8VPJh
# EDHZdIlopNPXjhTmUbOhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5n
# IENBAhALrma8Wrp/lYfG+ekE4zMEMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNDA3MTI1MzQ4WjAv
# BgkqhkiG9w0BCQQxIgQgCIWlWy4TSLJzIMgEIHqbXWh9esyY8RYQd9LWexU8l24w
# DQYJKoZIhvcNAQEBBQAEggIAcBQYU1qouno31sG9NOv3m31iMEcIL6sR3LqY0Bqb
# A51+/yG+ZOXzEjXWr5GnIO25HISek1r9CwtDkRDkCHf2UHsH8hXx7zSWQ5Bw8yHg
# vks6jCEc3+JVSpgqgwyzzx9hBzip5/F6NAOInXkGSOl1jqpw6vXpryaAIKxQWm+3
# o0jZDBtHeMBQmUrV7WldeIFwETvh+k9yVhS6/cJL6PaR5ihMn36HV53QXV9jp4iV
# wK6es95PMBc5gE4BWReGHLjTxsaid9NDBe0nWSf0jDlR9Q1IXhMOFp5AsSjTWe84
# PldzFQP/QDh8BDrARiarVQne9oG/f345Ikut8pj6rXoxgEcbBJEmo9nzQnntH3Py
# 0nPGe8OrLn7WhaoJE1ortNA75SucUiyIbGayTL3RLiHFgW6QyJ9n6oTMLLyEZoaT
# CVHgUpGhuor4WRQnw3j3JyWRFhi2fz/GTN86VZtF66/6XGczPu7/vOlf5nLM0ETd
# qbKUqSP7dztDc6/hLH0RrEjT+gzkCiA8hyCBGCdhNB8H4150tScUibBl+R+12Nc1
# sqHrCcUWzfAsmOPd/lnMifnc3mTzsyZCPXFXmn31jK1ZV9WUfEsdgpvC7SzrqwMw
# VsoSTr9XaSKqYHVtieWto8IEMlwI7C1aTU7JFW0H/rJ+W1AVc/8XO438wAjtv9eP
# HyA=
# SIG # End signature block
