<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" exclude-result-prefixes="#all" expand-text="yes">
    <xsl:template match="/">
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
                        background-color: #2e86c1;
                        color: #ffffff;
                        text-align: left;
                    }

                    .styled-table th,
                    .styled-table td {
                        text-align: center;
                        padding: 12px 15px;
                    }

                    .styled-table tbody tr:last-of-type {
                        border-bottom: 2px solid #2e86c1;
                    }

                    .styled-table tbody tr.active-row {
                        font-weight: bold;
                        color: #3498db;
                    }

                    .hidden {
                        visibility: hidden;
                    }

                    .button {
                        color: #494949;
                        text-align: center;
                        text-transform: uppercase;
                        text-decoration: none;
                        background-color: #aed6f1;
                        padding: 20px;
                        border: 4px solid #494949;
                        border-radius: 10px;
                        display: inline-block;
                        transition: all 0.4s ease 0s;
                        width: 250px;
                        height: 20px;
                        margin: 5px;
                    }

                    .risk-VeryHigh td {
                        color: #4c4c4c;
                        background-color: #ffa5a5;
                        border-top: 2px solid #fafafa;
                    }

                    .risk-High td {
                        color: #5b5b5b;
                        background-color: #ffc8a0;
                        border-top: 2px solid #fafafa;
                    }

                    .risk-Moderate td {
                        color: #737373;
                        background-color: #ffffb9;
                        border-top: 2px solid #fafafa;
                    }

                    .risk-Low td {
                        color: #494949;
                        background-color: #aed6f1;
                        border-top: 2px solid #fafafa;
                    }

                    .risk-VeryLow td {
                        color: #676767;
                        background-color: #d0f0c0;
                        border-top: 2px solid #fafafa;
                    }

                    .stig_button {
                        color: #494949;
                        text-align: center;
                        text-transform: uppercase;
                        text-decoration: none;
                        background-color: #aed6f1;
                        padding: 20px;
                        border: 4px solid #494949;
                        border-radius: 10px;
                        display: inline-flex;
                        justify-content: center;
                        align-items: center;
                        transition: all 0.4s ease 0s;
                        width: 450px;
                        height: 10px;
                    }

                    .button:hover{
                        color: #ffffff;
                        background: #2e86c1;
                        border-color: #2e86c1;
                        transition: all 0.4s ease 0s;
                        cursor: pointer;
                    }

                    .stig_button:hover{
                        color: #ffffff;
                        background: #2e86c1;
                        border-color: #2e86c1;
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

                    caption{
                        text-align: center;
                        margin-bottom: 5px;
                        font-size: 200%;
                        padding: 5px;
                        font-weight: bold;
                    }

                    .grid-container {
                        display: inline-grid;
                        grid-template-columns: auto auto auto;
                        padding: 10px;
                    }

                    .grid-item {
                        padding: 20px;
                        text-align: center;
                    }

                    .sortheading {
                        cursor: pointer;
                    }

                    .sortheading::after {
                        content: " ↑↓";
                        font-size: 10px;
                        vertical-align: top;
                    }

                    .filterdata,
                    .filterdata td {
                        margin-left: 16px;
                        text-align: left;
                        background-color: #ffffff;
                    }

                    .status-NF td {
                        color: #676767;
                        background-color: #d0f0c0;
                        border-top: 2px solid #fafafa;
                    }

                    .status-O_high td {
                        color: #4c4c4c;
                        background-color: #ffa5a5;
                        border-top: 2px solid #fafafa;
                    }

                    .status-O_med td {
                        color: #5b5b5b;
                        background-color: #ffc8a0;
                        border-top: 2px solid #fafafa;
                    }

                    .status-O_low td {
                        color: #737373;
                        background-color: #ffffb9;
                        border-top: 2px solid #fafafa;
                    }

                    .status-NA td {
                        color: #4a4a4a;
                        background-color: #c8c8c8;
                        border-top: 2px solid #fafafa;
                    }

                    .status-NR td {
                        color: #6d6d6d;
                        background-color: #f0f0f0;
                        border-top: 2px solid #fafafa;
                    }

                    .CellWithComment{
                        position:relative;
                        text-decoration:underline;
                        text-decoration-style: dotted;
                    }

                    .CellComment{
                        display:none;
                        position:absolute;
                        z-index:100;
                        border:1px;
                        background-color:#555555;
                        border-style:solid;
                        border-width:1px;
                        border-color: #555555;
                        border-radius: 10px;
                        padding:3px;
                        color:#C9C9C9;
                        top:20px;
                        left:20px;
                    }

                    .CellWithComment:hover span.CellComment{
                        display:block;
                    }
                </style>
                <script>
                    var topbutton = document.getElementById("topbtn");

                    function topFunction() {
                        document.body.scrollTop = 0;
                        document.documentElement.scrollTop = 0;
                    }

                    function change(table_value) {
                        var x = document.getElementById(table_value);
                        var rows = document.getElementById(table_value).getElementsByTagName("tbody");

                        if (x.style.display === "none") {
                        x.style.display = "table";
                        } else {
                            x.style.display = "none";
                        }
                    }

                    function sortTable(n,table_value) {
                        // https://www.w3schools.com/howto/howto_js_sort_table.asp
                        var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
                        table = document.getElementById(table_value);
                        switching = true;
                        // Set the sorting direction to ascending:
                        dir = "asc";
                        /* Make a loop that will continue until
                        no switching has been done: */
                        while (switching) {
                            // Start by saying: no switching is done:
                            switching = false;
                            rows = table.rows;
                            /* Loop through all table rows (except the
                            first, which contains table headers): */
                            for (i = 1; i &lt; (rows.length - 1); i++) {
                                // Start by saying there should be no switching:
                                shouldSwitch = false;
                                /* Get the two elements you want to compare,
                                one from current row and one from the next: */
                                x = rows[i].getElementsByTagName("TD")[n];
                                y = rows[i + 1].getElementsByTagName("TD")[n];
                                /* Check if the two rows should switch place,
                                based on the direction, asc or desc: */
                                if (dir == "asc") {
                                if (x.innerHTML.toLowerCase() &gt; y.innerHTML.toLowerCase()) {
                                    // If so, mark as a switch and break the loop:
                                    shouldSwitch = true;
                                    break;
                                }
                                } else if (dir == "desc") {
                                    if (x.innerHTML.toLowerCase() &lt; y.innerHTML.toLowerCase()) {
                                        // If so, mark as a switch and break the loop:
                                        shouldSwitch = true;
                                        break;
                                    }
                                }
                            }
                            if (shouldSwitch) {
                                /* If a switch has been marked, make the switch
                                and mark that a switch has been done: */
                                rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                                switching = true;
                                // Each time a switch is done, increase this count by 1:
                                switchcount ++;
                            } else {
                                /* If no switching has been done AND the direction is "asc",
                                set the direction to "desc" and run the while loop again. */
                                if (switchcount == 0 &amp;&amp; dir == "asc") {
                                    dir = "desc";
                                    switching = true;
                                }
                            }
                        }
                    }

                    function filterTable(input,table_value) {
                        // https://www.w3schools.com/howto/howto_js_filter_table.asp
                        // Declare variables
                        var input, filter, table, tr, td, i, txtValue;
                        input = document.getElementById(input);
                        filter = input.value.toUpperCase();
                        table = document.getElementById(table_value);
                        tr = table.getElementsByTagName("tr");

                        // Loop through all table rows, and hide those who don't match the search query
                        for (i = 0; i &lt; tr.length; i++) {
                            var allTDs = tr[i].getElementsByTagName("td");
                            for (index = 0; index &lt; allTDs.length; index++) {
                                txtValue = allTDs[index].textContent || allTDs[index].innerText;
                                if (txtValue.toUpperCase().indexOf(filter) &gt; -1) {
                                    tr[i].style.display = "";
                                    break;
                                } else {
                                    tr[i].style.display = "none";
                                }
                            }
                        }
                    }
                </script>
            </head>
            <body>
                <h1 align="center">Evaluate-STIG Summary Report</h1>
                <!--                    <h4 align="center">Click the Hostname button for Computer and STIG Info</h4>    -->
                <button onclick="topFunction()" id="topbtn" title="Go to Top">Top</button>
                <xsl:variable name="Summaries" select="Summaries/Summary" />
                <xsl:variable name="SummaryCount" select="count($Summaries)" />
                <xsl:for-each select="Summaries/Summary">
                    <xsl:variable name="ComputerName" select="Computer/Name" />
                    <!-- Commenting out ComputerName button.  May use in future.
                        <xsl:choose>
                            <xsl:when test="$SummaryCount > 1">
                                <div class="grid-container">
                                    <div class="grid-item"><div class="button_cont" align="center"><a class="button" id="button" onclick="change('{$ComputerName}')" title="Show/Hide {$ComputerName} information"><xsl:value-of select="Computer/Name" /></a></div></div>
                                </div>
                            </xsl:when>
                            <xsl:otherwise>
                                <div class="button_cont" align="center"><a class="button" id="button" onclick="change('{$ComputerName}')" title="Show/Hide {$ComputerName} information"><xsl:value-of select="Computer/Name" /></a></div>
                            </xsl:otherwise>
                    </xsl:choose>
                    -->
                    <table id="{$ComputerName}" class="styled-table">
                        <td>
                            <h2 align="center">
                                <xsl:value-of select="Computer/Name" />
                            </h2>
                            <h3 align="center">Scan Date:
                                <xsl:value-of select="Computer/ScanDate" />
                            </h3>
                            <h3 align="center">Evaluate-STIG Version:
                                <xsl:value-of select="Computer/EvalSTIGVer" />
                            </h3>
                            <h3 align="center">Scan Type:
                                <xsl:value-of select="Computer/ScanType" />
                            </h3>
                            <xsl:if test = "Computer/Marking">
                                <h3 align="center">Marking:
                                    <xsl:value-of select="Computer/Marking" />
                                </h3>
                            </xsl:if>
                            <h3 align="center">Scanned User Profile:
                                <xsl:value-of select="Computer/ScannedUserProfile" />
                            </h3>
                            <div class="button_cont" align="center">
                                <a class="button" id="button" onclick="change('{$ComputerName}_computer_table')" title="Show/Hide Computer information">Computer Information</a>
                                <a class="button" id="button" onclick="change('{$ComputerName}_stig_table')" title="Show/Hide STIG information">STIG Information</a>
                            </div>
                            <table id="{$ComputerName}_computer_table" class="styled-table">
                                <caption>Computer Information</caption>
                                <td>
                                    <table class="styled-table">
                                        <thead>
                                            <tr>
                                                <th>Manufacturer</th>
                                                <th>Model</th>
                                                <th>Serial Number</th>
                                                <th>BIOS Version</th>
                                                <th>OS Name</th>
                                                <th>OS Version</th>
                                                <th>OS Architecture</th>
                                                <th>CPU Architecture</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td>
                                                    <xsl:value-of select="Computer/Manufacturer" />
                                                </td>
                                                <td>
                                                    <xsl:value-of select="Computer/Model" />
                                                </td>
                                                <td>
                                                    <xsl:value-of select="Computer/SerialNumber" />
                                                </td>
                                                <td>
                                                    <xsl:value-of select="Computer/BIOSVersion" />
                                                </td>
                                                <td>
                                                    <xsl:value-of select="Computer/OSName" />
                                                </td>
                                                <td>
                                                    <xsl:value-of select="Computer/OSVersion" />
                                                </td>
                                                <td>
                                                    <xsl:value-of select="Computer/OSArchitecture" />
                                                </td>
                                                <td>
                                                    <xsl:value-of select="Computer/CPUArchitecture" />
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                    <table class="styled-table">
                                        <thead>
                                            <tr>
                                                <th>Interface Index</th>
                                                <th>Caption</th>
                                                <th>MAC Address</th>
                                                <th>IPv4 Addresses</th>
                                                <th>IPv6 Addresses</th>
                                            </tr>
                                        </thead>
                                        <xsl:for-each select="Computer/NetworkAdapters/Adapter">
                                            <tbody>
                                                <tr>
                                                    <td>
                                                        <xsl:value-of select="@InterfaceIndex" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="Caption" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="MACAddress" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="IPv4Addresses" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="IPv6Addresses" />
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </xsl:for-each>
                                    </table>
                                    <table class="styled-table">
                                        <thead>
                                            <tr>
                                                <th>Index</th>
                                                <th>Device ID</th>
                                                <th>Size</th>
                                                <th>Caption</th>
                                                <th>Serial Number</th>
                                                <th>Media Type</th>
                                                <th>Interface Type</th>
                                            </tr>
                                        </thead>
                                        <xsl:for-each select="Computer/DiskDrives/Disk">
                                            <tbody>
                                                <tr>
                                                    <td>
                                                        <xsl:value-of select="@Index" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="DeviceID" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="Size" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="Caption" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="SerialNumber" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="MediaType" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="InterfaceType" />
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </xsl:for-each>
                                    </table>
                                    <table class="styled-table">
                                        <thead>
                                            <tr>
                                                <th>Risk Rating</th>
                                                <th>Weighted Average</th>
                                                <th>CAT I Open|NR</th>
                                                <th>CAT I Possible</th>
                                                <th>CAT II Open|NR</th>
                                                <th>CAT II Possible</th>
                                                <th>CAT III Open|NR</th>
                                                <th>CAT III Possible</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <xsl:for-each select="Computer/Score">
                                                <xsl:variable name="Class">
                                                    <xsl:choose>
                                                        <xsl:when test="RiskRating='Very High'">
                                                            <xsl:value-of select="'risk-VeryHigh'" />
                                                        </xsl:when>
                                                        <xsl:when test="RiskRating='High'">
                                                            <xsl:value-of select="'risk-High'" />
                                                        </xsl:when>
                                                        <xsl:when test="RiskRating='Moderate'">
                                                            <xsl:value-of select="'risk-Moderate'" />
                                                        </xsl:when>
                                                        <xsl:when test="RiskRating='Low'">
                                                            <xsl:value-of select="'risk-Low'" />
                                                        </xsl:when>
                                                        <xsl:when test="RiskRating='Very Low'">
                                                            <xsl:value-of select="'risk-VeryLow'" />
                                                        </xsl:when>
                                                    </xsl:choose>
                                                </xsl:variable>
                                                <tr class="{$Class}">
                                                    <td>
                                                        <xsl:value-of select="RiskRating" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="WeightedAvg" />%
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="CATI_OpenNRTotal" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="CATI_PossibleTotal" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="CATII_OpenNRTotal" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="CATII_PossibleTotal" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="CATIII_OpenNRTotal" />
                                                    </td>
                                                    <td>
                                                        <xsl:value-of select="CATIII_PossibleTotal" />
                                                    </td>
                                                </tr>
                                            </xsl:for-each>
                                        </tbody>
                                    </table>
                                </td>
                            </table>
                            <table id="{$ComputerName}_stig_table" class="styled-table">
                                <caption>STIG Information</caption>
                                <thead>
                                    <tr>
                                        <th></th>
                                        <th>Start Time</th>
                                        <th>Open</th>
                                        <th>Not A Finding</th>
                                        <th>Not Applicable</th>
                                        <th>Not Reviewed</th>
                                        <th title="(Not A Finding + Not Applicable)/Total Findings">EvalScore</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <xsl:for-each select="Results/Result">
                                        <xsl:variable name="STIG" select="@STIG" />
                                        <xsl:variable name="Table">
                                            <xsl:value-of select="translate($STIG,'\\','/')" />
                                        </xsl:variable>
                                        <tr>
                                            <td>
                                                <div class="button_cont" align="left">
                                                    <a class="stig_button" id="button" onclick="change('{$Table}_filter');change('{$Table}')" title="Show/Hide {STIG}">
                                                        <xsl:value-of select="@STIG" />
                                                    </a>
                                                </div>
                                            </td>
                                            <td>
                                                <xsl:value-of select="@StartTime" />
                                            </td>
                                            <td>
                                                <xsl:value-of select="CAT_I/@Open + CAT_II/@Open + CAT_III/@Open" />
                                            </td>
                                            <td>
                                                <xsl:value-of select="CAT_I/@NotAFinding + CAT_II/@NotAFinding + CAT_III/@NotAFinding" />
                                            </td>
                                            <td>
                                                <xsl:value-of select="CAT_I/@Not_Applicable + CAT_II/@Not_Applicable + CAT_III/@Not_Applicable" />
                                            </td>
                                            <td>
                                                <xsl:value-of select="CAT_I/@Not_Reviewed + CAT_II/@Not_Reviewed + CAT_III/@Not_Reviewed" />
                                            </td>
                                            <td>
                                                <xsl:value-of select="@EvalScore" />%</td>
                                        </tr>
                                        <tr>
                                            <td id="{$Table}_filter" class="filterdata" style="display:none">
                                                <input type="text" id="{$Table}_input" onkeyup="filterTable(`{$Table}_input`,`{$Table}`)" placeholder="Filter..." title="Type data to filter on" />
                                            </td>
                                        </tr>
                                        <tr>
                                            <td colspan="7">
                                                <table id="{$Table}" class="styled-table" style="display:none;">
                                                    <thead>
                                                        <tr>
                                                            <th onclick="sortTable(`0`,`{$Table}`)" class="sortheading" style="width:10%;" title="Sort by column">Severity</th>
                                                            <th onclick="sortTable(`1`,`{$Table}`)" class="sortheading" style="width:10%;" title="Sort by column">Status</th>
                                                            <th onclick="sortTable(`2`,`{$Table}`)" class="sortheading" style="width:10%;" title="Sort by column">Group ID</th>
                                                            <th onclick="sortTable(`3`,`{$Table}`)" class="sortheading" title="Sort by column">Rule Title</th>
                                                            <th onclick="sortTable(`4`,`{$Table}`)" class="sortheading" style="width:10%;" title="Sort by column">Override</th>
                                                            <th onclick="sortTable(`5`,`{$Table}`)" class="sortheading" style="width:10%;" title="Sort by column">AFMod</th>
                                                            <th onclick="sortTable(`5`,`{$Table}`)" class="sortheading" style="width:10%;" title="Sort by column">Pre-AF Status</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <xsl:for-each select="CAT_I/Vuln">
                                                            <xsl:variable name="Class">
                                                                <xsl:choose>
                                                                    <xsl:when test="@Status='Not_Applicable'">
                                                                        <xsl:value-of select="'status-NA'" />
                                                                    </xsl:when>
                                                                    <xsl:when test="@Status='NotAFinding'">
                                                                        <xsl:value-of select="'status-NF'" />
                                                                    </xsl:when>
                                                                    <xsl:when test="@Status='Open'">
                                                                        <xsl:value-of select="'status-O_high'" />
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <xsl:value-of select="'status-NR'" />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                            </xsl:variable>
                                                            <tr class="{$Class}">
                                                                <td>CAT I</td>
                                                                <td>
                                                                    <xsl:value-of select="@Status" />
                                                                </td>
                                                                <td>
                                                                    <xsl:value-of select="@ID" />
                                                                </td>
                                                                <td>
                                                                    <xsl:value-of select="@RuleTitle" />
                                                                </td>
                                                                <!-- Begin Override/Justification entry -->
                                                                <xsl:choose>
                                                                    <xsl:when test="@Override !=''">
                                                                        <td class="CellWithComment">
                                                                            <xsl:value-of select="@Override" />
                                                                            <span class="CellComment">
                                                                                <xsl:value-of select="@Justification" />
                                                                            </span>
                                                                        </td>
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <td />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                                <!-- End Override/Justification entry -->
                                                                <!-- Begin AF Mod/Pre-AF Status entries -->
                                                                <xsl:choose>
                                                                    <xsl:when test="@AFStatusChange !=''">
                                                                        <td>
                                                                            <xsl:value-of select="@AFStatusChange" />
                                                                        </td>
                                                                        <td>
                                                                            <xsl:value-of select="@PreAFStatus" />
                                                                        </td>
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <td />
                                                                        <td />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                                <!-- AF Mod/Pre-AF Status entries -->
                                                            </tr>
                                                        </xsl:for-each>
                                                        <xsl:for-each select="CAT_II/Vuln">
                                                            <xsl:variable name="Class">
                                                                <xsl:choose>
                                                                    <xsl:when test="@Status='Not_Applicable'">
                                                                        <xsl:value-of select="'status-NA'" />
                                                                    </xsl:when>
                                                                    <xsl:when test="@Status='NotAFinding'">
                                                                        <xsl:value-of select="'status-NF'" />
                                                                    </xsl:when>
                                                                    <xsl:when test="@Status='Open'">
                                                                        <xsl:value-of select="'status-O_med'" />
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <xsl:value-of select="'status-NR'" />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                            </xsl:variable>
                                                            <tr class="{$Class}">
                                                                <td>CAT II</td>
                                                                <td>
                                                                    <xsl:value-of select="@Status" />
                                                                </td>
                                                                <td>
                                                                    <xsl:value-of select="@ID" />
                                                                </td>
                                                                <td>
                                                                    <xsl:value-of select="@RuleTitle" />
                                                                </td>
                                                                <!-- Begin Override/Justification entry -->
                                                                <xsl:choose>
                                                                    <xsl:when test="@Override !=''">
                                                                        <td class="CellWithComment">
                                                                            <xsl:value-of select="@Override" />
                                                                            <span class="CellComment">
                                                                                <xsl:value-of select="@Justification" />
                                                                            </span>
                                                                        </td>
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <td />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                                <!-- End Override/Justification entry -->
                                                                <!-- Begin AF Mod/Pre-AF Status entries -->
                                                                <xsl:choose>
                                                                    <xsl:when test="@AFStatusChange !=''">
                                                                        <td>
                                                                            <xsl:value-of select="@AFStatusChange" />
                                                                        </td>
                                                                        <td>
                                                                            <xsl:value-of select="@PreAFStatus" />
                                                                        </td>
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <td />
                                                                        <td />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                                <!-- AF Mod/Pre-AF Status entries -->
                                                            </tr>
                                                        </xsl:for-each>
                                                        <xsl:for-each select="CAT_III/Vuln">
                                                            <xsl:variable name="Class">
                                                                <xsl:choose>
                                                                    <xsl:when test="@Status='Not_Applicable'">
                                                                        <xsl:value-of select="'status-NA'" />
                                                                    </xsl:when>
                                                                    <xsl:when test="@Status='NotAFinding'">
                                                                        <xsl:value-of select="'status-NF'" />
                                                                    </xsl:when>
                                                                    <xsl:when test="@Status='Open'">
                                                                        <xsl:value-of select="'status-O_low'" />
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <xsl:value-of select="'status-NR'" />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                            </xsl:variable>
                                                            <tr class="{$Class}">
                                                                <td>CAT III</td>
                                                                <td>
                                                                    <xsl:value-of select="@Status" />
                                                                </td>
                                                                <td>
                                                                    <xsl:value-of select="@ID" />
                                                                </td>
                                                                <td>
                                                                    <xsl:value-of select="@RuleTitle" />
                                                                </td>
                                                                <!-- Begin Override/Justification entry -->
                                                                <xsl:choose>
                                                                    <xsl:when test="@Override !=''">
                                                                        <td class="CellWithComment">
                                                                            <xsl:value-of select="@Override" />
                                                                            <span class="CellComment">
                                                                                <xsl:value-of select="@Justification" />
                                                                            </span>
                                                                        </td>
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <td />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                                <!-- End Override/Justification entry -->
                                                                <!-- Begin AF Mod/Pre-AF Status entries -->
                                                                <xsl:choose>
                                                                    <xsl:when test="@AFStatusChange !=''">
                                                                        <td>
                                                                            <xsl:value-of select="@AFStatusChange" />
                                                                        </td>
                                                                        <td>
                                                                            <xsl:value-of select="@PreAFStatus" />
                                                                        </td>
                                                                    </xsl:when>
                                                                    <xsl:otherwise>
                                                                        <td />
                                                                        <td />
                                                                    </xsl:otherwise>
                                                                </xsl:choose>
                                                                <!-- AF Mod/Pre-AF Status entries -->
                                                            </tr>
                                                        </xsl:for-each>
                                                    </tbody>
                                                </table>
                                            </td>
                                        </tr>
                                    </xsl:for-each>
                                </tbody>
                            </table>
                        </td>
                    </table>
                </xsl:for-each>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>