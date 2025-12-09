# Evaluate-STIG Auxiliary Files

These are optional files to use in conjunction with Evaluate-STIG.

### ConfigMgr

Includes a sample Configuration Baseline/Configuration Item for use with Microsoft Configuration Manager.  Refer to the included documentation on importing and configuring in your environment.

### Evaluate-STIG.yml

An Ansible playbook designed to assist with remote Evaluate-STIG scans in a Linux-only environment. The default host list is set to "all"; please adjust as necessary. The playbook does modify "/etc/sudoers" temporarily to allow for rsync without a password. The playbook will remove this line regardless of if the sync passes or fails. The privileged user prompt is the user added to "/etc/sudoers" for the duration of the sync. The local path is where the Evaluate-STIG results are saved on the local host machine. The final part of the playbook cleans Evaluate-STIG from the remote host.  Previous scans are purged from the local host machine prior to syncing to defined local directory due to how the sync is designed.

**Note:**  The Evaluate-STIG directory must reside in the same directory as the Evaluate-STIG playbook -e.g. both Evaluate-STIG.yml and Evaluate-STIG in /etc/ansible.  `sudo bash Evaluate-STIG_Bash.sh --DownloadPS` should be run prior to executing the playbook.

### Get-AnswerFileSummary.ps1

Creates a HTML report from Evaluate-STIG Answer Files.

Use `Get-Help .\Get-AnswerFileSummary.ps1 -Full` for usage.

### Get-CklData.ps1

A script to parse a .ckl file.

Use `Get-Help .\Get-CklData.ps1 -Full` for usage.

### Get-SummaryReport.ps1

Creates a report from Evaluate-STIG Summary Reports.  Suggest running Validate-Results.ps1 prior to creating this report.  Excel is required be installed.

Use `Get-Help .\Get-SummaryReport.ps1 -Full` for usage.

### Maintain-AnswerFiles.ps1

Performs simple maintenance on Evaluate-STIG Answer Files.  Updates Vuln IDs to new STIGs that have been converted to DISA's new content management system.  It also identifies and optionally removes answers for Vuln IDs that have been removed from the STIG.  Finally, it will convert answer files from previous format to new format compatible with 1.2507.2 and greater.

Use `Get-Help .\Maintain-AnswerFiles.ps1 -Full` for usage.

### Validate-Results.ps1

Validates the CKLs against the SummaryReport.xml to ensure all expected CKLs exist.

Use `Get-Help .\Validate-Results.ps1 -Full` for usage.
