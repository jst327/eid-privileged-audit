# Justin Tucker - 2024-07-30
# SPDX-FileCopyrightText: Copyright © 2024, Justin Tucker
# - https://github.com/jst327/m365-privileged-audit

# Requires Microsoft Graph API
# Requires PowerShell 5.1 or later
# Request .NET Framework 4.7.2 or later

## Login to M365 tenant and approve delegated permissions to run scripts
Connect-MgGraph -Scopes 'Organization.Read.All' -NoWelcome


## Licensing audit
$rowCount = 1
$licenseHash = @{}
$licenseFilePath = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
[Text.Encoding]::UTF8.GetString((Invoke-WebRequest $licenseFilePath).RawContentStream.ToArray()) | ConvertFrom-CSV `
	| Select-Object Product_Display_Name, String_Id -Unique `
		| ForEach-Object{
			$licenseHash.Add($_.String_Id, $_.Product_Display_Name)
		} 

Get-MgSubscribedSKU -All | Select-Object SkuPartNumber, SkuId, @{Name = 'ActiveUnits'; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits |
	ForEach-Object {
		[PSCustomObject]@{
			'Row#' = $rowCount++
			'License'  = $licenseHash.($_.SkuPartNumber)
			'In Use'  = $_.ConsumedUnits
			'Total' = $_.ActiveUnits
			'Available' = $_.ActiveUnits - $_.ConsumedUnits
		} 
	} | Sort-Object 'Row#' | Out-GridView -Title 'Microsoft 365 Licensing'

## Admin role audit
# https://ourcloudnetwork.com/how-to-export-all-azuread-pim-roles-with-microsoft-graph-powershell/
$rowCount = 1
$EligiblePIMRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty *
$AssignedPIMRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty *

$PIMRoles = $EligiblePIMRoles + $AssignedPIMRoles

$Report = [System.Collections.Generic.List[Object]]::new()

foreach ($a in $PIMRoles) {
    $regex = "^([^.]+)\.([^.]+)\.(.+)$"
    $a.Principal.AdditionalProperties.'@odata.type' -match $regex | out-null

    $obj = [pscustomobject][ordered]@{
		'Row#'					= $rowCount++
    	'Assigned'				= $a.Principal.AdditionalProperties.displayName
    	'Assigned Type'			= $matches[3]
    	'Assigned Role'			= $a.RoleDefinition.DisplayName
    	'Assigned Role Scope'	= $a.directoryScopeId
    	'Assignment Type'		= (&{if ($a.AssignmentType -eq "Assigned") {"Active"} else {"Eligible"}})
    	'Is Built In'			= $a.roleDefinition.isBuiltIn
    	'Created Date (UTC)'	= $a.CreatedDateTime
    	'Expiration type'		= $a.ScheduleInfo.Expiration.type
    	'Expiration Date (UTC)'	= switch ($a.ScheduleInfo.Expiration.EndDateTime) {
        	{$a.ScheduleInfo.Expiration.EndDateTime -match '20'} {$a.ScheduleInfo.Expiration.EndDateTime}
        	{$a.ScheduleInfo.Expiration.EndDateTime -notmatch '20'} {"N/A"}
        }
    }
    $report.Add($obj)
}

$Report | Out-GridView -Title 'Microsoft 365 Privileged Users'
