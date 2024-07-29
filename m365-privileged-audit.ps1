# Justin Tucker - 2024-07-29
# SPDX-FileCopyrightText: Copyright © 2024, Justin Tucker
# - https://github.com/jst327/m365-privileged-audit

# Parameters
$m = 'Microsoft.Graph'
$rowCount = 1

# Requires PowerShell 5.1 or later
# Request .NET Framework 4.7.2 or later

## Check if execution policy is already set to bypass. If not set to remote signed.
    if (Get-ExecutionPolicy -List | Where-Object ExecutionPolicy -eq Bypass) {
    }
    else {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    }

## If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        write-host "Module $m is already imported."
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m -Verbose
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m -Verbose
            }
            else {

                # If the module is not imported, not available and not in the online gallery then abort
                write-host "Module $m not imported, not available and not in an online gallery, exiting."
                EXIT 1
            }
        }
    }

## Login to M365 tenant and approve delegated permissions to run scripts
Connect-MgGraph -Scopes "Organization.Read.All" -NoWelcome


## Licensing audit
$licenseFilePath = "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv"
$licenseLocalPath = (Get-Location).Path
(Invoke-WebRequest $licenseFilePath -OutFile $licenseLocalPath).content
$licenseHash = @{}
Import-Csv ".\Product names and service plan identifiers for licensing.csv" | Select-Object Product_Display_Name, String_Id -unique | ForEach-Object {$licenseHash.add($_.String_Id, $_.Product_Display_Name)}


Connect-Graph -Scopes Organization.Read.All -NoWelcome
Get-MgSubscribedSKU -All | Select-Object SkuPartNumber, SkuId, @{Name = "ActiveUnits"; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits |
    ForEach-Object {
        [PSCustomObject]@{
        'Row#' = $rowCount++
        'License'  = $licenseHash.($_.SkuPartNumber)
        'In Use'  = $_.ConsumedUnits
        'Total' = $_.ActiveUnits
        'Available' = $_.ActiveUnits - $_.ConsumedUnits
    } 
} | Sort-Object Row | Out-GridView -Title 'Microsoft 365 Licensing'

## Admin role audit
# Fetch a specific directory role by ID
#Connect-Graph -Scopes RoleManagement.Read.All -NoWelcome
# Fetch membership for a role


#Connect-MgGraph -Scopes EntitlementManagement.Read.All, Directory.Read.All, RoleManagement.Read.All, RoleManagement.Read.Directory, RoleManagement.Read.Exchange -NoWelcome


#Connect-MgGraph -Scopes "Directory.Read.All" -NoWelcome
#[System.Collections.ArrayList]$roles = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id
#[System.Collections.ArrayList]$userId = Get-MgUser
#[System.Collections.ArrayList]$roleAssignment = Get-MgRoleManagementDirectoryRoleAssignment | Select-Object PrincipalId, RoleDefinitionId
#foreach ($item in $userId) {
#    foreach ($role in $item) {
#       $role | Add-Member -MemberType NoteProperty -Name 'Test' -Value ($roleAssignment | Where-Object { $_.RoleId -eq $role.Id}).PrincipalId
#    }
#}

#userId | Out-GridView -Title 'Admin Roles'



#Get-MgRoleManagementDirectoryRoleAssignment | Where-Object RoleDefinitionId -eq $roleName.Id

#Get-MgRoleManagementDirectoryRoleDefinition | Where-Object DisplayName -eq 'Global Administrator' | fl

#Get-MgUser | Where-Object Id -eq $Id