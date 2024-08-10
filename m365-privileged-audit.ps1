# Justin Tucker - 2024-08-09
# SPDX-FileCopyrightText: Copyright © 2024, Justin Tucker
# - https://github.com/jst327/m365-privileged-audit

# Requires Microsoft Graph API
# Requires PowerShell 5.1 or later
# Request .NET Framework 4.7.2 or later

# Ensure required modules are installed
#Install-Module Microsoft.Graph -Force -Scope CurrentUser

# Connect to Microsoft Graph
function Connect-MicrosoftGraph {
    #Import-Module Microsoft.Graph
    Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "AuditLog.Read.All", "Directory.Read.All" -NoWelcome
}

# Function to get a list of all users
function Get-AllUsers {
    Connect-MicrosoftGraph
    $users = Get-MgUser -All | Sort-Object DisplayName
    $users | Select-Object @{Name='Index';Expression={[array]::IndexOf($users, $_) + 1}}, DisplayName, UserPrincipalName, Mail
}

# Function to get a list of all groups
function Get-AllGroups {
    Connect-MicrosoftGraph
    $groups = Get-MgGroup -All | Sort-Object DisplayName
    $groups | Select-Object @{Name='Index';Expression={[array]::IndexOf($groups, $_) + 1}}, DisplayName, Mail
}

# Function to get a list of privileged users
function Get-PrivilegedUsers {
    $EligiblePIMRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty *
    $AssignedPIMRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty *
    
    $PIMRoles = $EligiblePIMRoles + $AssignedPIMRoles
    
    $privilegedUsers = [System.Collections.Generic.List[Object]]::new()
    
    foreach ($role in $PIMRoles) {
        $regex = "^([^.]+)\.([^.]+)\.(.+)$"
        $role.Principal.AdditionalProperties.'@odata.type' -match $regex | out-null
    
        $obj = [pscustomobject][ordered]@{
            'Assigned Role'			= $role.RoleDefinition.DisplayName
            'Assigned Role Scope'	= $role.directoryScopeId
            'Display Name'			= $role.Principal.AdditionalProperties.displayName
            'User Principal Name'	= $role.Principal.AdditionalProperties.userPrincipalName
            'Is Guest Account?'		= (&{if ($role.Principal.AdditionalProperties.userPrincipalName -match '#EXT#') {'True'} else {'False'}})
            'Assigned Type'			= $matches[3]
            'Assignment Type'		= (&{if ($role.AssignmentType -eq 'Assigned') {'Active'} else {'Eligible'}})
            'Is Built In'			= $role.roleDefinition.isBuiltIn
            'Created Date (UTC)'	= $role.CreatedDateTime
            'Expiration type'		= $role.ScheduleInfo.Expiration.type
            'Expiration Date (UTC)'	= switch ($role.ScheduleInfo.Expiration.EndDateTime) {
                {$role.ScheduleInfo.Expiration.EndDateTime -match '20'} {$role.ScheduleInfo.Expiration.EndDateTime}
                {$role.ScheduleInfo.Expiration.EndDateTime -notmatch '20'} {'N/A'}
            }
        } | Sort-Object 'Assigned Role'
        $privilegedUsers.Add($obj)
    }
    
    $privilegedUsers | Select-Object @{Name='Index';Expression={[array]::IndexOf($privilegedUsers, $_) + 1}}, *
}

# Function to hash tables of easy to read license display names from GUID or string
function Get-LicenseNames {
    $licenseGUID = @{}
    $licenseString = @{}
    $licenseFilePath = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
    [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $licenseFilePath).RawContentStream.ToArray()) | ConvertFrom-CSV `
        | Select-Object Product_Display_Name, String_Id, GUID -Unique `
        | ForEach-Object{
            $licenseGUID.Add($_.GUID, $_.Product_Display_Name)
            $licenseString.Add($_.String_Id, $_.Product_Display_Name)
        }
}

# Function to get user licenses
function Get-UserLicenses {
    Connect-MicrosoftGraph
    $licensedUsers = Get-MgUser -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All -Select UserPrincipalName,DisplayName,AssignedLicenses | Sort-Object DisplayName
    $users = foreach ($user in $licensedUsers) {
        [PSCustomObject]@{
            'UserPrincipalName' = $user.UserPrincipalName
            'DisplayName'       = $user.DisplayName
            'Licenses'          = $user.AssignedLicenses | ForEach-Object { $licenseGUID[$_.SkuId] }  # Use the hashtable to lookup license names
        }
    }
    $users | Select-Object @{Name='Index';Expression={[array]::IndexOf($users, $_) + 1}}, *
}

# Function to get a list of M365 licenses
function Get-M365LicenseSummary {
    try {
        Connect-MicrosoftGraph
        $tenantLicenses = Get-MgSubscribedSKU -All | Select-Object SkuPartNumber, SkuId, @{Name = 'ActiveUnits'; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits |
            ForEach-Object {
                [PSCustomObject]@{
                    'License'   = $licenseString.($_.SkuPartNumber)
                    'In Use'    = $_.ConsumedUnits
                    'Total'     = $_.ActiveUnits
                    'Available' = $_.ActiveUnits - $_.ConsumedUnits
                } 
            }
        $tenantLicenses | Select-Object @{Name='Index';Expression={[array]::IndexOf($tenantLicenses, $_) + 1}}, *
    } catch {
        Write-Error "Failed to retrieve licenses. $_"
    }
}


# Function to get a list of inactive users (no logins for the past 90 days)
function Get-InactiveUsers {
    Connect-MicrosoftGraph
    $date = (Get-Date).AddDays(-30).ToString("o")
    $inactiveUsers = Get-MgAuditLogSignIn -Filter "createdDateTime ge $date" | 
                     Group-Object -Property UserPrincipalName | 
                     Where-Object { $_.Count -eq 0 }
    $inactiveUsers | Select-Object @{Name='Index';Expression={[array]::IndexOf($inactiveUsers, $_) + 1}}, Name, Count
}

# Function to get activity logs
function Get-ActivityLogs {
    Connect-MicrosoftGraph
    $logs = Get-MgAuditLogSignIn -All
    $logs | Select-Object @{Name='Index';Expression={[array]::IndexOf($logs, $_) + 1}}, UserPrincipalName, AppDisplayName, ResourceDisplayName, CreatedDateTime
}

# Perform-Audit function
function Start-Audit {
    try {
        $users = Get-AllUsers
        $groups = Get-AllGroups
        $privilegedUsers = Get-PrivilegedUsers
        $userLicenses = Get-UserLicenses
        $tenantLicenses = Get-M365LicenseSummary
        $inactiveUsers = Get-InactiveUsers
        $activityLogs = Get-ActivityLogs

        $users | Out-GridView -Title 'All Users'
        $groups | Out-GridView -Title 'All Groups'
        $privilegedUsers | Out-GridView -Title 'Privileged Users'
        $userLicenses | Out-GridView -Title 'User Licenses'
        $tenantLicenses | Out-GridView -Title 'Tenant Licenses'
        $inactiveUsers | Out-GridView -Title 'Inactive Users'
        $activityLogs | Out-GridView -Title 'Activity Logs'
    } catch {
        Write-Error "An error occurred during the audit. $_"
    }
}

# Run the audit
Start-Audit