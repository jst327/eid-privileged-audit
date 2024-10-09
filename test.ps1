function Get-M365RoleAssignments {
    [CmdletBinding()]
    param(
        [string]$TenantId
    )

    # Connect to Microsoft Graph
    try {
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -NoWelcome
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph API."
        return
    }

    # Fetch all directory roles
    try {
        $roles = Get-MgDirectoryRole
        if (-not $roles) {
            Write-Host "No roles found in the tenant."
            return
        }
    }
    catch {
        Write-Error "Error fetching roles: $_"
        return
    }

    # Initialize an array to store role and member count
    $roleSummary = @()

    # Loop through each role to fetch its members and count
    foreach ($role in $roles) {
        try {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
            $count = $members.Count

            # Add role and count to the summary array
            $roleSummary += [pscustomobject]@{
                RoleName    = $role.DisplayName
                MemberCount = $count
            }
        }
        catch {
            Write-Warning "Error retrieving members for role $($role.DisplayName): $_"
        }
    }

    # Display the result in Out-GridView
    if ($roleSummary.Count -gt 0) {
        $roleSummary | Out-GridView -Title "Assigned Roles in Microsoft 365"
    }
    else {
        Write-Host "No roles with members found."
    }
}

# Example usage:
Get-M365RoleAssignments



Connect-MgGraph -Scopes "Directory.Read.All"

Connect-MgGraph -Scopes "RoleManagement.Read.Directory, Directory.Read.All"

$report = [System.Collections.Generic.List[Object]]::new()
$roles = Get-MgDirectoryRole

foreach ($role in $roles) {
    # Fetch assigned members
    $assignedMembers = @(Get-MgPrivilegedRoleRoleAssignment -RoleId $role.Id)

    # Fetch eligible members
    $eligibleMembers = @(Get-MgPrivilegedRoleEligibilityScheduleInstance -RoleId $role.Id)

    $assignedCount = $assignedMembers.Count
    $eligibleCount = $eligibleMembers.Count

    if ($assignedCount -gt 0 -or $eligibleCount -gt 0) {
        $obj = [PSCustomObject]@{
            'Role Name'         = $role.DisplayName
            'Assigned Members'  = $assignedCount
            'Eligible Members'  = $eligibleCount
        }
        $report.Add($obj)
    }
}

# Sort and add index column
$report = $report | Sort-Object 'Role Name'
$report = $report | Select-Object @{Name='Row#';Expression={[array]::IndexOf($report, $_) + 1}}, *

# Display results in Out-GridView
$report | Out-GridView







function Get-M365Roles {
    # Authenticate to Microsoft Graph
    $graphClient = New-Object Microsoft.Graph.GraphServiceClient -ArgumentList $accessToken

    # Retrieve all users
    $users = $graphClient.Users.GetAsync().GetAwaiter().GetResult()

    # Iterate through each user and retrieve their roles
    $allRoles = $users | ForEach-Object {
        $userId = $_.Id
        $assignedRoles = $graphClient.Users.$userId.DirectoryRoles.GetAsync().GetAwaiter().GetResult()
        $eligibleRoles = $graphClient.Users.$userId.TransitiveMemberOf.GetAsync().GetAwaiter().GetResult() | ForEach-Object {
            $groupId = $_.Id
            $groupRoles = $graphClient.Groups.$groupId.RoleDefinitions.GetAsync().GetAwaiter().GetResult()
            $groupRoles | Select-Object -ExpandProperty RoleName
        }

        # Combine results
        $userRoles = $assignedRoles | Select-Object -ExpandProperty RoleName | ForEach-Object {
            New-Object PSObject -Property @{
                UserId = $userId
                RoleType = "Assigned"
                RoleName = $_
            }
        } + $eligibleRoles | ForEach-Object {
            New-Object PSObject -Property @{
                UserId = $userId
                RoleType = "Eligible"
                RoleName = $_
            }
        }
        $userRoles
    }

    # Display results
    $allRoles | Out-GridView
}

Get-M365Roles








function Get-PrivilegedUsersReport {
    # Connect to Microsoft Graph (prompts for credentials)
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "User.Read.All"

    # Retrieve the list of role definitions (privileged roles)
    $rolesUrl = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
    $roleDefinitions = Invoke-MgGraphRequest -Uri $rolesUrl -Method Get

    $report = @()

    foreach ($role in $roleDefinitions.value) {
        # Retrieve assigned users for each role
        $assignedUrl = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?filter=roleDefinitionId eq '$($role.id)'"
        $assignedAssignments = Invoke-MgGraphRequest -Uri $assignedUrl -Method Get

        foreach ($assignment in $assignedAssignments.value) {
            # Attempt to resolve the display name from the user ID
            try {
                $user = Get-MgUser -UserId $assignment.principalId -ErrorAction Stop
                $report += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    UserName          = $user.DisplayName
                    RoleName          = $role.displayName
                    RoleType          = "Assigned"
                }
            } catch {
                # Handle case where user is not found
                $report += [PSCustomObject]@{
                    UserPrincipalName = $assignment.principalId
                    UserName          = "Not Found"
                    RoleName          = $role.displayName
                    RoleType          = "Assigned"
                }
            }
        }

        # Retrieve eligible users for each role
        $eligibleUrl = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?filter=roleDefinitionId eq '$($role.id)'"
        $eligibleAssignments = Invoke-MgGraphRequest -Uri $eligibleUrl -Method Get

        foreach ($eligibility in $eligibleAssignments.value) {
            # Attempt to resolve the display name from the user ID
            try {
                $user = Get-MgUser -UserId $eligibility.principalId -ErrorAction Stop
                $report += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    UserName          = $user.DisplayName
                    RoleName          = $role.displayName
                    RoleType          = "Eligible"
                }
            } catch {
                # Handle case where user is not found
                $report += [PSCustomObject]@{
                    UserPrincipalName = $eligibility.principalId
                    UserName          = "Not Found"
                    RoleName          = $role.displayName
                    RoleType          = "Eligible"
                }
            }
        }
    }

    # Display the report in Out-GridView
    $report | Out-GridView -Title "Privileged Users Report"
}

# Call the function to generate the report
Get-PrivilegedUsersReport


function Get-PrivilegedUsersReport {
    # Connect to Microsoft Graph (prompts for credentials)
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "User.Read.All"

    # Retrieve the list of role definitions (privileged roles) using Get-MgRoleManagementDirectoryRoleDefinition
    $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition

    $report = @()

    foreach ($role in $roleDefinitions) {
        # Retrieve assigned users for each role using Get-MgRoleManagementDirectoryRoleAssignmentSchedule
        $assignedAssignments = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -Filter "roleDefinitionId eq '$($role.id)'"

        foreach ($assignment in $assignedAssignments) {
            # Attempt to resolve the display name from the user ID
            try {
                $user = Get-MgUser -UserId $assignment.principalId -ErrorAction Stop
                $report += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    UserName          = $user.DisplayName
                    RoleName          = $role.displayName
                    RoleType          = "Assigned"
                }
            } catch {
                # Handle case where user is not found
                $report += [PSCustomObject]@{
                    UserPrincipalName = $assignment.principalId
                    UserName          = "Not Found"
                    RoleName          = $role.displayName
                    RoleType          = "Assigned"
                }
            }
        }

        # Retrieve eligible users for each role using Get-MgRoleManagementDirectoryRoleEligibilitySchedule
        $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '$($role.id)'"

        foreach ($eligibility in $eligibleAssignments) {
            # Attempt to resolve the display name from the user ID
            try {
                $user = Get-MgUser -UserId $eligibility.principalId -ErrorAction Stop
                $report += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    UserName          = $user.DisplayName
                    RoleName          = $role.displayName
                    RoleType          = "Eligible"
                }
            } catch {
                # Handle case where user is not found
                $report += [PSCustomObject]@{
                    UserPrincipalName = $eligibility.principalId
                    UserName          = "Not Found"
                    RoleName          = $role.displayName
                    RoleType          = "Eligible"
                }
            }
        }
    }

    # Display the report in Out-GridView
    $report | Out-GridView -Title "Privileged Users Report"
}

# Call the function to generate the report
Get-PrivilegedUsersReport

#$EligiblePIMRoles | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Eligible" -Force}
        #$AssignedPIMRoles | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Assigned" -Force}


<#
        foreach ($role in $PIMRoles) {
            $regex = "^([^.]+)\.([^.]+)\.(.+)$"
            $role.Principal.AdditionalProperties.'@odata.type' -match $regex | Out-Null
        
            if ($role.Principal.AdditionalProperties.ContainsKey('userPrincipalName')) {
                $userPrincipalName = $role.Principal.AdditionalProperties.userPrincipalName
            } else {
                $userPrincipalName = 'N/A'
                # Log an error or handle the missing data as needed
            }
        
            $obj = [PSCustomObject]@{
                'Assigned Role'         = $role.RoleDefinition.DisplayName
                'Assigned Role Scope'   = $role.directoryScopeId
                'Display Name'          = $role.Principal.AdditionalProperties.displayName
                'User Principal Name'   = $userPrincipalName
                'Is Guest Account?'     = (&{if ($userPrincipalName -match '#EXT#') {'True'} else {'False'}})
                'Assigned Type'         = $matches[3]
                'Assignment Type'       = (&{if ($role.AssignmentType -eq 'Assigned') {'Active'} else {'Eligible'}})
                'Is Built In'           = $role.roleDefinition.isBuiltIn
                'Created Date (UTC)'    = $role.CreatedDateTime
                'Expiration type'       = $role.ScheduleInfo.Expiration.type
                'Expiration Date (UTC)' = switch ($role.ScheduleInfo.Expiration.EndDateTime) {
                    {$role.ScheduleInfo.Expiration.EndDateTime -match '20'} {$role.ScheduleInfo.Expiration.EndDateTime}
                    {$role.ScheduleInfo.Expiration.EndDateTime -notmatch '20'} {'N/A'}
                }
            }
            $privilegedUsers.Add($obj)
        }#>




# Import the Microsoft Graph module
Import-Module Microsoft.Graph

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory" -NoWelcome

# Get all roles from Microsoft Entra
$roles = Get-MgRoleManagementDirectoryRole -Top 1000

# Initialize an array to hold users with assigned roles
$usersWithRoles = @()

# Loop through each role to get assigned users
foreach ($role in $roles) {
    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -RoleId $role.Id -Top 1000
    
    foreach ($assignment in $roleAssignments) {
        # Get user details for each assignment
        $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
        if ($user) {
            $usersWithRoles += [PSCustomObject]@{
                UserId       = $user.Id
                UserPrincipalName = $user.UserPrincipalName
                DisplayName  = $user.DisplayName
                RoleId       = $role.Id
                RoleName     = $role.DisplayName
            }
        }
    }
}

# Output the results
$usersWithRoles | Format-Table -AutoSize

