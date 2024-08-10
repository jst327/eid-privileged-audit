# Justin Tucker - 2024-08-10
# SPDX-FileCopyrightText: Copyright © 2024, Justin Tucker
# - https://github.com/jst327/m365-privileged-audit

# Requires Microsoft Graph API
# Requires PowerShell 5.1 or later
# Request .NET Framework 4.7.2 or later

# Ensure required modules are installed
#Install-Module Microsoft.Graph -Force -Scope CurrentUser

# Global variables to hold the license data
$licenseGUID = $null
$licenseString = $null

# Connect to Microsoft Graph
function Connect-MicrosoftGraph {
	try {
    	Connect-MgGraph -Scopes "AuditLog.Read.All", "GroupMember.Read.All", "Organization.Read.All", "RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.Directory", "RoleManagement.Read.All", "User.Read.All" -NoWelcome
	} catch {
		Write-Error "Failed to connect to Microsoft Graph. $_"
	}
}

# Function to get a list of all users, MFA, and SSPR status
function Get-AllUsers {
	try {
		Connect-MicrosoftGraph

		# Retrieve the MFA registration details for all users
		$mfaRegistrationDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All

		# Prepare an array to store the results
		$mfaReport = @()

		# Loop through each user's MFA registration details
		foreach ($mfaDetail in $mfaRegistrationDetails) {
    		# Retrieve the user's display name based on their user ID
    		$user = Get-MgUser -UserId $mfaDetail.Id

    		# Create a custom object with the desired properties
    		$mfaReport += [PSCustomObject]@{
		        'Display Name'				= $user.DisplayName
    	    	'User Principal Name'		= $user.UserPrincipalName
        		'Is Admin?'					= $mfaDetail.IsAdmin
				'Is MFA Capable?'			= $mfaDetail.IsMfaCapable
        		'Is MFA Registered?'		= $mfaDetail.IsMfaRegistered
        		'Is Passwordless Capable?'	= $mfaDetail.IsPasswordlessCapable
				'Is SSPR Capable?'			= $mfaDetail.IsSsprCapable
				'Is SSPR Enabled?'			= $mfaDetail.IsSsprEnabled
        		'Is SSPR Registered?'		= $mfaDetail.IsSsprRegistered
        		'Last Updated'				= $mfaDetail.LastUpdatedDateTime
    		}
		}
		$mfaReport | Select-Object @{Name='Index';Expression={[array]::IndexOf($mfaReport, $_) + 1}}, *
	} catch {
		Write-Error "Failed to retrieve users. $_"
	}
}

# Function to get a list of all groups
function Get-AllGroups {
	try {
    	Connect-MicrosoftGraph
    	$groups = Get-MgGroup -All | Sort-Object DisplayName
    	$groups | Select-Object @{Name='Index';Expression={[array]::IndexOf($groups, $_) + 1}}, DisplayName, Mail
	} catch {
		Write-Error "Failed to retrieve all groups. $_"
	}
}

# Function to get a list of privileged users
function Get-PrivilegedUsers {
	try {
		Connect-MicrosoftGraph
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
	} catch {
		Write-Error "Failed to retrieve privileged users. $_"
	}
}

# Function to hash tables of easy-to-read license display names from GUID or string
function Get-LicenseNames {
    try {
        $global:licenseGUID = @{}
        $global:licenseString = @{}
        $licenseFilePath = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
        [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $licenseFilePath).RawContentStream.ToArray()) | ConvertFrom-CSV `
            | Select-Object Product_Display_Name, String_Id, GUID -Unique `
            | ForEach-Object {
                $licenseGUID.Add($_.GUID, $_.Product_Display_Name)
                $licenseString.Add($_.String_Id, $_.Product_Display_Name)
            }
    } catch {
        Write-Error "Failed to retrieve license names. $_"
    }
}

# Function to ensure license names are loaded before continuing
function Confirm-LicenseNamesLoaded {
    if (-not $global:licenseGUID -or -not $global:licenseString) {
        Get-LicenseNames
    }
}

# Function to get user licenses
function Get-UserLicenses {
    Confirm-LicenseNamesLoaded

    try {
        Connect-MicrosoftGraph
        $licensedUsers = Get-MgUser -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All -Select UserPrincipalName,DisplayName,AssignedLicenses | Sort-Object DisplayName
        $users = foreach ($user in $licensedUsers) {
            [PSCustomObject]@{
                'UserPrincipalName' = $user.UserPrincipalName
                'DisplayName'       = $user.DisplayName
                'Licenses'          = $user.AssignedLicenses | ForEach-Object { $global:licenseGUID[$_.SkuId] }  # Use the hashtable to lookup license names
            }
        }
        $users | Select-Object @{Name='Index';Expression={[array]::IndexOf($users, $_) + 1}}, *
    } catch {
        Write-Error "Failed to retrieve user licenses. $_"
    }
}

# Function to get a list of M365 licenses
function Get-M365LicenseSummary {
    Confirm-LicenseNamesLoaded

    try {
        Connect-MicrosoftGraph
        $tenantLicenses = Get-MgSubscribedSKU -All | Select-Object SkuPartNumber, SkuId, @{Name = 'ActiveUnits'; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits |
            ForEach-Object {
                [PSCustomObject]@{
                    'License'   = $global:licenseString.($_.SkuPartNumber)
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

# Function to get a list of inactive users (no logins for the past 30 days)
function Get-InactiveUsers {
	Connect-MicrosoftGraph

    # Define the time span of inactivity (30 days)
    $inactiveThreshold = (Get-Date).AddDays(-30)

    # Get all users
    $users = Get-MgUser -All

    # Retrieve sign-in logs for the past 30 days in one go
    $signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $($inactiveThreshold.ToString('yyyy-MM-ddTHH:mm:ssZ'))" -Top 1000

    # Initialize an array to hold inactive users
    $inactiveUsers = @()

    # Create a hash table of the most recent sign-in for each user
    $userSignInMap = @{}
    foreach ($signIn in $signIns) {
        $userPrincipalName = $signIn.UserPrincipalName
        if ($userSignInMap[$userPrincipalName] -lt $signIn.CreatedDateTime) {
            $userSignInMap[$userPrincipalName] = $signIn.CreatedDateTime
        }
    }

    # Determine which users have not signed in within the last 30 days
    foreach ($user in $users) {
        $lastSignInDate = $null
        if ($userSignInMap.ContainsKey($user.UserPrincipalName)) {
            $lastSignInDate = $userSignInMap[$user.UserPrincipalName]
        }

        # If no sign-in or the last sign-in was more than 30 days ago, mark the user as inactive
        if (-not $lastSignInDate -or $lastSignInDate -lt $inactiveThreshold) {
            $inactiveUsers += [PSCustomObject]@{
                DisplayName       = $user.DisplayName
				UserPrincipalName = $user.UserPrincipalName
                LastSignInDate    = $lastSignInDate
            }
        }
    }

    # Output the inactive users
    return $inactiveUsers
}

# Function to get activity logs
function Get-ActivityLogs {
	try {
    	Connect-MicrosoftGraph
    	$logs = Get-MgAuditLogSignIn -All
    	$logs | Select-Object @{Name='Index';Expression={[array]::IndexOf($logs, $_) + 1}}, UserPrincipalName, AppDisplayName, ResourceDisplayName, CreatedDateTime
	} catch {
		Write-Error "Failed to retrieve activity logs. $_"
	}
}

# Perform-Audit function
function Start-Audit {
    try {
        $users = Get-AllUsers
        $groups = Get-AllGroups
        $privilegedUsers = Get-PrivilegedUsers
        $userLicenses = Get-UserLicenses
        $tenantLicenses = Get-M365LicenseSummary
        #$inactiveUsers = Get-InactiveUsers
        #$activityLogs = Get-ActivityLogs

        $users | Out-GridView -Title 'All Users'
        $groups | Out-GridView -Title 'All Groups'
        $privilegedUsers | Out-GridView -Title 'Privileged Users'
        $userLicenses | Out-GridView -Title 'User Licenses'
        $tenantLicenses | Out-GridView -Title 'Tenant Licenses'
        #$inactiveUsers | Out-GridView -Title 'Inactive Users'
        #$activityLogs | Out-GridView -Title 'Activity Logs'
    } catch {
        Write-Error "An error occurred during the audit. $_"
    }
}

# Run the audit
Start-Audit

# If running in the console, wait for input before closing.
if ($Host.Name -eq "ConsoleHost")
{
    Write-Host "Press any key to continue..."
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null
}