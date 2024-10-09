# Justin Tucker - 2024-09-30
# SPDX-FileCopyrightText: Copyright © 2024, Justin Tucker
# - https://github.com/jst327/m365-privileged-audit

# Requires Microsoft Graph PowerShell Module
# Requires Exchange Online PowerShell Module
# Requires PowerShell 5.1 or later
# Request .NET Framework 4.7.2 or later

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

# Function for writing logs
function Write-Log {
    param(
        [string]$Message,
        [string]$LogLevel = 'INFO',
        [switch]$Verbose
    )

    $colors = @{
        TRACE = 'DarkGray'
        DEBUG = 'Gray'
        INFO = 'Cyan'
        WARN = 'Yellow'
        ERROR = 'Red'
    }

    if ($Verbose) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    } else {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }

    $logEntry = "$timestamp [$LogLevel] $Message"

    Write-Host $logEntry -ForegroundColor $colors[$LogLevel]
}

# Function to check if Microsoft Graph module is installed
function Test-MicrosoftGraphModule {
    # Check if Microsoft.Graph module is installed
    Write-Log 'Checking to see if Microsoft Graph Module is installed'
    $module = Get-Module -Name 'Microsoft.Graph' -ListAvailable

    if ($module) {
        Write-Log 'Microsoft Graph module is installed.'
    } else {
        # Output an error and prompt user to press any key to exit script
        Write-Log 'Microsoft Graph module is not installed.' -LogLevel ERROR
        Write-Log "Please install it using 'Install-Module -Name Microsoft.Graph'." -LogLevel ERROR
        Write-Log 'Press any key to exit the script.' -LogLevel ERROR
        $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp') > $null
        exit
    }
}

# Run module test
Test-MicrosoftGraphModule

# Continue with other script tasks if the module is found
Write-Log 'Continuing with rest of the script...' -LogLevel TRACE

# Function to check if Exchange Online module is installed
function Test-ExchangeOnlineModule {
    # Check if Exchange Online module is installed
    Write-Log 'Checking to see if Exchange Online Module is installed'
    $module = Get-Module -Name 'ExchangeOnlineManagement' -ListAvailable

    if ($module) {
        Write-Log 'Exchange Online module is installed.'
    } else {
        # Output an error and prompt user to press any key to exit script
        Write-Log 'Exchange Online module is not installed.' -LogLevel ERROR
        Write-Log "Please install it using 'Install-Module -Name ExchangeOnlineManagement'." -LogLevel ERROR
        Write-Log 'Press any key to exit the script.' -LogLevel ERROR
        $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp') > $null
        exit
    }
}

# Run module test
Test-ExchangeOnlineModule

# Continue with other script tasks if the module is found
Write-Log 'Continuing with rest of the script...' -LogLevel TRACE

# Global array to store informational events
$Global:Information = @()
$global:LASTWARNING = @()
$global:licenseGUID = @()
$global:licenseString = @()

# Function to log informational events
function Add-ToInformation {
    param (
        [string]$Type,
        [string]$Function,
        [string]$Message
    )

    # Calculate the next index based on the current array length
    $rowNumber = $Global:Information.Count + 1

    # Add the new entry to the global array with an index
    $Global:Information += [PSCustomObject]@{
        'Row#'      = $rowNumber
        'Type'      = $Type
        'Function'  = $Function
        'Message'   = $Message
    }
}

# Function to show informational events
function Show-Information {
    if (-not $Global:Information) {
        # If no warnings or errors exist, add a placeholder entry
        $Global:Information += [PSCustomObject]@{
            'Row#'      = 1
            'Type'      = 'Information'
            'Function'  = 'N/A'
			'Message'   = 'No information to report.'
        }
    }

    $Global:Information | Out-GridView -Title 'Information Report'
}

# Global array to store the warnings and errors
$Global:WarningsAndErrors = @()

# Function to log warnings and errors
function Add-ToWarningsAndErrors {
    param (
        [string]$Type,
        [string]$Function,
        [string]$Message        
    )

    # Calculate the next index based on the current array length
    $rowNumber = $Global:WarningsAndErrors.Count + 1

    # Add the new entry to the global array with an index
    $Global:WarningsAndErrors += [PSCustomObject]@{
        'Row#'      = $rowNumber
        'Type'      = $Type
        'Function'  = $Function
        'Message'   = $Message
    }
}

# Function to show the collected warnings and errors
function Show-WarningsAndErrors {
    if (-not $Global:WarningsAndErrors) {
        # If no warnings or errors exist, add a placeholder entry
        $Global:WarningsAndErrors += [PSCustomObject]@{
            'Row#'      = 1
            'Type'      = 'Information'
            'Function'  = 'N/A'
			'Message'   = 'No warnings or errors to report.'
        }
    }

    $Global:WarningsAndErrors | Out-GridView -Title 'Warnings and Errors Report'
}

# Connect to Microsoft Graph
function Connect-ToMicrosoftGraph {
    # Redirect warnings and errors to variables
    $ErrorActionPreference = 'Stop'
    $WarningPreference = 'Continue'

	try {
    	Connect-MgGraph -Scopes 'AuditLog.Read.All', 'GroupMember.Read.All', 'Organization.Read.All', 'Policy.Read.All', 'RoleEligibilitySchedule.Read.Directory', 'RoleManagement.Read.Directory', 'RoleManagement.Read.All', 'User.Read.All' -NoWelcome
	} catch {
		Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
	}
    $lastWarning = $null
    $lastWarning = $global:LASTWARNING
    if ($lastWarning) {
        Add-ToWarningsAndErrors -Type 'Warning' -Message $lastWarning.Message -Function $lastWarning.InvocationInfo.MyCommand.Name
    }
}

# Connect to Exchange Online
function Connect-ToExchangeOnline {
    # Redirect warnings and errors to variables
    $ErrorActionPreference = 'Stop'
    $WarningPreference = 'Continue'

    try {
        Connect-ExchangeOnline -ShowProgress $false
    } catch {
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
    }
    $lastWarning = $null
    $lastWarning = $global:LASTWARNING
    if ($lastWarning) {
        Add-ToWarningsAndErrors -Type 'Warning' -Message $lastWarning.Message -Function $lastWarning.InvocationInfo.MyCommand.Name
    }
}

# Function to get a list of all users, MFA, and SSPR status
function Get-AllUsers {
    Write-Log "Starting 'All Users' report."
	
    try {
		Connect-ToMicrosoftGraph

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
		$mfaReport | Select-Object @{Name='Row#';Expression={[array]::IndexOf($mfaReport, $_) + 1}}, *
	} catch {
		Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
	}
	$lastWarning = $null
    $lastWarning = $global:LASTWARNING
    if ($lastWarning) {
        Add-ToWarningsAndErrors -Type 'Warning' -Message $lastWarning.Message -Function $lastWarning.InvocationInfo.MyCommand.Name
    }
}

# Function to get a list of privileged users
function Get-PrivilegedUsers {
    Write-Log "Starting 'Privileged Users' report."

    try {
        Connect-ToMicrosoftGraph
        $EligiblePIMRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty *
        $AssignedPIMRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty *
        $PIMRoles = $EligiblePIMRoles + $AssignedPIMRoles
        $privilegedUsers = [System.Collections.Generic.List[Object]]::new()
    
        foreach ($role in $PIMRoles) {
            $regex = "^([^.]+)\.([^.]+)\.(.+)$"
            $role.Principal.AdditionalProperties.'@odata.type' -match $regex | out-null
            $obj = [pscustomobject][ordered]@{
                'Assigned Role'         = $role.RoleDefinition.DisplayName
                'Assigned Role Scope'   = $role.directoryScopeId
                'Display Name'          = $role.Principal.AdditionalProperties.displayName
                'User Principal Name'   = $role.Principal.AdditionalProperties.userPrincipalName
                'Is Guest Account?'     = (&{if ($role.Principal.AdditionalProperties.userPrincipalName -match '#EXT#') {'True'} else {'False'}})
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
        }
    
        # Sort the entire collection by 'Assigned Role'
        $privilegedUsers = $privilegedUsers | Sort-Object 'Assigned Role'
    
        # Output the sorted results with a row column
        $privilegedUsers | Select-Object @{Name='Row#';Expression={[array]::IndexOf($privilegedUsers, $_) + 1}}, *
    } catch {
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand
    }
    $lastWarning = $null
    $lastWarning = $global:LASTWARNING
    if ($lastWarning) {
        Add-ToWarningsAndErrors -Type 'Warning' -Message $lastWarning.Message -Function $lastWarning.InvocationInfo.MyCommand.Name
    }
}

# Function to hash tables of easy-to-read license display names from GUID or string
function Get-LicenseNames {

    try {

        $licenseFilePath = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
        [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $licenseFilePath).RawContentStream.ToArray()) | ConvertFrom-CSV `
            | Select-Object Product_Display_Name, String_Id, GUID -Unique `
            | ForEach-Object {
                $licenseGUID.Add($_.GUID, $_.Product_Display_Name)
                $licenseString.Add($_.String_Id, $_.Product_Display_Name)
            }
    } catch {
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
    }
	$lastWarning = $null
    $lastWarning = $global:LASTWARNING
    if ($lastWarning) {
        Add-ToWarningsAndErrors -Type 'Warning' -Message $lastWarning.Message -Function $lastWarning.InvocationInfo.MyCommand.Name
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
    Write-Log "Starting 'User Licenses' report."

    Confirm-LicenseNamesLoaded

    try {
        Connect-ToMicrosoftGraph
        $licensedUsers = Get-MgUser -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All -Select UserPrincipalName,DisplayName,AssignedLicenses | Sort-Object DisplayName
        $users = foreach ($user in $licensedUsers) {
            [PSCustomObject]@{
                'UserPrincipalName' = $user.UserPrincipalName
                'DisplayName'       = $user.DisplayName
                'Licenses'          = $user.AssignedLicenses | ForEach-Object { $global:licenseGUID[$_.SkuId] }  # Use the hashtable to lookup license names
            }
        }
        
        # Output the sorted results with a row column
        $users | Select-Object @{Name='Row#';Expression={[array]::IndexOf($users, $_) + 1}}, *
    } catch {
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
    }
	$lastWarning = $null
    $lastWarning = $global:LASTWARNING
    if ($lastWarning) {
        Add-ToWarningsAndErrors -Type 'Warning' -Message $lastWarning.Message -Function $lastWarning.InvocationInfo.MyCommand.Name
    }
}

# Function to get a list of M365 licenses
function Get-LicenseSummary {
    Write-Log "Starting 'Tenant Licenses' report."

    Confirm-LicenseNamesLoaded

    try {
        Connect-ToMicrosoftGraph
        $tenantLicenses = Get-MgSubscribedSKU -All | Select-Object SkuPartNumber, SkuId, @{Name = 'ActiveUnits'; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits |
            ForEach-Object {
                [PSCustomObject]@{
                    'License'   = $global:licenseString.($_.SkuPartNumber)
                    'In Use'    = $_.ConsumedUnits
                    'Total'     = $_.ActiveUnits
                    'Available' = $_.ActiveUnits - $_.ConsumedUnits
                } 
            }

        # Sort the entire collection by 'Assigned Role'
        $tenantLicenses = $tenantLicenses | Sort-Object 'License'

        # Output the sorted results with a row column
        $tenantLicenses | Select-Object @{Name='Row#';Expression={[array]::IndexOf($tenantLicenses, $_) + 1}}, *
    } catch {
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
    }
	$lastWarning = $null
    $lastWarning = $global:LASTWARNING
    if ($lastWarning) {
        Add-ToWarningsAndErrors -Type 'Warning' -Message $lastWarning.Message -Function $lastWarning.InvocationInfo.MyCommand.Name
    }
}

function Get-StaleUsers {
    try {
        Connect-ToMicrosoftGraph
        # Initialize a List to store the data
        $Report = [System.Collections.Generic.List[Object]]::new()

        # Get properties
        $Properties = @(
            'DisplayName',
            'Mail',
            'UserPrincipalName',
            'UserType',
            'AccountEnabled',
            'SignInActivity',
            'CreatedDateTime',
            'AssignedLicenses'
        )

        # Get all users along with the properties
        $AllUsers = Get-MgUser -All -Property $Properties | Select-Object $Properties

        foreach ($User in $AllUsers) {
            $LastSuccessfulSignInDate = if ($User.SignInActivity.LastSuccessfulSignInDateTime) {
                $User.SignInActivity.LastSuccessfulSignInDateTime
            } else {
                "Never Signed-in."
            }

            $DaysSinceLastSignIn = if ($User.SignInActivity.LastSuccessfulSignInDateTime) {
                (New-TimeSpan -Start $User.SignInActivity.LastSuccessfulSignInDateTime -End (Get-Date)).Days
            } else {
                "N/A"
            }

            # Check if the user is licensed
            $IsLicensed = if ($User.AssignedLicenses) {
                "Yes"
            } else {
                "No"
            }

            # Collect data and add to report only if DaysSinceLastSignIn is greater than or equal to 30
            if (!$User.SignInActivity.LastSuccessfulSignInDateTime -or (Get-Date $User.SignInActivity.LastSuccessfulSignInDateTime)) {
                if ($DaysSinceLastSignIn -ge 30) {
                    $ReportLine = [PSCustomObject]@{
                        DisplayName                 = $User.DisplayName
                        UserPrincipalName           = $User.UserPrincipalName                                  
                        CreatedDateTime             = $User.CreatedDateTime
                        LastSuccessfulSignInDate    = $LastSuccessfulSignInDate
                        DaysSinceLastSignIn         = $DaysSinceLastSignIn
                        AccountEnabled              = $User.AccountEnabled
                        IsLicensed                  = $IsLicensed
                        UserType                    = $User.UserType
                    }
                    # Add the report line to the List
                    $Report.Add($ReportLine)
                    Add-ToWarningsAndErrors -Type 'Warning' -Message 'Stale users found.'
                } else {
                    Add-ToInformation -Type 'Info' -Message 'No stale users found.'
                }
            }
        }
        # Display data by DaysSinceLastSignIn Descending
        $Report = $Report | Sort-Object -Property DaysSinceLastSignIn -Descending
        # Output the sorted results with a row column
        $Report | Select-Object @{Name='Row#';Expression={[array]::IndexOf($Report, $_) + 1}}, *
    } catch{
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
    }

}

# Function to get activity logs
function Get-ActivityLogs {
    Write-Log "Starting 'Activity Logs' report."
	# Redirect warnings and errors to variables
	$ErrorActionPreference = 'Stop'
	$WarningPreference = 'Continue'

	try {
    	Connect-ToMicrosoftGraph
    	$logs = Get-MgAuditLogSignIn -All
        # Output the sorted results with a row column
    	$logs | Select-Object @{Name='Row#';Expression={[array]::IndexOf($logs, $_) + 1}}, UserPrincipalName, AppDisplayName, ResourceDisplayName, CreatedDateTime
	} catch {
		Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $_.InvocationInfo.MyCommand.Name
	}
}

# Function to see if security defaults are enabled
function Test-SecurityDefaults {

}

# Function to see if audting is enabled for tenant
function Test-AuditStatus {  
    Write-Log "Starting 'Audit Status' report."
	# Redirect warnings and errors to variables
	$ErrorActionPreference = 'Stop'
	$WarningPreference = 'Continue'

    try {
        Write-Log 'Connecting to Exchange Online'
        Connect-ToExchangeOnline
        # Get the audit log configuration
        $auditConfig = Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled

        if ($auditConfig.UnifiedAuditLogIngestionEnabled -match 'True') {
            Add-ToInformation -Type 'Information' -Message 'Auditing is enabled in your tenant.' -Function $MyInvocation.MyCommand.Name
        } else {
            Add-ToWarningsAndErrors -Type 'Warning' -Message 'Auditing is not enabled in your tenant.' -Function $MyInvocation.MyCommand.Name
        }

    } catch {
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $MyInvocation.MyCommand.Name
        Write-Log $_.Exception.Message -LogLevel ERROR
    }
}

# Function to check if shared mailboxes are allowed to sign in
# https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-mailbox?view=o365-worldwide#block-sign-in-for-the-shared-mailbox-account
function Test-SharedMailboxSignInAllowed {
    Write-Log "Starting 'Shared Mailbox Sign-In Allowed' report."
    # Redirect warnings and errors to variables
    $ErrorActionPreference = 'Stop'
    $WarningPreference = 'Continue'

    try {
        # Get all shared mailboxes
        $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox | Select-Object Name, UserPrincipalName

        # Get enabled and disabled accounts
        $accountEnabled = Get-MgUser -Filter 'accountEnabled eq true' -Select UserPrincipalName
        $accountDisabled = Get-MgUser -Filter 'accountEnabled eq false' -Select UserPrincipalName

        # Create a list to store the custom objects (initialize as an array)
        $mailboxStatusList = @()

        # Loop through each shared mailbox
        foreach ($mailbox in $sharedMailboxes) {
            # Check if the mailbox is in the enabled or disabled list
            $isEnabled = $accountEnabled.UserPrincipalName -contains $mailbox.UserPrincipalName
            $isDisabled = $accountDisabled.UserPrincipalName -contains $mailbox.UserPrincipalName

            # Determine the account status
            $status = if ($isEnabled) { 
                "Enabled" 
            } elseif ($isDisabled) { 
                "Disabled" 
            } else { 
                "Unknown" 
            }

            # If the account is enabled, output a warning message
            if ($isEnabled) {
                Write-Log "The shared mailbox account for '$($mailbox.UserPrincipalName)' is enabled." -LogLevel WARN
                Add-ToWarningsAndErrors -Type 'Warning' -Message "The shared mailbox account for '$($mailbox.UserPrincipalName)' is enabled." -Function $MyInvocation.MyCommand.Name
            }

            # Create a custom object with the desired properties
            $mailboxStatus = [PSCustomObject]@{
                Name              = $mailbox.Name
                UserPrincipalName = $mailbox.UserPrincipalName
                AccountStatus     = $status
            }

            # Add the custom object to the list
            $mailboxStatusList += $mailboxStatus
        }

        # Sort the entire collection by 'Name'
        $mailboxStatusList = $mailboxStatusList | Sort-Object 'Name'
    
        # Output the sorted results with a row column
        $mailboxStatusList | Select-Object @{Name='Row#';Expression={[array]::IndexOf($mailboxStatusList, $_) + 1}}, *

    } catch {
        Add-ToWarningsAndErrors -Type 'Error' -Message $_.Exception.Message -Function $MyInvocation.MyCommand.Name
        Write-Log $_.Exception.Message -LogLevel ERROR
    }
}

# Perform-Audit function
function Start-Audit {
    try {
        Write-Log 'Starting audit...'
        $users = Get-AllUsers #in new script
        $privilegedUsers = Get-PrivilegedUsers #in new script
        $userLicenses = Get-UserLicenses #in new script
        $tenantLicenses = Get-LicenseSummary #in new script
        $staleUsers = Get-StaleUsers #in new script
        #$activityLogs = Get-ActivityLogs
		$auditStatus = Test-AuditStatus
		$sharedMailbox = Test-SharedMailboxSignInAllowed

        $users | Out-GridView -Title 'All Users'
        $privilegedUsers | Out-GridView -Title 'Privileged Users'
        $userLicenses | Out-GridView -Title 'User Licenses'
        $tenantLicenses | Out-GridView -Title 'Tenant Licenses'
        $staleUsers | Out-GridView -Title 'Stale Users'
        #$activityLogs | Out-GridView -Title 'Activity Logs'
		$auditStatus
		$sharedMailbox | Out-GridView -Title 'Shared Mailbox Sign-In'
    } catch {
        Write-Log "An error occurred during the audit. $_" -LogLevel ERROR
    }
}

# Run the audit
Start-Audit

# Show informational report
Show-Information

# Show warnings and errors report
Show-WarningsAndErrors

Write-Log 'Script finished!'

# If running in the console, wait for input before closing.
if ($Host.Name -eq 'ConsoleHost')
{
    Write-Log 'Press any key to continue...'
    $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp') > $null
}