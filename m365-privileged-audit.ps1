# Justin Tucker - 2024-10-17
# SPDX-FileCopyrightText: Copyright © 2024, Justin Tucker
# https://github.com/jst327/m365-privileged-audit

# Requires PowerShell 5.1 or later
# Requires Microsoft Graph PowerShell Module
# Requires Exchange Online PowerShell Module

#### TO-DO
# 1. Privileged Group separate from priv users
# 2. Issues with duplicates in shared mailbox report

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$warnings = [System.Collections.ArrayList]::new()
$Global:WarningsAndErrors = [System.Collections.ArrayList]::new()
$Global:licenseGUID = @{}
$Global:licenseString = @{}

function Write-Log{
	[CmdletBinding()]
	param(
        [Parameter()]
		[ValidateNotNullOrEmpty()]
		[object]$Message,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE', IgnoreCase=$false)]
		[string]$Severity = 'INFO'
	)

	if($Severity -ceq 'TRACE'){
		$color = [ConsoleColor]::DarkGray
	}elseif($Severity -ceq 'DEBUG'){
		$color = [ConsoleColor]::Gray
	}elseif($Severity -ceq 'INFO'){
		$color = [ConsoleColor]::Cyan
	}elseif($Severity -ceq 'WARN'){
		$color = [ConsoleColor]::Yellow
		[void]$warnings.Add([PSCustomObject]@{
			Text = $Message
		})
	}elseif($Severity -ceq 'ERROR'){
		$color = [ConsoleColor]::Red
	}

	$msg = "$(Get-Date -f s) [$Severity] $Message"

	# - https://stackoverflow.com/questions/38523369/write-host-vs-write-information-in-powershell-5
	# - https://blog.kieranties.com/2018/03/26/write-information-with-colours
	Write-Information ([System.Management.Automation.HostInformationMessage]@{
		Message = $msg
		ForegroundColor = $color
	})
}

function Add-ToWarningsAndErrors {
    param (
        [string]$Type,
        [string]$Function,
        [string]$Message
    )
    $rowNumber = $Global:WarningsAndErrors.Count + 1
    $Global:WarningsAndErrors += [PSCustomObject]@{
        'Row#'      = $rowNumber
        'Type'      = $Type
        'Report'    = $Function
        'Message'   = $Message
    }
}

function Show-WarningsAndErrors {
    if (-not $Global:WarningsAndErrors) {
        $Global:WarningsAndErrors += [PSCustomObject]@{
            'Row#'      = 1
            'Type'      = 'Information'
            'Report'    = 'N/A'
			'Message'   = 'No warnings or errors to report.'
        }
    }
    $Global:WarningsAndErrors | Out-GridView -Title 'Warnings and Errors Report'
}

function Test-MicrosoftGraphModule {
    Write-Log 'Checking to see if Microsoft Graph Module is installed'
    $module = Get-Module -Name 'Microsoft.Graph' -ListAvailable

    if ($module) {
        Write-Log 'Microsoft Graph module is installed.'
    } else {
        Write-Log 'Microsoft Graph module is not installed.' -Severity ERROR
        Write-Log "Please install it using 'Install-Module -Name Microsoft.Graph'." -Severity ERROR
        Write-Log 'Press any key to exit the script.' -Severity ERROR
        $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp') > $null
        exit
    }
}

Test-MicrosoftGraphModule

function Test-ExchangeOnlineModule {
    Write-Log 'Checking to see if Exchange Online Module is installed'
    $module = Get-Module -Name 'ExchangeOnlineManagement' -ListAvailable

    if ($module) {
        Write-Log 'Exchange Online module is installed.'
    } else {
        Write-Log 'Exchange Online module is not installed.' -Severity ERROR
        Write-Log "Please install it using 'Install-Module -Name ExchangeOnlineManagement'." -Severity ERROR
        Write-Log 'Press any key to exit the script.' -Severity ERROR
        $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp') > $null
        exit
    }
}

Test-ExchangeOnlineModule

function Connect-MicrosoftGraph {
	try {
    	Connect-MgGraph -Scope RoleManagement.Read.Directory -NoWelcome
	} catch {
		Write-Log -Message 'Unable to connect to Microsoft Graph.' -Severity ERROR
	}
}

function Get-AllUsers {
    Write-Log "Starting 'All Users' report."
	Connect-MicrosoftGraph
    try {
		$userDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
		$allUsers = @()

		foreach ($userDetail in $userDetails) {
    		$user = Get-MgUser -UserId $userDetail.Id

    		$allUsers += [PSCustomObject]@{
		        'Display Name'			    = $user.DisplayName
    	    	'User Principal Name'	    = $user.UserPrincipalName
        		'Is Admin?'				    = $userDetail.IsAdmin
				'Is MFA Capable?'		    = $userDetail.IsMfaCapable
        		'Is MFA Registered?'	    = $userDetail.IsMfaRegistered
        		'Is Passwordless Capable?'  = $userDetail.IsPasswordlessCapable
				'Is SSPR Capable?'		    = $userDetail.IsSsprCapable
				'Is SSPR Enabled?'		    = $userDetail.IsSsprEnabled
        		'Is SSPR Registered?'	    = $userDetail.IsSsprRegistered
        		'Last Updated'			    = $userDetail.LastUpdatedDateTime
    		}
		}
        $allUsers | Select-Object @{Name='Row#';Expression={[array]::IndexOf($allUsers, $_) + 1}}, *
	} catch {
        Write-Log -Message "Error creating 'All Users report." -Severity ERROR
    }
}

function Get-PrivilegedUsers {
    Write-Log "Starting 'Privileged Users' report."
    Connect-MicrosoftGraph
    try {
        $assignedRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All
        $eligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All

        $privilegedUsers = [System.Collections.Generic.List[Object]]::new()

        foreach ($assignment in $assignedRoles) {
            try {
                $user = $null
                $servicePrincipal = $null

                if ($null -ne $assignment.PrincipalId) {
                    try {
                        $user = Get-MgUser -UserId $assignment.PrincipalId
                    } catch {
                        Write-Log -Message "Error retrieving user $($assignment.PrincipalId). Error: $_" -Severity DEBUG
                        try {
                            $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId
                        } catch {
                            Write-Log -Message "Error retrieving servicePrincipal for PrincipalId: $($assignment.PrincipalId). Error: $_" -Severity WARN
                            continue
                        }
                    }
                } else {
                    Write-Log -Message 'PrincipalId missing for assigned role.' -Severity WARN
                    continue
                }

                if ($null -ne $assignment.RoleDefinitionId) {
                    try {
                        $role = Get-MgRoleManagementDirectoryRoleDefinition -All | Where-Object { $_.Id -eq $assignment.RoleDefinitionId }
                    } catch {
                        Write-Log -Message "Error retrieving assigned role for RoleDefinitionId: $($assignment.RoleDefinitionId). Error: $_" -Severity WARN
                        continue
                    }
                } else {
                    Write-Log -Message 'RoleDefinitionId missing for assigned role.' -Severity WARN
                }

                if ($null -ne $assignment.DirectoryScopeId) {
                    try {
                        $cleanDirectoryScopeId = $assignment.DirectoryScopeId -replace '/administrativeUnits/', ''
                        $directoryScope = Get-MgDirectoryAdministrativeUnit -All | Where-Object { $_.Id -eq $cleanDirectoryScopeId }
                        $directoryScopeName = $directoryScope.DisplayName
                    } catch {
                        $directoryScopeName = '/'
                    }
                } else {
                    Write-Log -Message "Error retrieving directory scope name for DirectoryScopeId: $($cleanDirectoryScopeId). Error: $_" -Severity WARN
                }

                $isActivated = ($assignment.Status -eq 'Activated')

                if ($null -ne $user) {
                    $privilegedUsers += [PSCustomObject]@{
                        'RoleName'              = $role.DisplayName
                        'RoleType'              = 'Assigned'
                        'userPrincipalName'     = $user.UserPrincipalName
                        'DisplayName'           = $user.DisplayName
                        'DirectoryScope'        = $directoryScopeName
                        'IsGuest'               = if ($user.UserPrincipalName -match '#EXT#') {'True'} else {'False'}
                        'IsActivated'           = if ($null -ne $isActivated) {'True'} else {'False'}
                        'Created Date (UTC)'    = $assignment.CreatedDateTime
                        'Expiration type'       = $assignment.ScheduleInfo.Expiration.type
                        'Expiration Date (UTC)' = if ($assignment.ScheduleInfo.Expiration.EndDateTime -match '20') {
                            $assignment.ScheduleInfo.Expiration.EndDateTime
                        } else {
                            'N/A'
                        }
                    }
                } elseif ($null -ne $servicePrincipal) {
                    $privilegedUsers += [PSCustomObject]@{
                        'RoleName'              = $role.DisplayName
                        'RoleType'              = 'Assigned'
                        'userPrincipalName'     = 'Service Principal'
                        'DisplayName'           = $servicePrincipal.DisplayName
                        'DirectoryScope'        = $directoryScopeName
                        'IsGuest'               = 'False'
                        'IsActivated'           = if ($null -ne $isActivated) {'True'} else {'False'}
                        'Created Date (UTC)'    = $assignment.CreatedDateTime
                        'Expiration type'       = $assignment.ScheduleInfo.Expiration.type
                        'Expiration Date (UTC)' = if ($assignment.ScheduleInfo.Expiration.EndDateTime -match '20') {
                            $assignment.ScheduleInfo.Expiration.EndDateTime
                        } else {
                            'N/A'
                        }
                    }
                } else {
                    Write-Log -Message "Unknown object type for PrincipalId: $($assignment.PrincipalId)" -Severity WARN
                }

            } catch {
                Write-Log -Message "Error processing assigned role $($assignment.Id): $_" -Severity WARN
            }
        }

        foreach ($eligibility in $eligibleRoles) {
            try {
                if ($null -ne $eligibility.PrincipalId) {
                    try {
                        $user = Get-MgUser -UserId $eligibility.PrincipalId
                    } catch {
                        Write-Log -Message "Error retrieving user $($eligibility.PrincipalId). Error: $_" -Severity DEBUG
                        continue
                    }
                } else {
                    Write-Log -Message 'PrincipalId missing for eligible role.' -Severity WARN
                    continue
                }

                if ($null -ne $eligibility.RoleDefinitionId) {
                    try {
                        $role = Get-MgRoleManagementDirectoryRoleDefinition -All | Where-Object { $_.Id -eq $eligibility.RoleDefinitionId }
                    } catch {
                        Write-Log -Message "Error retrieving eligible role for RoleDefinitionId: $($eligibility.RoleDefinitionId). Error: $_" -Severity WARN
                        continue
                    }
                } else {
                    Write-Log -Message 'RoleDefinitionId missing for eligible role.' -Severity WARN
                }

                if ($null -ne $eligibility.DirectoryScopeId) {
                    try {
                        $cleanDirectoryScopeId = $eligibility.DirectoryScopeId -replace '/administrativeUnits/', ''
                        $directoryScope = Get-MgDirectoryAdministrativeUnit -All | Where-Object {$_.Id -eq $cleanDirectoryScopeId}
                        $directoryScopeName = $directoryScope.DisplayName
                    } catch {
                        $directoryScopeName = '/'
                    }
                } else {
                    Write-Log -Message "Error retrieving directory scope name for DirectoryScopeId: $($cleanDirectoryScopeId). Error: $_" -Severity WARN
                }

                $isActivated = $assignedRoles | Where-Object { $_.PrincipalId -eq $eligibility.PrincipalId -and $_.RoleDefinitionId -eq $eligibility.RoleDefinitionId }

                $privilegedUsers += [PSCustomObject]@{
                    'RoleName'              = $role.DisplayName
                    'RoleType'              = 'Eligible'
                    'userPrincipalName'     = $user.UserPrincipalName
                    'DisplayName'           = $user.DisplayName
                    'DirectoryScope'        = $directoryScopeName
                    'IsGuest'               = if ($null -ne $user -and $user.UserPrincipalName -match '#EXT#') { 'True' } else { 'False' }
                    'IsActivated'           = if ($null -ne $isActivated) {'True'} else {'False'}
                    'Created Date (UTC)'    = $eligibility.CreatedDateTime
                    'Expiration type'       = $eligibility.ScheduleInfo.Expiration.type
                    'Expiration Date (UTC)' = if ($eligibility.ScheduleInfo.Expiration.EndDateTime -match '20') {
                        $eligibility.ScheduleInfo.Expiration.EndDateTime
                    } else {
                        'N/A'
                    }
                }
            } catch {
                Write-Log -Message "Error processing eligible role: $_" -Severity WARN
            }
        }

        $privilegedUsers = $privilegedUsers | Sort-Object @{Expression={if ($_.RoleName -eq 'Global Administrator') {0} else {1}}}, RoleName
        $privilegedUsers | Select-Object @{Name='Row#';Expression={[array]::IndexOf($privilegedUsers, $_) + 1}}, *
    } catch {
        Write-Log -Message "$_ Error creating 'Privileged Users' report." -Severity ERROR
    }
}

function Get-PrivilegedGroups {
    Write-Log -Message "Starting 'Privileged Groups' report."
    Connect-MicrosoftGraph
    try {
        $roles = Get-MgDirectoryRole
        if (-not $roles) {
            Write-Log -Message 'No roles found in this tenant.' -Severity WARN
        }
    } catch {
        Write-Log -Message 'Error fetching roles.' -Severity ERROR
    }
    try {
        $roleCount = @{}
        foreach ($role in $roles) {
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
                $count = $members.Count
                $roleCount[$role.DisplayName] = $count
            } catch {
                Write-Log -Message "Error retrieving members for the role $($role.DisplayName): $_"
            }
        }

    } catch {
        Write-Log -Message "Error creating 'Privileged Groups' report." -Severity ERROR
    }
}

function Get-StaleUsers {
    Write-Log -Message "Starting 'Stale Users' report."
    Connect-MicrosoftGraph
    try {
        $staleUsers = [System.Collections.Generic.List[Object]]::new()
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
        $allUsers = Get-MgUser -All -Property $Properties | Select-Object $Properties
        foreach ($user in $allUsers) {
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
            $IsLicensed = if ($User.AssignedLicenses) {
                "Yes"
            } else {
                "No"
            }
            if (!$user.SignInActivity.LastSuccessfulSignInDateTime -or (Get-Date $user.SignInActivity.LastSuccessfulSignInDateTime)) {
                if ($DaysSinceLastSignIn -ge 30) {
                    $obj = [PSCustomObject]@{
                        'DisplayName'               = $User.DisplayName
                        'UserPrincipalName'         = $User.UserPrincipalName
                        'CreatedDateTime'           = $User.CreatedDateTime
                        'LastSuccessfulSignInDate'  = $LastSuccessfulSignInDate
                        'DaysSinceLastSignIn'       = $DaysSinceLastSignIn
                        'AccountEnabled'            = $User.AccountEnabled
                        'IsLicensed'                = $IsLicensed
                        'UserType'                  = $User.UserType
                    }
                    $staleUsers.Add($obj)
                }
            }
        }

        if ($staleUsers.Count -gt 0) {
            Write-Log -Message 'Stale users found.' -Severity WARN
            Add-ToWarningsAndErrors -Type 'Warning' -Message 'Stale users found.' -Function 'Stale Users'
        } else {
            Write-Log -Message 'No stale users found.' -Severity INFO
        }
        $staleUsers = $staleUsers | Sort-Object -Property DaysSinceLastSignIn -Descending
        $staleUsers | Select-Object @{Name='Row#';Expression={[array]::IndexOf($staleUsers, $_) + 1}}, *
    } catch {
        Write-Log -Message "Error creating 'Stale Users' report." -Severity ERROR
    }
}

function Get-LicenseNames {
    try {
        $licenseFilePath = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
        [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $licenseFilePath).RawContentStream.ToArray()) | ConvertFrom-CSV `
            | Select-Object Product_Display_Name, String_Id, GUID -Unique `
            | ForEach-Object {
                if (-not $licenseGUID.ContainsKey($_.GUID)) {
                    $licenseGUID.Add($_.GUID, $_.Product_Display_Name)
                }
                if (-not $licenseString.ContainsKey($_.String_Id)) {
                    $licenseString.Add($_.String_Id, $_.Product_Display_Name)
                }
            }
    } catch {
        Write-Log -Message 'Error retrieiving license names.' -Severity ERROR
    }
}

function Get-UserLicenses {
    Write-Log "Starting 'User Licenses' report."
    Connect-MicrosoftGraph
    Get-LicenseNames
    try {
        $licensedUsers = [System.Collections.Generic.List[Object]]::new()
        $users = Get-MgUser -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All -Select UserPrincipalName,DisplayName,AssignedLicenses | Sort-Object DisplayName
        foreach ($user in $users) {
            $obj = [PSCustomObject]@{
                'UserPrincipalName' = $user.UserPrincipalName
                'DisplayName'       = $user.DisplayName
                'Licenses'          = $user.AssignedLicenses | ForEach-Object { $Global:licenseGUID[$_.SkuId] }
            }
            $licensedUsers.Add($obj)
        }
        $licensedUsers | Select-Object @{Name='Row#';Expression={[array]::IndexOf($licensedUsers, $_) + 1}}, *
    } catch {
        Write-Log -Message "Error creating 'User Licenses' report." -Severity ERROR
    }
}

function Get-TenantLicenses {
    Write-Log "Starting 'Tenant Licenses' report."
    Connect-MicrosoftGraph
    Get-LicenseNames
    try {
        $tenantLicenses = Get-MgSubscribedSKU -All | Select-Object SkuPartNumber, SkuId, @{Name = 'ActiveUnits'; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits |
        ForEach-Object {
            [PSCustomObject]@{
                'License' = $Global:licenseString.($_.SkuPartNumber)
                'In Use' = $_.ConsumedUnits
                'Total' = $_.ActiveUnits
                'Available' = $_.ActiveUnits - $_.ConsumedUnits
            }
        }
        $tenantLicenses | Select-Object @{Name='Row#';Expression={[array]::IndexOf($tenantLicenses, $_) + 1}}, *
    } catch {
        Write-Log -Message "Error creating 'Tenant Licenses' report."
    }
}

function Connect-ToExchangeOnline {
    try {
        Connect-ExchangeOnline -ShowProgress $false
    } catch {
        Write-Log -Message 'Error connecting to Exchange Online' -Severity ERROR
        Add-ToWarningsAndErrors -Type Error -Message 'Error connecting to Exchange Online' -Function 'Connect to Exchange Online'
    }
}

function Test-AuditStatus {
    Write-Log "Starting 'Audit Status' report."
    Connect-ToExchangeOnline
    try {
        $auditConfig = Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
        if ($auditConfig -match 'True') {
            Write-Log -Message 'Auditing is enabled for your tenant.' -Severity INFO
        } else {
            Write-Log -Message 'Auditing is not enabled for your tenant.' -Severity WARN
            Add-ToWarningsAndErrors -Type 'Warning' -Message 'Auditing is not enabled for your tenant.' -Function 'Audit Status'
        }
    } catch {
        Write-Log -Message "Error running 'Test-AuditStatus' report." -Severity ERROR
    }
}

function Test-SharedMailboxSignInAllowed {
    Write-Log -Message "Starting 'Shared Mailbox Sign-In Allowed' report."
    try {
        $mailboxStatusList = [System.Collections.Generic.List[Object]]::new()
        $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox | Select-Object Name, UserPrincipalName
        $accountEnabled = Get-MgUser -Filter 'accountEnabled eq true' -Select UserPrincipalName
        $accountDisabled = Get-MgUser -Filter 'accountEnabled eq false' -Select UserPrincipalName
        foreach ($mailbox in $sharedMailboxes) {
            $isEnabled = $accountEnabled.UserPrincipalName -contains $mailbox.UserPrincipalName
            $isDisabled = $accountDisabled.UserPrincipalName -contains $mailbox.UserPrincipalName
            $status = if ($isEnabled) {
                'Enabled'
            } elseif ($isDisabled) {
                'Disabled'
            } else {
                'Unknown'
            }
            if ($isEnabled) {
                $obj = [PSCustomObject]@{
                    'Name' = $mailbox.Name
                    'userPrincipalName' = $mailbox.UserPrincipalName
                    'AccountStatus' = $status
                }
                Write-Log -Message "The shared mailbox account for '$($mailbox.UserPrincipalName)' is enabled." -Severity WARN
                Add-ToWarningsAndErrors -Type 'Warning' -Message "The shared mailbox account for '$($mailbox.UserPrincipalName)' is enabled." -Function 'Shared Mailbox Sign-In Allowed'
            }
            $mailboxStatusList.Add($obj)
        }
        $mailboxStatusList = $mailboxStatusList | Sort-Object 'Name'
        $mailboxStatusList | Select-Object @{Name='Row#';Expression={[array]::IndexOf($mailboxStatusList, $_) + 1}}, *
    } catch {
        Write-Log -Message "Error running 'Shared Mailbox Sign-In Allowed' report." -Severity ERROR
    }
}

function Start-Audit {
    $allUsers = Get-AllUsers
    $privUsers = Get-PrivilegedUsers
    $privGroups = Get-PrivilegedGroups
    $staleUsers = Get-StaleUsers
    $licensedUsers = Get-UserLicenses
    $tenantLicenses = Get-TenantLicenses
    $auditStatus = Test-AuditStatus
    $sharedMailbox = Test-SharedMailboxSignInAllowed

    $allUsers | Out-GridView -Title 'All Users'
    $privUsers | Out-GridView -Title 'Privileged Users'
    $privGroups | Out-GridView -Title 'Privileged Groups'
    $staleUsers | Out-GridView -Title 'Stale Users'
    $licensedUsers | Out-GridView -Title 'User Licenses'
    $tenantLicenses | Out-GridView -Title 'Tenant Licenses'
    $auditStatus
    $sharedMailbox | Out-GridView -Title 'Shared Mailbox Sign-In Allowed'
}

Start-Audit

Show-WarningsAndErrors

Write-Log -Message 'Script finished!' -Severity INFO

if ($Host.Name -eq 'ConsoleHost')
{
    Write-Log 'Press any key to continuee...'
    $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp') > $null
}