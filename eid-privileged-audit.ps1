# Justin Tucker - 2025-01-01, 2025-09-13
# SPDX-FileCopyrightText: Copyright © 2025, Justin Tucker
# https://github.com/jst327/eid-privileged-audit

Param(
	[string]$server = $null,
	[switch]$batch,
	[IO.FileInfo]$reportsFolder = $null,
	[switch]$noFiles,
	[switch]$noZip,
	[switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$version = '2025-09-13'
$warnings = [System.Collections.ArrayList]::new()
$EIDConnectParams = @{}

$Global:WarningsAndErrors = [System.Collections.ArrayList]::new()
$Global:licenseGUID = @{}
$Global:licenseString = @{}
$Global:EIDPropsCache = @{
	Users = $null
	Devices = $null
	Groups = $null
	NamedLocations = $null
	RoleDefinitions = $null
	ServicePrincipals = $null
	SubscribedSKUs = $null
	DefaultUserRolePermissions = $null
}

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

Write-Log 'Checking for required PowerShell version...'

if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
	Write-Log 'This script requires PowerShell version 5.1 or later.' -Severity ERROR
	Write-Host "Press Enter to exit..."
	do {
		$key = [System.Console]::ReadKey($true)
	} until ($key.Key -eq 'Enter')
	exit 1
}

Write-Log "PowerShell version: $($PSVersionTable.PSVersion)"

function Test-ModuleInstalled {
	param (
		[string]$ModuleName
	)
	Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue | ForEach-Object {
		return $true
	}
	return $false
}

$requiredModules = @(
	'Microsoft.Graph.Applications',
	'Microsoft.Graph.Authentication',
	'Microsoft.Graph.Groups',
	'Microsoft.Graph.Identity.DirectoryManagement',
	'Microsoft.Graph.Identity.Governance',
	'Microsoft.Graph.Identity.SignIns',
	'Microsoft.Graph.Reports',
	'Microsoft.Graph.Users',
	'Microsoft.Graph.Beta.Identity.SignIns'
	#'ExchangeOnlineManagement'
)
$missingModules = @()

foreach ($module in $requiredModules) {
	if (-not (Test-ModuleInstalled -ModuleName $module)) {
		$missingModules += $module
	}
}

Write-Log 'Checking for required PowerShell modules...'

if ($missingModules.Count -gt 0) {
	foreach ($module in $missingModules) {
		Write-Log "Required module not installed: $module" -Severity ERROR
		Write-Log 'You may install them using the follow command:' -Severity DEBUG
		Write-Log "    Install-Module $module -Scope CurrentUser" -Severity DEBUG
	}
	Write-Host "Press Enter to exit...:"
	do {
		$key = [System.Console]::ReadKey($true)
	} until ($key.Key -eq 'Enter')
	exit 1
}

Write-Log 'Required modules are installed.'
Write-Log 'All requirements met. Proceeding with the script...'

$scopes = @(
	'AdministrativeUnit.Read.All',
	'Application.Read.All',
	'AuditLog.Read.All',
	'Domain.Read.All',
	'Directory.Read.All',
	'RoleAssignmentSchedule.Read.Directory',
	'RoleEligibilitySchedule.Read.Directory',
	'RoleManagement.Read.Directory',
	'Policy.Read.All',
	'User.Read.All'
)

function Connect-MicrosoftGraph {
	try {
		Connect-MgGraph -Scope $scopes -NoWelcome
	} catch {
		Write-Log -Message "Unable to connect to Microsoft Graph. Error: $_" -Severity ERROR
	}
}

Connect-MicrosoftGraph

#Connect-ExchangeOnline -ShowBanner:$false

function Resolve-EIDPrivProps{
	param (
		[Parameter(Mandatory)]
		[ValidateSet('Users', 'Devices', 'Groups', 'NamedLocations', 'RoleDefinitions', 'ServicePrincipals', 'SubscribedSKUs', 'DefaultUserRolePermissions')]
		[string[]]$Type
	)
	$userProperties = @(
			'AccountEnabled',
			'AssignedLicenses',
			'CreatedDateTime',
			'DisplayName',
			'Id',
			'LastPasswordChangeDateTime',
			'Mail',
			'OnPremisesSyncEnabled',
			'SignInActivity',
			'UserPrincipalName',
			'UserType'
		)
	if (-not $Global:EIDPropsCache.Users -or -not `
		$Global:EIDPropsCache.Devices -or -not `
		$Global:EIDPropsCache.Groups -or -not `
		$Global:EIDPropsCache.NamedLocations -or -not `
		$Global:EIDPropsCache.RoleDefinitions -or -not `
		$Global:EIDPropsCache.ServicePrincipals -or -not `
		$Global:EIDPropsCache.SubscribedSKUs -or -not `
		$Global:EIDPropsCache.DefaultUserRolePermissions) {
			Write-Log 'Initializing Microsoft Graph cache...'
			if (-not $Global:EIDPropsCache.Users) {
				$Global:EIDPropsCache.Users = Get-MgUser -All -Property $userProperties
			}
			if (-not $Global:EIDPropsCache.Devices) {
				$Global:EIDPropsCache.Devices = Get-MgDevice -All
			}
			if (-not $Global:EIDPropsCache.Groups) {
				$Global:EIDPropsCache.Groups = Get-MgGroup -All
			}
			if (-not $Global:EIDPropsCache.NamedLocations) {
				$Global:EIDPropsCache.NamedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
			}
			if (-not $Global:EIDPropsCache.RoleDefinitions) {
				$Global:EIDPropsCache.RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
			}
			if (-not $Global:EIDPropsCache.ServicePrincipals) {
				$Global:EIDPropsCache.ServicePrincipals = Get-MgServicePrincipal -All
			}
			if (-not $Global:EIDPropsCache.SubscribedSKUs) {
				$Global:EIDPropsCache.SubscribedSKUs = Get-MgSubscribedSku -All
			}
			if (-not $Global:EIDPropsCache.DefaultUserRolePermissions) {
				$Global:EIDPropsCache.DefaultUserRolePermissions = (Get-MgBetaPolicyAuthorizationPolicy).DefaultUserRolePermissions
			}
			Write-Log 'Microsoft Graph cache initialized.'
		}

	else {
		Write-Log 'Microsoft Graph cache already initialized.' -Severity DEBUG
	}

	$result = @{}
	foreach ($t in $Type) {
		$result[$t] = $Global:EIDPropsCache[$t]
	}
	return $result
}

$script:GridViews = [System.Collections.Generic.List[hashtable]]::new()

function Add-GridView {
	[CmdletBinding()]
	param(
		[Parameter(ValueFromPipeline=$true)]
		$InputObject,
		[string]$Title = 'Report',
		[switch]$PassThru,
		[switch]$Wait
	)
	begin { $buf = New-Object System.Collections.Generic.List[object] }
	process { if($null -ne $InputObject){ [void]$buf.Add($InputObject) } }
	end {
		$script:GridViews.Add(@{
			Title = $Title
			Data  = $buf.ToArray()
			PassThru = [bool]$PassThru
			Wait     = [bool]$Wait
		})
	}
}

function Show-QueuedGridViews {
	[CmdletBinding()]
	param(
		[ValidateSet('AllAtOnce','Sequential')]
		[string]$Mode = 'Sequential'
	)
	foreach($g in $script:GridViews){
		$params = @{
			Title    = $g.Title
		}
		if($g.PassThru){ $params.PassThru = $true }
		if($Mode -eq 'Sequential'){ $params.Wait = $true }
		$null = $g.Data | Microsoft.PowerShell.Utility\Out-GridView @params
	}
	$script:GridViews.Clear()
}


function ConvertTo-EIDPrivRows{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject]$row,
		[Object[]]$property,
		[System.Collections.Generic.HashSet[string]]$dateProps = 'lastLogonTimestamp',
		[scriptblock]$scriptBlock
	)

	Begin{
		$rowCount = 1
		if($property){
			$outProps = @(, 'Row#') + $property
		}else{
			$outProps = $null
		}
	}
	Process{
		$out = [ordered]@{
			'Row#' = $rowCount++
		}
		foreach($p in $row.PSObject.Properties.Name){
			if($dateProps.Contains($p)){
				$out.($p + 'Date') = if($null -ne $row.$p){
					[DateTime]::FromFileTime($row.$p)
				}else{
					$null
				}
			}
			if($p -ieq 'mS-DS-ConsistencyGuid'){
				$out.$p = [System.Convert]::ToBase64String($row.$p)
			}else{
				$out.$p = $row.$p
			}
		}
		if($scriptBlock){
			$scriptBlock.Invoke($out)
		}
		# The Select-Object here must be called only after the the object is re-created above,
		#   including null properties for the columns requested,
		#   or operating under StrictMode will throw a PropertyNotFoundException (PropertyNotFoundException).
		return [PSCustomObject]$out |
			Select-Object -Property $outProps
	}
}

function Out-EIDPrivReports{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[PSCustomObject]$inputResults,
		[Parameter(Mandatory)]
		$ctx,
		[Parameter(Mandatory)]
		[string]$name,
		[Parameter(Mandatory)]
		[string]$title
	)
	Begin{
		$results = [System.Collections.ArrayList]::new()
	}
	Process{
		[void]$results.Add([PSCustomObject]$inputResults)
	}
	End{
		$results = $results.ToArray()
		$caption = "$title ($name): "
		if($results){
			$caption += $results.Count
		}else{
			$caption += 0
		}
		Write-Log "  $caption"
		# Reduce unnecessary memory usage in large directories with large reports.
		if($ctx.params.passThru){
			$ctx.reports.$name = $results
		}
		$path = ($ctx.params.filePattern -f ('-' + $name)) + '.csv'
		$pathName = Split-Path -Path $path -Leaf
		$ctx.reportRowCounts[$pathName] = $results.Count
		if($results){
			if(!$ctx.params.noFiles){
				$results | Export-Csv -NoTypeInformation -Path $path -Encoding $ctx.params.fileEncoding
				$ctx.reportFiles[$name] = $path
			}
			if($ctx.params.interactive){
				$results | Add-GridView -Title $caption
			}
		}elseif(!$ctx.params.noFiles){
			# Write (or overwrite) an empty file.
			[System.IO.FileStream]::new(
					$path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write
				).Close()
			$ctx.reportFiles[$name] = $path
		}
	}
}

function New-EIDPrivReport{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		$ctx,
		[Parameter(Mandatory)]
		[string]$name,
		[Parameter(Mandatory)]
		[string]$title,
		[Parameter(Mandatory)]
		[scriptblock]$dataSource,
		[switch]$mayNotFail
	)

	Write-Log "Processing $title ($name)..."
	try{
		& $dataSource | Out-EIDPrivReports -ctx $ctx -name $name -title $title
	}catch{
		if($mayNotFail){
			throw $_
		}else{
			Write-Log 'Error:', $_ -Severity ERROR
			[void]$warnings.Add([PSCustomObject]@{
				Text = "Failed report: $title ($name) - $_"
			})
			if(!$batch){
				$_ | Format-List -Force
			}
		}
	}
}

function Get-EIDPrivReportsFolder(){
	if(!$reportsFolder){
		$desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
		$reportsFolder = Join-Path $desktopPath 'EID-Reports'
	}
	$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($reportsFolder)
}

function Initialize-EIDPrivReports(){
	$ctx = [ordered]@{
		params = [ordered]@{
			version = $version
			now = $null
			currentUser = $null
			hostName = [System.Net.Dns]::GetHostName()
			domain = $null
			m366ConnectParams = $EIDConnectParams
			psExe = (Get-Process -Id $PID).Path
			psVersionTable = $PSVersionTable
			interactive = !$batch
			filePattern = $null
			firstRunFiles = $false
			noFiles = $noFiles
			noZip = $noZip
			passThru = $PassThru
			fileEncoding = "UTF8"
		}
		reports = [ordered]@{}
		reportFiles = [ordered]@{}
		reportRowCounts = @{}
		EIDProps = [ordered]@{}
		osVersions = $null
	}

	Write-Log ('Version: ' + $version)

	$reportsFolder = Get-EIDPrivReportsFolder
	$ctx.params.reportsFolder = $reportsFolder
	Write-Log ('$reportsFolder: {0}' -f $reportsFolder)
	if(!$ctx.params.noFiles){
		[void](New-Item -ItemType Directory -Path $reportsFolder -Force)
	}

	# This doesn't affect Out-GridView, which falls back to the current user preferences in Windows.
	$currentThread = [System.Threading.Thread]::CurrentThread
	$culture = [CultureInfo]::InvariantCulture.Clone()
	$culture.DateTimeFormat.ShortDatePattern = 'yyyy-MM-dd'
	$currentThread.CurrentCulture = $culture
	$currentThread.CurrentUICulture = $culture

	$now = $ctx.params.now = Get-Date
	# Write-Log ('$now: {0}' -f $now)
	# $filterDate = $ctx.params.filterDate = $now.AddDays(-90)
	# Write-Log ('$filterDate: {0}' -f $filterDate)
	# $filterDatePassword = $ctx.params.filterDatePassword = $now.AddDays(-365)
	# Write-Log ('$filterDatePassword: {0}' -f $filterDatePassword)

	if($PSVersionTable.PSVersion.Major -ge 6){
		$ctx.params.fileEncoding = 'utf8BOM'
	}

	if($server){
		$EIDConnectParams['Server'] = $server
	}
	$domain = $ctx.params.domain = (Get-MgDomain | Where-Object {$_.isDefault}).Id

	$filePattern = $ctx.params.filePattern = Join-Path $reportsFolder `
		($domain +
			'{0}-' +
			(Get-Date -Date $now -Format 'yyyy-MM-dd'))
	Write-Log ('$filePattern: {0}' -f $filePattern)

	if(!$ctx.params.noFiles){
		$firstRunSearch = Join-Path $reportsFolder ($domain + '-*')
		if(!(Get-ChildItem -Path $firstRunSearch -File)){
			Write-Log ('firstRunFiles: {0}' -f $firstRunSearch)
			$ctx.params.firstRunFiles = $true
		}

		Write-Log 'Writing parameters JSON file...'

		$paramsJsonPath = $filePattern -f '-params' + '.json'
		$ctx.params | ConvertTo-Json | Out-File $paramsJsonPath -Force -Encoding $ctx.params.fileEncoding
		$ctx.reportFiles['params'] = $paramsJsonPath
	}

#	Initialize-EIDPrivProps $ctx

	return $ctx
}

function Invoke-EIDPrivReportHistory($ctx){
	if(!(Test-Path $ctx.params.reportsFolder -PathType Container)){
		Write-Log 'Invoke-EIDPrivReportHistory: reportsFolder does not exist, exiting.'
		return
	}

	New-EIDPrivReport -ctx $ctx -name 'reportHistory' -title 'EID Privileged Audit Report History' -dataSource {
		$rowCounts = @{}

		# Read prior counts from cache.
		$rptHistRowCountCacheCsv = Join-Path $ctx.params.reportsFolder "$($ctx.params.domain)-reportHistory-RowCountCache.csv"
		if(Test-Path $rptHistRowCountCacheCsv -PathType Leaf){
			Import-Csv -Path $rptHistRowCountCacheCsv | ForEach-Object{
				$rowCounts[$_.CsvFile] = [int]$_.RowCount
			}
		}else{
			Write-Log '  No row count cache found.'
		}

		# Update with any values from this report run.
		foreach($rc in $ctx.reportRowCounts.GetEnumerator()){
			$rowCounts[$rc.Key] = $rc.Value
		}

		$reportNamePattern = [regex]::new('(.*)-(.*)-(\d{4}-\d{2}-\d{2})(?:-(initial))?\.csv')
		Get-ChildItem -Path ($ctx.params.reportsFolder + '\*.csv') -Exclude '*-reportHistory-*' | ForEach-Object -Process {
			$csvFile = $_
			$rowCount = $rowCounts[$csvFile.Name]
			if($null -eq $rowCount){
				# If the row count result still does not exist, then actually read the number of rows from the CSV file.
				$rowCount = (Import-Csv -Path $csvFile | Measure-Object).Count
				$rowCounts[$csvFile.Name] = $rowCount
			}
			$result = [PSCustomObject][ordered]@{
				'CsvFile' = $csvFile.Name
				'Domain' = $null
				'Report' = $null
				'Date' = $null
				'DateSuffix' = $null
				'RowCount' = $rowCount
			}

			$match = $reportNamePattern.Match($csvFile.Name)
			if($match.Success){
				$result.Domain = $match.Groups[1].Value
				$result.Report = $match.Groups[2].Value
				$result.Date = $match.Groups[3].Value
				$result.DateSuffix = $match.Groups[4].Value
			}

			$result
		} -End{
			$rowCounts.GetEnumerator() | Sort-Object -Property Key | ForEach-Object{
				[PSCustomObject][ordered]@{
					CsvFile = $_.Key
					RowCount = $_.Value
				}
			} | Export-Csv -NoTypeInformation -Path $rptHistRowCountCacheCsv -Encoding $ctx.params.fileEncoding
		} | Sort-Object -Property 'Domain', 'Report', 'Date', 'DateSuffix', 'CsvFile' `
			| ConvertTo-EIDPrivRows
	}
}

function Test-PrivilegedUsers($ctx) {
	New-EIDPrivReport -ctx $ctx -name 'privUsers' -title 'Privileged Users' -dataSource {
		$privilegedUsers = @()
		$servicePlans = (Get-MgSubscribedSku).ServicePlans.ServicePlanName
		$isEntraP2 = $servicePlans -contains 'AAD_PREMIUM_P2'
		$isEntraP1 = $servicePlans -contains 'AAD_PREMIUM'
		$propsCache = Resolve-EIDPrivProps -Type Users, Groups, RoleDefinitions, ServicePrincipals
		$allUsers = $propsCache.Users
		$allGroups = $propsCache.Groups
		$allServicePrincipalIds = ($propsCache.ServicePrincipals).Id
		$role = $propsCache.RoleDefinitions

		try {
			function Get-RoleDetails {
				param (
					[Parameter(Mandatory)] [string]$roleType,
					[Parameter(Mandatory)] [string]$principalId,
					[Parameter(Mandatory)] [string]$roleDefinitionId,
					[Parameter(Mandatory)] [string]$directoryScopeId,
					[int]$memberDepth = 1,
					[string]$parentGroupId = $null
				)

				try {
					if ($principalId -in $allUsers.Id) {
						Write-Log -Message "PrincipalId $principalId identified as User." -Severity DEBUG
						$principal = $allUsers | Where-Object {$_.Id -eq $principalId}
						$userType = $principal.UserType
					} elseif ($principalId -in $allGroups.Id) {
						Write-Log -Message "PrincipalId $principalId identified as Group." -Severity DEBUG
						$principal = $allGroups | Where-Object {$_.Id -eq $principalId}
						$userType = $null
						$groupType = $principal.GroupTypes
						$serviceType = $null
						$DaysSinceLastSignIn = $null
						$groupMembers = Get-MgGroupMember -GroupId $principalId
						foreach ($groupMember in $groupMembers) {
							Get-RoleDetails -roleType $roleType -principalId $groupMember.Id -roleDefinitionId $roleDefinitionId -directoryScopeId $directoryScopeId -memberDepth ($memberDepth + 1) -parentGroupId $principalId
						}
					} elseif ($principalId -in $allServicePrincipalIds) {
						Write-Log -Message "PrincipalId $principalId identified as Service Principal." -Severity DEBUG
						try {
							$principal = $propsCache.ServicePrincipals | Where-Object {$_.Id -eq $principalId} | Select-Object -Property DisplayName, AppId, ServicePrincipalType
							$userType = $null
							$groupType = $null
							$serviceType = $principal.ServicePrincipalType
							$DaysSinceLastSignIn = $null
						} catch {
							Write-Log -Message "Failed to retrieve service principal for PrincipalId: $principalId. Error: $_" -Severity ERROR
							$principal = [PSCustomObject]@{
								DisplayName = "Unknown Service Principal"
								Id = $principalId
								ServicePrincipalType = "Unknown"
							}
						}
					} else {
						Write-Log -Message "PrincipalId $principalId not found in users, groups, or service principals." -Severity WARN
						$principal = [PSCustomObject]@{
							DisplayName = "Unknown Principal"
							Id = $principalId
						}
					}

					$roleId = $role.Id | Where-Object {$_ -eq $roleDefinitionId}
					$roleName = $role | Where-Object {$_.Id -eq $roleDefinitionId} | Select-Object -ExpandProperty DisplayName
					$roleDescription = $role | Where-Object {$_.Id -eq $roleDefinitionId} | Select-Object -ExpandProperty Description
					$roleBuiltIn = $role | Where-Object {$_.Id -eq $roleDefinitionId} | Select-Object -ExpandProperty IsBuiltIn
					$parentGroupName = if ($parentGroupId) { ($allGroups | Where-Object { $_.Id -eq $parentGroupId }).DisplayName } else { $null }

					if ($null -ne $principal -and $principal.PSObject.Properties.Match('SignInActivity').Count -gt 0 -and $null -ne $principal.SignInActivity.LastSuccessfulSignInDateTime) {
						$LastSuccessfulSignInDateTime = $principal.SignInActivity.LastSuccessfulSignInDateTime
						$DaysSinceLastSignIn = (Get-Date).Subtract($LastSuccessfulSignInDateTime).Days
					} else {
						$DaysSinceLastSignIn = $null
					}

					if ($null -ne $directoryScopeId) {
						try {
							$cleanDirectoryScopeId = $directoryScopeId -replace '/administrativeUnits/', ''
							$directoryScope = Get-MgDirectoryAdministrativeUnit -All | Where-Object { $_.Id -eq $cleanDirectoryScopeId }
							$directoryScopeName = $directoryScope.DisplayName
						} catch {
							$directoryScopeName = '/'
						}
					} else {
						Write-Log -Message "Error retrieving directory scope name for DirectoryScopeId: $($cleanDirectoryScopeId). Error: $_" -Severity WARN
					}

					if ($roleType -eq 'Eligible') {
						$createdDateTime = $eligibility.CreatedDateTime
						$expirationType = $eligibility.ScheduleInfo.Expiration.Type
						$expirationDateTime = $eligibility.ScheduleInfo.Expiration.EndDateTime
					} else {
						$createdDateTime = $null
						$expirationType = $null
						$expirationDateTime = $null
					}

					if ($null -ne $principal -and $principal.PSObject.Properties.Match('OnPremisesSyncEnabled').Count -gt 0 -and $principal.OnPremisesSyncEnabled) {
						Write-Log -Message "Privileged user $($principal.UserPrincipalName) is synced from on-premises." -Severity WARN
					}

					return [PSCustomObject]@{
						'RoleId' = if($null -ne $roleId) {$roleId} else {$null}
						'RoleName' = $roleName
						'MemberDepth' = $memberDepth
						'ObjectId' = if($null -ne $principal -and $principal.PSObject.Properties.Match('Id').Count -gt 0) {$principal.Id} else {"Unknown (PrincipalId: $principalId)"}
						'DisplayName' = if($null -ne $principal -and $principal.PSObject.Properties.Match('DisplayName').Count -gt 0) {$principal.DisplayName} else {"Unknown Service Principal"}
						'OnPremisesSyncEnabled' = if($principal.PSObject.Properties['OnPremisesSyncEnabled'] -and $principal.OnPremisesSyncEnabled -eq $true) {'Yes'} else {'No'}
						'Type' = if($null -ne $userType) {$userType} elseif ($null -ne $serviceType) {$serviceType} elseif ($groupType -eq 'Unified') {'Microsoft 365 Group'} elseif (-not $groupType -or $groupType.Count -eq 0) {'Security Group'} else {'Unknown'}
						'ParentGroup' = $parentGroupName
						'CreatedDateTime' = if($null -ne $principal -and $principal.PSObject.Properties.Match('CreatedDateTime').Count -gt 0) {$principal.CreatedDateTime} else {$null}
						'LastSuccessfulSignInDateTime' = if($null -ne $principal -and $principal.PSObject.Properties.Match('SignInActivity').Count -gt 0) {$principal.SignInActivity.LastSuccessfulSignInDateTime} else {$null}
						'DaysSinceLastSignIn' = $DaysSinceLastSignIn
						'LastPasswordChangeDateTime' = if($null -ne $principal -and $principal.PSObject.Properties.Match('LastPasswordChangeDateTime').Count -gt 0) {$principal.LastPasswordChangeDateTime} else {$null}
						'IsBuiltIn' = if($null -ne $roleBuiltIn) {$roleBuiltIn} else {'False'}
						'RoleType' = $RoleType
						'DirectoryScope' = $directoryScopeName
						'IsActivated' = 'True'
						'CreatedDate(UTC)' = $createdDateTime
						'ExpirationType' = $expirationType
						'ExpirationDate(UTC)' = $expirationDateTime
						'UserPrincipalName' = if ($null -ne $principal -and $principal.PSObject.Properties.Match('UserPrincipalName').Count -gt 0) {$principal.UserPrincipalName} elseif ($principal.PSObject.Properties.Match('AppId').Count -gt 0) {"$($principal.DisplayName) (Service Principal)"} else {"$($principal.DisplayName) (Group)"}
						'RoleDescription' = $roleDescription
					}
				} catch {
					Write-Log -Message "Error getting role details for PrincipalId: $principalId for role: $($assignment.RoleDefinitionId). $_" -Severity ERROR
					return $null
				}
			}

			function Get-RoleAssignment {
				param (
					[Parameter(Mandatory)] [object]$assignment,
					[Parameter(Mandatory)] [string]$roleType,
					[ref]$privilegedUsers
				)

				$roleDetails = Get-RoleDetails -RoleType $roleType -PrincipalId $assignment.PrincipalId -RoleDefinitionId $assignment.RoleDefinitionId -DirectoryScopeId $assignment.DirectoryScopeId

				if ($roleDetails) {
					$privilegedUsers.Value += $roleDetails
				}
			}

			if ($isEntraP2) {
				Write-Log -Message 'Entra P2 license found.'
				foreach ($assignment in Get-MgRoleManagementDirectoryRoleAssignment -All) {
					Get-RoleAssignment -assignment $assignment -roleType 'Assigned' -privilegedUsers ([ref]$privilegedUsers)
				}
				foreach ($eligibility in Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All) {
					Get-RoleAssignment -assignment $eligibility -roleType 'Eligible' -privilegedUsers ([ref]$privilegedUsers)
				}
			} elseif ($isEntraP1) {
				Write-Log -Message 'Entra P1 license found.'
				foreach ($assignment in Get-MgRoleManagementDirectoryRoleAssignment -All) {
					Get-RoleAssignment -assignment $assignment -roleType 'Assigned' -privilegedUsers ([ref]$privilegedUsers)
				}
			} else {
				Write-Log -Message 'No Entra P1 or P2 licenses found.' -Severity WARN
			}
		} catch {
			Write-Log -Message "Error generating privileged user report: $_" -Severity ERROR
		}

		$orderedList = @()
		$processedUsers = @()

		$globalAdmins = $privilegedUsers | Where-Object { $_.RoleName -eq 'Global Administrator' } | Sort-Object DisplayName
		$nonGlobalRoles = $privilegedUsers | Where-Object { $_.RoleName -ne 'Global Administrator' }

		$validRoles = $nonGlobalRoles | Where-Object { $_.RoleName }
		$invalidRoles = $nonGlobalRoles | Where-Object { -not $_.RoleName }

		$rolesGrouped = $validRoles | Sort-Object RoleName, DisplayName | Group-Object -Property RoleName

		$orderedList += $globalAdmins
		$processedUsers += $globalAdmins.ObjectId

		foreach ($role in $rolesGrouped) {
			$roleName = $role.Name
			Write-Log "Processing Role: $roleName" -Severity DEBUG
			$roleGroups = $role.Group | Where-Object { $_.Type -like "*Group" } | Sort-Object DisplayName
			$roleUsers = $role.Group | Where-Object { $_.Type -eq 'Member' -or $_.Type -eq 'Guest' -and $_.MemberDepth -eq 2} | Sort-Object DisplayName
			$directAssignments = $role.Group | Where-Object {$_.Type -eq 'Member' -or $_.Type -eq 'Guest' -and $_.MemberDepth -eq 1} | Sort-Object DisplayName
			$orderedList += $directAssignments
			$processedUsers += $directAssignments | Sort-Object DisplayName

			foreach ($group in $roleGroups) {
				$orderedList += $group
				if ($group.ObjectId) {
					$members = foreach ($user in $roleUsers) {
						if ($user.ObjectId -and $user.MemberDepth -eq 2) {
							try {
								$userGroups = Get-MgUserMemberOf -UserId $user.ObjectId
								if ($userGroups.Id -contains $group.ObjectId) {
									$processedUsers += $user.ObjectId
									$user
								}
							} catch {
								Write-Log "Failed to retrieve groups for user: $($user.DisplayName) - $_" -Severity WARN
							}
						}
						else {
							Write-Log "Skipping user with no ObjectId: $($user.DisplayName)" -Severity WARN
						}
					}

					$orderedList += $members | Sort-Object DisplayName
				}
				else {
					Write-Log "Skipping group with no ObjectId: $($group.DisplayName)" -Severity WARN
				}
			}

			$remainingUsers = $roleUsers | Where-Object {$null -ne $_.ObjectId -and $_.ObjectId -notin $processedUsers}
			$orderedList += $remainingUsers
			$processedUsers += $remainingUsers
		}

		if ($invalidRoles) {
			Write-Log 'Found entries missing RoleName. Adding them at the end.' -Severity DEBUG
			$orderedList += $invalidRoles | Sort-Object DisplayName
		}

		$orderedList | ConvertTo-EIDPrivRows
	}
}

function Test-PrivilegedRoles($ctx) {
	New-EIDPrivReport -ctx $ctx -name 'privRoles' -title 'Privileged Roles' -dataSource {
		try {
			$servicePlans = (Get-MgSubscribedSku).ServicePlans.ServicePlanName
			$roleDefinitions = (Resolve-EIDPrivProps -Type RoleDefinitions).RoleDefinitions
			$roleDefDict = @{}
			foreach ($role in $roleDefinitions) {
				$roleDefDict[$role.Id] = $role
			}

			if ($servicePlans -contains 'AAD_PREMIUM_P2') {
				$roleCounts = @{}

				foreach ($role in $roleDefinitions) {
					$roleCounts[$role.DisplayName] = @{
						'isBuiltIn' = $role.IsBuiltIn
						'Assigned#' = 0
						'Eligible#' = 0
						'Description' = $role.Description
					}
				}

				function Get-Roles {
					param (
						[array]$Roles,
						[string]$Type
					)

					foreach ($roleEntry in $Roles) {
						try {
							if ($null -eq $roleEntry.RoleDefinitionId) {
								Write-Log -Message "$Type RoleDefinitionId missing for role entry $($roleEntry.Id)." -Severity WARN
								continue
							}

							$role = $roleDefDict[$roleEntry.RoleDefinitionId]

							if ($null -eq $role) {
								try {
									$role = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($roleEntry.RoleDefinitionId)"
								} catch {
									Write-Log -Message "Error retrieving role definition for RoleDefinitionId: $($roleEntry.RoleDefinitionId). Error: $_" -Severity WARN
									continue
								}
							}

							if ($null -ne $role) {
								if (-not $roleCounts.ContainsKey($role.DisplayName)) {
									$roleCounts[$role.DisplayName] = @{
										'isBuiltIn' = $role.IsBuiltIn
										'Assigned#' = 0
										'Eligible#' = 0
										'Description' = $role.Description
									}
								}
								$roleCounts[$role.DisplayName]["${Type}#"] += 1
							}
						} catch {
							Write-Log -Message "Error processing $Type role $($roleEntry.Id). Error: $_" -Severity WARN
						}
					}
				}

				Get-Roles -Roles (Get-MgRoleManagementDirectoryRoleAssignment -All) -Type 'Assigned'
				Get-Roles -Roles (Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All) -Type 'Eligible'

				$privilegedRoles = $roleCounts.GetEnumerator() | ForEach-Object {
					[PSCustomObject]@{
						'RoleName' = $_.Key
						'isBuiltIn' = $_.Value['isBuiltIn']
						'Assigned#' = $_.Value['Assigned#']
						'Eligible#' = $_.Value['Eligible#']
						'Description' = $_.Value['Description']
					}
				}

				$privilegedRoles = $privilegedRoles | Sort-Object `
					@{Expression = { if ($_.RoleName -eq 'Global Administrator') { 0 } `
						elseif ($_.'Assigned#' -gt 0 -or $_.'Eligible#' -gt 0) { 1 } `
						else { 2 }	}}, RoleName

				$privilegedRoles | ConvertTo-EIDPrivRows

			} elseif ($servicePlans -contains 'AAD_PREMIUM') {
				$roleCounts = @{}

				foreach ($role in $roleDefinitions) {
					$roleCounts[$role.DisplayName] = @{
						'isBuiltIn' = $role.IsBuiltIn
						'Assigned#' = 0
						'Eligible#' = 0
						'Description' = $role.Description
					}
				}

				foreach ($assignment in Get-MgRoleManagementDirectoryRoleAssignment -All) {
					try {
						if ($null -eq $assignment.RoleDefinitionId) {
							Write-Log -Message 'RoleDefinitionId missing for assigned role.' -Severity WARN
							continue
						}

						$role = $roleDefDict[$assignment.RoleDefinitionId]

						if ($null -eq $role) {
							try {
								$role = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$($assignment.RoleDefinitionId)"
							} catch {
								Write-Log -Message "Error retrieving role definition for RoleDefinitionId: $($assignment.RoleDefinitionId). Error: $_" -Severity WARN
								continue
							}
						}

						if ($null -ne $role) {
							if (-not $roleCounts.ContainsKey($role.DisplayName)) {
								$roleCounts[$role.DisplayName] = @{
									'isBuiltIn' = $role.IsBuiltIn
									'Assigned#' = 0
									'Eligible#' = 0
									'Description' = $role.Description
								}
							}
							$roleCounts[$role.DisplayName]['Assigned#'] += 1
						}
					} catch {
						Write-Log -Message "Error processing assigned role $($assignment.Id). Error: $_" -Severity WARN
					}
				}

				$privilegedRoles = $roleCounts.GetEnumerator() | ForEach-Object {
					[PSCustomObject]@{
						'RoleName'   = $_.Key
						'isBuiltIn'  = $_.Value['isBuiltIn']
						'Assigned#'  = $_.Value['Assigned#']
						'Eligible#'  = $_.Value['Eligible#']
						'Description' = $_.Value['Description']
					}
				}

				$privilegedRoles = $privilegedRoles | Sort-Object `
					@{Expression = { if ($_.RoleName -eq 'Global Administrator') { 0 } `
						elseif ($_.'Assigned#' -gt 0 -or $_.'Eligible#' -gt 0) { 1 } `
						else { 2 }	}}, RoleName

				$privilegedRoles | ConvertTo-EIDPrivRows
			} else {
				Write-Host 'No relevant service plans found.'
			}
		} catch {
			Write-Log -Message "Error creating 'Privileged Roles' report. Error: $_" -Severity ERROR
		}
	}
}


function Test-StaleUsers($ctx) {
	New-EIDPrivReport -ctx $ctx -name 'staleUsers' -title 'Stale Users' -dataSource {
		try {
			$staleUsers = [System.Collections.Generic.List[Object]]::new()
			$allUsers = (Resolve-EIDPrivProps -Type Users).Users
			foreach ($user in $allUsers) {
				$LastSuccessfulSignInDate = if ($user.SignInActivity.LastSuccessfulSignInDateTime) {
					$user.SignInActivity.LastSuccessfulSignInDateTime
				} else {
					'Never Signed-in.'
				}
				$DaysSinceLastSignIn = if ($user.SignInActivity.LastSuccessfulSignInDateTime) {
					(New-TimeSpan -Start $user.SignInActivity.LastSuccessfulSignInDateTime -End (Get-Date)).Days
				} else {
					'N/A'
				}
				$isLicensed = if ($user.AssignedLicenses) {
					'Yes'
				} else {
					'No'
				}
				if (!$user.SignInActivity.LastSuccessfulSignInDateTime -or (Get-Date $user.SignInActivity.LastSuccessfulSignInDateTime)) {
					if ($DaysSinceLastSignIn -ge 30) {
						$obj = [PSCustomObject]@{
							'ObjectId' = $user.Id
							'DisplayName' = $user.DisplayName
							'UserPrincipalName' = $user.UserPrincipalName
							'CreatedDateTime' = $user.CreatedDateTime
							'LastSuccessfulSignInDate' = $LastSuccessfulSignInDate
							'DaysSinceLastSignIn' = $DaysSinceLastSignIn
							'LastPasswordChangeDateTime' = $user.LastPasswordChangeDateTime
							'AccountEnabled' = $user.AccountEnabled
							'IsLicensed' = $isLicensed
							'UserType' = $user.UserType
						}
						$staleUsers.Add($obj)
					}
				}
			}

			if ($staleUsers.Count -gt 0 -and $staleUsers.Count -lt 2) {
				Write-Log -Message "$($staleUsers.Count) stale user found." -Severity WARN
			} elseif ($staleUsers.Count -gt 1) {
				Write-Log -Message "$($staleUsers.Count) stale users found." -Severity WARN
			}
			 else {
				Write-Log -Message 'No stale users found.' -Severity INFO
			}
			$staleUsers = $staleUsers | Sort-Object -Property DaysSinceLastSignIn -Descending
			$staleUsers | ConvertTo-EIDPrivRows
		} catch {
			Write-Log -Message "Error creating 'Stale Users' report. Error: $_" -Severity ERROR
		}
	}
}

function Test-StalePasswords($ctx) {
	New-EIDPrivReport -ctx $ctx -name 'stalePasswords' -title 'Stale Passwords' -dataSource {
		try {
			$stalePasswords = [System.Collections.Generic.List[Object]]::new()
			$allUsers = (Resolve-EIDPrivProps -Type Users).Users
			foreach ($user in $allUsers) {
				$LastPasswordChangeDateTime = if ($user.LastPasswordChangeDateTime) {
					$user.LastPasswordChangeDateTime
				} else {
					'Never Signed-in.'
				}
				$DaysSinceLastPasswordChange = if ($user.LastPasswordChangeDateTime) {
					(New-TimeSpan -Start $user.LastPasswordChangeDateTime -End (Get-Date)).Days
				} else {
					'N/A'
				}
				$isLicensed = if ($user.AssignedLicenses) {
					'Yes'
				} else {
					'No'
				}
				if (!$user.LastPasswordChangeDateTime -or (Get-Date $user.LastPasswordChangeDateTime)) {
					if ($DaysSinceLastPasswordChange -ge 365) {
						$obj = [PSCustomObject]@{
							'DisplayName' = $user.DisplayName
							'UserPrincipalName' = $user.UserPrincipalName
							'CreatedDateTime' = $user.CreatedDateTime
							'LastPasswordChangeDateTime' = $LastPasswordChangeDateTime
							'DaysSinceLastPasswordChange' = $DaysSinceLastPasswordChange
							'AccountEnabled' = $user.AccountEnabled
							'IsLicensed' = $isLicensed
							'UserType' = $user.UserType
						}
						$stalePasswords.Add($obj)
					}
				}
			}

			if ($stalePasswords.Count -gt 0 -and $stalePasswords.Count -lt 2) {
				Write-Log -Message "$($stalePasswords.Count) stale password found." -Severity WARN
			} elseif ($stalePasswords.Count -gt 1) {
				Write-Log -Message "$($stalePasswords.Count) stale passwords found." -Severity WARN
			}
			else {
				Write-Log -Message 'No stale passwords found.'
			}
			$stalePasswords = $stalePasswords | Sort-Object -Property DaysSinceLastPasswordChange -Descending
			$stalePasswords | ConvertTo-EIDPrivRows
		} catch {
			Write-Log -Message "Error creating 'Stale Passwords' report. Error: $_" -Severity ERROR
		}
	}
}

function Test-StaleDevices($ctx){
	New-EIDPrivReport -ctx $ctx -name 'staleDevices' -title 'Stale Devices' -dataSource {
		$staleDaysThreshold = 90
		$now = Get-Date
		$devices = (Resolve-EIDPrivProps -Type Devices).Devices
		$staleDevices = $devices | Where-Object {
			($_.ApproximateLastSignInDateTime -lt $now.AddDays(-$staleDaysThreshold))
		}
		if ($staleDevices) {
			$staleDevicesReport = $staleDevices | Select-Object `
				DeviceId,
				DisplayName,
				OperatingSystem,
				OperatingSystemVersion,
				ApproximateLastSignInDateTime,
				@{n='DaysSinceLastSignIn'; e={(New-TimeSpan -Start $_.ApproximateLastSignInDateTime -End $now).Days}}

			$staleDevicesReport | ConvertTo-EIDPrivRows
			if ($staleDevices.Count -gt 0 -and $staleDevices.Count -lt 2) {
				Write-Log -Message "$($staleDevices.Count) stale device found." -Severity WARN
			} elseif ($staleDevices.Count -gt 1) {
				Write-Log -Message "$($staleDevices.Count) stale devices found." -Severity WARN
			}
		} else {
			Write-Log -Message 'No stale devices found.'
		}
	}
}

function Test-UserRegistration($ctx){
	New-EIDPrivReport -ctx $ctx -name 'userRegistration' -title 'User Registration' -dataSource {
		$regDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
		$allUsers = (Resolve-EIDPrivProps -Type Users).Users
		$userDetails = [System.Collections.Generic.List[Object]]::new()
		foreach ($userDetail in $regDetails) {
			$user = $allUsers | Where-Object {$_.Id -eq $userDetail.Id}
			$obj = [PSCustomObject]@{
				'ObjectId' = $user.Id
				'DisplayName' = $user.DisplayName
				'UserPrincipalName' = $user.UserPrincipalName
				'IsAdmin?' = $userDetail.IsAdmin
				'IsMFACapable?' = $userDetail.IsMfaCapable
				'IsMFARegistered?' = $userDetail.IsMfaRegistered
				'IsPasswordlessCapable?' = $userDetail.IsPasswordlessCapable
				'IsSSPRCapable?' = $userDetail.IsSsprCapable
				'IsSSPREnabled?' = $userDetail.IsSsprEnabled
				'IsSSPRRegistered?' = $userDetail.IsSsprRegistered
				'LastUpdated' = $userDetail.LastUpdatedDateTime
			}
			$userDetails.Add($obj)
		}
		$userDetails | ConvertTo-EIDPrivRows
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
		Write-Log -Message "Error retrieving license names. Error: $_" -Severity ERROR
	}
}

function Get-UserLicenses {
	Get-LicenseNames
	$propsCache = Resolve-EIDPrivProps -Type Users, SubscribedSKUs
	$allUsers = $propsCache.Users
	$allSKUs = $propsCache.SubscribedSKUs

	try {
		$licensedUsers = [System.Collections.Generic.List[Object]]::new()
		$disabledLicensedUsers = @()
		$users = $allUsers | Where-Object { $_.AssignedLicenses.Count -gt 0 }

		foreach ($user in $users) {
			foreach ($license in $user.AssignedLicenses) {
				$obj = [PSCustomObject]@{
					'ObjectId' = $user.Id
					'DisplayName' = $user.DisplayName
					'UserPrincipalName' = $user.UserPrincipalName
					'Type' = $user.UserType
					'AccountEnabled' = $user.AccountEnabled
					'License' = if ($Global:licenseGUID[$license.SkuId]) {
						$Global:licenseGUID[$license.SkuId]
					} else {
						$allSKUs | Where-Object { $_.SkuId -eq $license.SkuId } | Select-Object -ExpandProperty SkuPartNumber
					}
				}
				$licensedUsers.Add($obj)
			}

			if ($user.AccountEnabled -eq $false) {
				$disabledLicensedUsers += $user
			}
		}

		if ($disabledLicensedUsers.Count -gt 0 -and $disabledLicensedUsers.Count -lt 2) {
			Write-Log "$($disabledLicensedUsers.Count) disabled licensed user account found." -Severity WARN
		}

		if ($disabledLicensedUsers.Count -gt 1) {
			Write-Log "$($disabledLicensedUsers.Count) disabled licensed user accounts found." -Severity WARN
		}

		$licensedUsers = $licensedUsers | Sort-Object @{ Expression = { if ($_.AccountEnabled -eq $false) { 0 } else { 1 } } }, DisplayName
		$licensedUsers
	} catch {
		Write-Log -Message "Error creating 'User Licenses' report. Error: $_" -Severity ERROR
	}
}

function Get-TenantLicenses {
	Get-LicenseNames
	$tenantLicenses = (Resolve-EIDPrivProps -Type SubscribedSKUs).SubscribedSKUs
	try {
		$tenantLicenses = $tenantLicenses | Select-Object SkuPartNumber, SkuId, @{Name = 'ActiveUnits'; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits, CapabilityStatus |
		ForEach-Object {
			[PSCustomObject]@{
				'SKU' = $_.SkuPartNumber
				'License' = if($Global:licenseString[$_.SkuPartNumber]) {
					$Global:licenseString[$_.SkuPartNumber]
				} else { 
					$null
				}
				'Total' = $_.ActiveUnits
				'In Use' = $_.ConsumedUnits
				'Available' = $_.ActiveUnits - $_.ConsumedUnits
				'CapabilityStatus' = if ($_.CapabilityStatus) { $_.CapabilityStatus } else { 'Unknown' }
			}
		}
		$tenantLicenses | Sort-Object 'License'
	} catch {
		Write-Log -Message "Error creating 'Tenant Licenses' report. Error: $_" -Severity ERROR
	}
}

function Test-CAPolicies($ctx) {
	New-EIDPrivReport -ctx $ctx -name 'caPolicies' -title 'Conditional Access Policies' -dataSource {
		try {
			$policies = Get-MgIdentityConditionalAccessPolicy -All
			if ($policies.Count -eq 0) {
				Write-Log -Message 'No Conditional Access policies found.' -Severity INFO
				return @()
			}

			$cache = Resolve-EIDPrivProps -Type @('Users', 'Groups', 'RoleDefinitions', 'ServicePrincipals', 'NamedLocations')
			$userMap  = $cache.Users | Group-Object -Property Id -AsHashTable
			$groupMap = $cache.Groups | Group-Object -Property Id -AsHashTable
			$roleMap  = $cache.RoleDefinitions | Group-Object -Property Id -AsHashTable
			$appMap   = $cache.ServicePrincipals | Group-Object -Property AppId -AsHashTable
			$locationMap = $cache.NamedLocations | Group-Object -Property Id -AsHashTable

			function Resolve-Ids {
				param (
					[string[]]$Ids,
					[hashtable]$LookupMap
				)
				if (-not $Ids) { return @() }
				$Ids | ForEach-Object {
					if ($_ -eq 'All') {'All'}
					elseif ($_ -eq 'GuestsOrExternalUsers') {'GuestsOrExternalUsers'}
					elseif ($LookupMap.ContainsKey($_)) {$LookupMap[$_].DisplayName}
					elseif ($_ -eq $null -or $_ -eq '') {'None'}
					else {"Unknown: $_"}
				}
			}

			function Resolve-AppIds {
				param (
					[string[]]$Ids,
					[hashtable]$LookupMap
				)
				if (-not $Ids) { return @() }
				$Ids | ForEach-Object {
					if ($_ -eq 'All') { 'All Cloud Apps' }
					elseif ($_ -eq 'Office365') { 'Office 365' }
					elseif ($LookupMap.ContainsKey($_)) { $LookupMap[$_].DisplayName }
					else { "Unknown App: $_" }
				}
			}

			function Resolve-Locations {
				param (
					[string[]]$Ids,
					[hashtable]$LookupMap
				)
				if (-not $Ids) { return @() }
				$Ids | ForEach-Object {
					if ($LookupMap.ContainsKey($_)) { $LookupMap[$_].DisplayName }
					elseif ($_ -eq 'AllTrusted') { 'All Trusted Locations' }
					elseif ($_ -eq 'All') { 'All Locations' }
					else {"Unknown Location: $_"}
				}
			}


			$policyList = foreach ($policy in $policies) {
				$includedUsers = Resolve-Ids -Ids $policy.Conditions.Users.IncludeUsers -LookupMap $userMap
				$excludedUsers = Resolve-Ids -Ids $policy.Conditions.Users.ExcludeUsers -LookupMap $userMap
				$includedGroups = Resolve-Ids -Ids $policy.Conditions.Users.IncludeGroups -LookupMap $groupMap
				$excludedGroups = Resolve-Ids -Ids $policy.Conditions.Users.ExcludeGroups -LookupMap $groupMap
				$includedRoles = Resolve-Ids -Ids $policy.Conditions.Users.IncludeRoles -LookupMap $roleMap
				$excludedRoles = Resolve-Ids -Ids $policy.Conditions.Users.ExcludeRoles -LookupMap $roleMap
				$includedApps = Resolve-AppIds -Ids $policy.Conditions.Applications.IncludeApplications -LookupMap $appMap
				$excludedApps = Resolve-AppIds -Ids $policy.Conditions.Applications.ExcludeApplications -LookupMap $appMap
				$includedLocations = Resolve-Locations -Ids $policy.Conditions.Locations.IncludeLocations -LookupMap $locationMap
				$excludedLocations = Resolve-Locations -Ids $policy.Conditions.Locations.ExcludeLocations -LookupMap $locationMap
				$session = $policy.SessionControls

				[PSCustomObject]@{
					'Id' = $policy.Id
					'DisplayName' = $policy.DisplayName
					'State' = $policy.State
					'CreatedDateTime' = if ($policy.CreatedDateTime) { [datetime]::Parse($policy.CreatedDateTime).ToLocalTime() } else { $null }
					'ModifiedDateTime' = if ($policy.ModifiedDateTime) { [datetime]::Parse($policy.ModifiedDateTime).ToLocalTime() } else { $null }
					'UsersIncluded' = $includedUsers -join ', '
					'UsersExcluded' = $excludedUsers -join ', '
					'GroupsIncluded' = $includedGroups -join ', '
					'GroupsExcluded' = $excludedGroups -join ', '
					'RolesIncluded' = $includedRoles -join ', '
					'RolesExcluded' = $excludedRoles -join ', '
					'AppsIncluded' = $includedApps -join ', '
					'AppsExcluded' = $excludedApps -join ', '
					'AppFilterMode' = $policy.Conditions.Applications.ApplicationFilter.Mode
					'AppFilterRule' = $policy.Conditions.Applications.ApplicationFilter.Rule
					'PlatformsIncluded' = ($policy.Conditions.Platforms.IncludePlatforms -join ', ')
					'PlatformsExcluded' = ($policy.Conditions.Platforms.ExcludePlatforms -join ', ')
					'LocationsIncluded' = $includedLocations -join ', '
					'LocationsExcluded' = $excludedLocations -join ', '
					'ClientAppTypes' = ($policy.Conditions.ClientAppTypes -join ', ')
					'GrantControls' = ($policy.GrantControls.BuiltInControls -join ', ')
					'GrantOperator' = $policy.GrantControls.Operator
					'Session_SignInFrequency' = if ($session.SignInFrequency.IsEnabled -and $null -ne $session.SignInFrequency.Value) {
						if ($session.SignInFrequency.Type -eq 'Hours' -and $session.SignInFrequency.Value -eq 1) {
							"Every $($session.SignInFrequency.Value) hour"
						} elseif ($session.SignInFrequency.Type -eq 'Hours' -and $session.SignInFrequency.Value -gt 1) {
							"Every $($session.SignInFrequency.Value) hours"
						} elseif ($session.SignInFrequency.Type -eq 'Days' -and $session.SignInFrequency.Value -eq 1) {
							"Every $($session.SignInFrequency.Value) day"
						} elseif ($session.SignInFrequency.Type -eq 'Days' -and $session.SignInFrequency.Value -gt 1) {
							"Every $($session.SignInFrequency.Value) days"
						} else {
							'Every time'
						}
					} elseif ($session.SignInFrequency.IsEnabled -and $null -eq $session.SignInFrequency.Value) {
						'Every time'
					} else {
						'Disabled'
					}

					'Session_PersistentBrowser' = if ($session.PersistentBrowser.IsEnabled) {
						$session.PersistentBrowser.Mode
					} else {'Disabled'}

					'Session_CloudAppSecurity' = if ($session.CloudAppSecurity.IsEnabled) {
						$session.CloudAppSecurity.Mode
					} else {'Disabled'}

					'Session_AppEnforcedRestrictions' = if ($session.ApplicationEnforcedRestrictions.IsEnabled) {
						'Enabled'
					} else {'Disabled'}

					'Session_DisableResilienceDefaults' = if ($session.DisableResilienceDefaults) {
						'True'
					} else {'False'}
				}
			}

			$policyList | Sort-Object DisplayName | ConvertTo-EIDPrivRows
		}
		catch {
			Write-Log -Message "Error retrieving Conditional Access policies: $_" -Severity ERROR
			return @()
		}
	}
}

function Test-UserCanRegisterApps($ctx) {
	try {
		$propsCache = Resolve-EIDPrivProps -Type DefaultUserRolePermissions
		$ctx = $propsCache.DefaultUserRolePermissions.AllowedToCreateApps
		if ($ctx -eq $true) {
			Write-Log -Message 'Users can register applications in your tenant.' -Severity WARN
		} elseif ($ctx -eq $false) {
			Write-Log -Message 'Users cannot register applications in your tenant.'
		} else {
			Write-Log -Message "Unexpected value for UserCanRegisterApps: $ctx" -Severity ERROR
		}
	} catch {
			Write-Log -Message "Error checking app register permissions: $_" -Severity ERROR
	}
}

function Test-UserCanCreateGroups($ctx) {
	try {
		$propsCache = Resolve-EIDPrivProps -Type DefaultUserRolePermissions
		$ctx = $propsCache.DefaultUserRolePermissions.AllowedToCreateSecurityGroups
		if ($ctx -eq $true) {
			Write-Log -Message 'Users can create security groups in your tenant.' -Severity WARN
		} elseif ($ctx -eq $false) {
			Write-Log -Message 'Users cannot create security groups in your tenant.'
		} else {
			Write-Log -Message "Unexpected value for UserCanCreateGroups: $ctx" -Severity ERROR
		}
	} catch {
		Write-Log -Message "Error checking group creation permissions: $_" -Severity ERROR
	}
}

function Test-SharedMailboxSignInAllowed {
	New-EIDPrivReport -ctx $ctx -name 'sharedMailboxSignInAllowed' -title 'Shared Mailbox Sign-In Allowed' -dataSource {
		$sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox
		$enabledMailboxes = [System.Collections.Generic.List[Object]]::new()
		$propsCache = Resolve-EIDPrivProps -Type Users
		$allUsers = $propsCache.Users

		foreach ($mailbox in $sharedMailboxes) {
			try {
				$enabledUsers = $null

				if ($null -ne $mailbox.userPrincipalName) {
					try {
						$enabledUsers = $allUsers | Where-Object {$_.UserPrincipalName -eq $mailbox.UserPrincipalName -and $_.AccountEnabled -eq $true} | Select-Object AccountEnabled,DisplayName,UserPrincipalName
					} catch {
						Write-Log -Message "Error retrieving user $($mailbox.userPrincipalName). Error: $_" -Severity WARN
					}
				}

				if ($null -ne $enabledUsers) {
					$enabledMailboxes += [PSCustomObject]@{
						'Name' = $enabledUsers.DisplayName
						'userPrincipalName' = $enabledUsers.UserPrincipalName
						'Sign-In' = $enabledUsers.AccountEnabled
					}
					Write-Log -Message "The shared mailbox account for $($mailbox.UserPrincipalName) is enabled." -Severity WARN
					Add-ToWarningsAndErrors -Type 'Warning' -Message "The shared mailbox account for $($mailbox.UserPrincipalName) is enabled." -Function 'Shared Mailbox Sign-In Allowed'
				}
			} catch {

			}
		}
	}
	$enabledMailboxes = $enabledMailboxes | Where-Object {$_.'Sign-In' -eq $true}
	$enabledMailboxes | ConvertTo-EIDPrivRows
}

function Invoke-EIDPrivReports($ctx){
	$steps = New-Object System.Collections.Generic.List[hashtable]

	$addStep = {
		param([string]$name, [scriptblock]$action)
		$steps.Add(@{ Name = $name; Action = $action })
	}

	& $addStep 'Privileged Users' { Test-PrivilegedUsers -ctx $ctx }
	& $addStep 'Privileged Roles' { Test-PrivilegedRoles -ctx $ctx }
	& $addStep 'Stale Users' { Test-StaleUsers -ctx $ctx }
	& $addStep 'Stale Passwords' { Test-StalePasswords -ctx $ctx }
	& $addStep 'Stale Devices' { Test-StaleDevices -ctx $ctx }
	& $addStep 'User Registration' { Test-UserRegistration -ctx $ctx }
	& $addStep 'User Licenses' {
		New-EIDPrivReport -ctx $ctx -name 'userLicenses' -title 'User Licenses' -dataSource {
			Get-UserLicenses | ConvertTo-EIDPrivRows
		}
	}
	& $addStep 'Tenant Licenses' {
		New-EIDPrivReport -ctx $ctx -name 'tenantLicenses' -title 'Tenant Licenses' -dataSource {
			Get-TenantLicenses | ConvertTo-EIDPrivRows
		}
	}
	& $addStep 'Conditional Access Policies' { Test-CAPolicies -ctx $ctx }
	& $addStep 'User Can Register Apps' { Test-UserCanRegisterApps -ctx $ctx }
	& $addStep 'User Can Create Groups' { Test-UserCanCreateGroups -ctx $ctx }
#	& $addStep 'Shared Mailbox Sign-In Allowed' { Test-SharedMailboxSignInAllowed } # left commented
	& $addStep 'Warnings' {
		New-EIDPrivReport -ctx $ctx -name 'warnings' -title 'Warnings' -mayNotFail -dataSource {
			$warnings | ConvertTo-EIDPrivRows
		}
	}

	if(-not $ctx.params.noFiles){
		if(-not $ctx.params.noZip){
			& $addStep 'Create compressed archive (ZIP)' {
				Write-Log 'Creating compressed archive...'
				$zipPath = $ctx.params.filePattern -f '' + '.zip'
				Compress-Archive -Path $ctx.reportFiles.Values -DestinationPath $zipPath -CompressionLevel 'Optimal' -Force
				$ctx.reportFiles['zip'] = $zipPath
			}
		}

		if($ctx.params.firstRunFiles){
			& $addStep 'Copy initial run files' {
				Write-Log 'Copying files as initial run...'
				foreach($f in $ctx.reportFiles.Values){
					$f2 = $f -replace '\.[^\.\\]+$', '-initial$0'
					Copy-Item -Path $f -Destination $f2
				}
			}
		}

		& $addStep 'Update report history' {
			Invoke-EIDPrivReportHistory -ctx $ctx
		}
	}

	$activity = 'Running EID Privileged Reports'
	$total = [math]::Max(1, $steps.Count)
	$progressId = 1

	for($i = 0; $i -lt $steps.Count; $i++){
		$step = $steps[$i]
		$status = ('{0}/{1}: {2}' -f ($i+1), $total, $step.Name)

		$percentBefore = [math]::Floor((100.0 * $i) / $total)

		Write-Progress -Id $progressId -Activity $activity -Status $status -PercentComplete $percentBefore

		try {
			& $($step.Action)
		} catch {
			Write-Progress -Id $progressId -Activity $activity -Status ("Error on step: {0}" -f $step.Name) -PercentComplete $percentBefore
			throw
		}

		$percentAfter = [math]::Floor((100.0 * ($i + 1)) / $total)
		Write-Progress -Id $progressId -Activity $activity -Status $status -PercentComplete $percentAfter
	}

	Write-Progress -Id $progressId -Activity $activity -Completed

	if($ctx.params.passThru){
		return [PSCustomObject]$ctx
	}
}

function Invoke-EIDPrivMain(){
	try{
		$ctx = Initialize-EIDPrivReports
		Invoke-EIDPrivReports -ctx $ctx
		Show-QueuedGridViews -Mode AllAtOnce
		Disconnect-MgGraph
		Write-Log 'Done!'
		if($ctx.params.interactive){
			Pause
		}
	}catch{
		Write-Log 'Error:', $_ -Severity ERROR
		if(!$batch){
			$_ | Format-List -Force
			Pause
		}else{
			throw $_
		}
	}
}

if($MyInvocation.InvocationName -ne '.'){
	Invoke-EIDPrivMain
}
