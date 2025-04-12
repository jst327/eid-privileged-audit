# Justin Tucker - 2025-01-01, 2025-04-11
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

$version = '2025-04-11'
$warnings = [System.Collections.ArrayList]::new()
$EIDConnectParams = @{}

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

$requiredModules = @('Microsoft.Graph', 'ExchangeOnlineManagement')
$missingModules = @()

foreach ($module in $requiredModules) {
	if (-not (Test-ModuleInstalled -ModuleName $module)) {
		$missingModules += $module
	}
}

Write-Log 'Checking for required PowerShell modules...'

if ($missingModules.Count -gt 0) {
	Write-Log "The following required modules are not installed: $($missingModules -join ', ')" -Severity ERROR
	Write-Host "Press Enter to exit...:"
	do {
		$key = [System.Console]::ReadKey($true)
	} until ($key.Key -eq 'Enter')
	exit 1
}

Write-Log "Required modules are installed: $($requiredModules -join ', ')"
Write-Log 'All requirements met. Proceeding with the script...'

function Connect-MicrosoftGraph {
	try {
		Connect-MgGraph -Scope `
				'User.Read.All', `
				'Directory.Read.All', `
				'AuditLog.Read.All', `
				'RoleManagement.Read.Directory', `
				'AdministrativeUnit.Read.All', `
				'RoleAssignmentSchedule.Read.Directory', `
				'RoleEligibilitySchedule.Read.Directory', `
				'Application.Read.All' `
			-NoWelcome
	} catch {
		Write-Log -Message "Unable to connect to Microsoft Graph. Error: $_" -Severity ERROR
	}
}

Connect-MicrosoftGraph

function Connect-ToExchangeOnline {
	try {
		Connect-ExchangeOnline -ShowBanner:$false
	} catch {
		Write-Log -Message 'Error connecting to Exchange Online' -Severity ERROR
		Add-ToWarningsAndErrors -Type Error -Message 'Error connecting to Exchange Online' -Function 'Connect to Exchange Online'
	}
}

#Connect-ToExchangeOnline

$osVersionPattern = [regex]::new('(\d+\.\d+)(?: \((\d+)\))?')

function Initialize-ADPrivOSVersions(){
	$osVersions = @{
		# - https://learn.microsoft.com/en-us/lifecycle/products/
		'4.0' = @{
			'Categories' = @{
				'Windows NT' = 1
			}
			'Builds' = @{
				'' = @{
					'Version' = ''
					'Availability' = '1996-08-24'
					'EndOfServicing' = @{
						1 = @{
							'Mainstream' = '2002-12-31'
							'Extended' = '2004-12-31'
						}
					}
				}
			}
		}
		'5.0' = @{
			'Categories' = @{
				'Windows 2000 Professional' = 1
				'Windows 2000 Server' = 1
			}
			'Builds' = @{
				2195 = @{
					'Version' = ''
					'Availability' = '2000-02-17'
					'EndOfServicing' = @{
						1 = @{
							'Mainstream' = '2005-06-30'
							'Extended' = '2010-07-13'
						}
					}
				}
			}
		}
		'5.1' = @{
			'Categories' = @{
				'Windows XP Professional' = 1
				'Windows XP Tablet PC Edition' = 2
			}
			'Builds' = @{
				2600 = @{
					# This currently does not take into account Service Packs, given they are
					#   not reflected in the OperatingSystemVersion for Windows XP.
					'Version' = ''
					'Availability' = @{
						1 = '2001-12-31'
						2 = '2003-02-11'
					}
					'EndOfServicing' = @{
						1 = @{
							'Mainstream' = '2009-04-14'
							'Extended' = '2014-04-08'
						}
						2 = @{
							'Mainstream' = '2009-04-14'
							'Extended' = '2014-04-08'
						}
					}
				}
			}
		}
		'5.2' = @{
			'Categories' = @{
				'Windows Server 2003' = 1
			}
			'Builds' = @{
				3790 = @{
					# This currently does not take into account Service Packs, given they are
					#   not reflected in the OperatingSystemVersion for Windows Server 2013.
					'Version' = ''
					'Availability' = '2003-05-28'
					'EndOfServicing' = @{
						1 = @{
							'Mainstream' = '2010-07-13'
							'Extended' = '2015-07-14'
						}
					}
				}
			}
		}
		'6.0' = @{
			'Categories' = @{
				'Windows Vista™ Business' = 0
				'Windows Server® 2008 Datacenter' = 1
				'Windows Server® 2008 Enterprise' = 1
				'Windows Server® 2008 Standard' = 1
				'Windows® Storage Server 2008 Standard' = 2
			}
			'Builds' = @{
				6000 = @{
					'Version' = ''
					'Availability' = @{
						0 = '2007-01-25'
						1 = '2008-05-06'
					}
					'EndOfServicing' = @{
						0 = '2010-04-13'
						1 = '2011-07-12'
					}
				}
				6001 = @{
					'Version' = ''
					'Availability' = @{
						0 = '2008-02-04'
						1 = '2008-05-06'
					}
					'EndOfServicing' = @{
						0 = '2011-07-12'
						1 = '2011-07-12'
					}
				}
				6002 = @{
					'Version' = ''
					'Availability' = @{
						0 = '2009-04-29'
						1 = '2009-04-29'
						2 = '2009-07-19'
					}
					'EndOfServicing' = @{
						0 = @{
							'Mainstream' = '2012-04-10'
							'Extended' = '2017-04-11'
						}
						1 = @{
							'Mainstream' = '2015-01-13'
							'Extended' = '2020-01-14'
						}
						2 = @{
							'Mainstream' = '2015-01-13'
							'Extended' = '2020-01-14'
						}
					}
				}
				#6003 = 6002, override below.
			}
		}
		'6.1' = @{
			'Categories' = @{
				'Windows 7 Enterprise' = 1
				'Windows 7 Professional N' = 1
				'Windows 7 Professional' = 1
				'Windows 7 Ultimate N' = 1
				'Windows 7 Ultimate' = 1
				'Windows Embedded Standard' = 2
				'Windows Server 2008 R2 Datacenter' = 1
				'Windows Server 2008 R2 Enterprise' = 1
				'Windows Server 2008 R2 Standard' = 1
				'Windows Server 2008 HPC Edition' = 3
				'Hyper-V Server' = 100
			}
			'Builds' = @{
				7600 = @{
					'Version' = ''
					'Availability' = @{
						1 = '2009-10-22'
						2 = '2010-07-29'
						3 = '2010-10-17'
						100 = '2009-10-22'
					}
					'EndOfServicing' = @{
						1 = '2013-04-09'
						2 = '2013-04-09'
						3 = '2013-04-09'
						100 = '2012-04-10'
					}
				}
				7601 = @{
					'Version' = ''
					'Availability' = @{
						1 = '2011-02-22'
						2 = '2011-02-28'
						3 = '2011-02-22'
						100 = '2011-04-12'
					}
					'EndOfServicing' = @{
						1 = @{
							'Mainstream' = '2015-01-13'
							'Extended' = '2020-01-14'
						}
						2 = @{
							'Mainstream' = '2015-10-13'
							'Extended' = '2020-10-13'
						}
						3 = @{
							'Mainstream' = '2015-01-13'
							'Extended' = '2020-04-14'
						}
						100 = @{
							'Mainstream' = '2014-01-14'
							'Extended' = '2020-01-14'
						}
					}
				}
			}
		}
		'6.2' = @{
			'Categories' = @{
				'Hyper-V Server 2012' = 2
				'Windows 8 Enterprise' = 1
				'Windows 8 Pro' = 1
				'Windows Server 2012 Datacenter' = 2
				'Windows Server 2012 Standard' = 2
				'Windows Storage Server 2012 Standard' = 3
			}
			'Builds' = @{
				9200 = @{
					'Version' = ''
					'Availability' = '2012-10-30'
					'EndOfServicing' = @{
						1 = '2016-01-12'
						2 = @{
							'Mainstream' = '2018-10-09'
							'Extended' = '2023-10-10'
						}
						3 = @{
							'Mainstream' = '2018-10-09'
							'Extended' = '2023-10-10'
						}
					}
				}
			}
		}
		'6.3' = @{
			'Categories' = @{
				'Hyper-V Server 2012 R2' = 3
				'Windows 8.1 Enterprise' = 1
				'Windows 8.1 Pro' = 1
				'Windows Embedded 8.1 Industry Pro' = 2
				'Windows Server 2012 R2 Datacenter' = 3
				'Windows Server 2012 R2 Standard' = 3
				'Windows Storage Server 2012 R2 Standard' = 3
			}
			'Builds' = @{
				9600 = @{
					'Version' = ''
					'Availability' = '2013-11-25'
					'EndOfServicing' = @{
						1 = @{
							'Mainstream' = '2018-01-09'
							'Extended' = '2023-01-10'
						}
						2 = @{
							'Mainstream' = '2018-07-10'
							'Extended' = '2023-07-11'
						}
						3 = @{
							'Mainstream' = '2018-10-09'
							'Extended' = '2023-10-10'
						}
					}
				}
			}
		}
		'10.0' = @{
			'Categories' = @{
				'Windows 10 Business' = 1
				'Windows 10 Education' = 2
				'Windows 10 Enterprise 2015 LTSB' = 3
				'Windows 10 Enterprise 2016 LTSB' = 3
				'Windows 10 Enterprise for Virtual Desktops' = 2
				'Windows 10 Enterprise LTSC' = 3
				'Windows 10 Enterprise N' = 2
				'Windows 10 Enterprise' = 2
				'Windows 10 IoT Enterprise' = 2
				# - https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/whats-new/windows-iot-enterprise-ltsc
				'Windows 10 IoT Enterprise LTSC' = 4
				'Windows 10 Pro Education' = 1
				'Windows 10 Pro for Workstations' = 1
				'Windows 10 Pro N for Workstations' = 1
				'Windows 10 Pro N' = 1
				'Windows 10 Pro' = 1
				'Windows 11 Business' = 1
				'Windows 11 Education N' = 2
				'Windows 11 Education' = 2
				'Windows 11 Enterprise Multi-Session' = 2
				'Windows 11 Enterprise' = 2
				'Windows 11 IoT Enterprise' = 2
				'Windows 11 Pro Education' = 1
				'Windows 11 Pro for Workstations' = 1
				'Windows 11 Pro' = 1

				'Windows Server 2016 Datacenter' = 100
				'Windows Server 2016 Standard' = 100
				'Hyper-V Server 2016' = 100

				'Windows Server 2019 Datacenter' = 110
				'Windows Server 2019 Standard' = 110
				'Hyper-V Server' = 110

				'Windows Server 2022 Datacenter Azure Edition' = 120
				'Windows Server 2022 Datacenter' = 120
				'Windows Server 2022 Standard' = 120

				'Windows Server 2025 Datacenter Azure Edition' = 130
				'Windows Server 2025 Datacenter' = 130
				'Windows Server 2025 Standard' = 130
			}
			'Builds' = @{
				# - https://learn.microsoft.com/en-us/windows/release-health/release-information#windows-10-current-versions-by-servicing-option
				# - https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro
				# - https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education
				# - https://learn.microsoft.com/en-us/lifecycle/products/windows-10-team-surface-hub
					# - (Not yet included, as no releases are documented within.)
				# - https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/whats-new/release-history
				10240 = @{
					'Version' = '1507'
					'Availability' = '2015-07-29'
					'EndOfServicing' = @{
						1 = '2017-05-09'
						2 = '2017-05-09'
						# - https://learn.microsoft.com/en-us/lifecycle/products/windows-10-2015-ltsb
						3 = @{
							'Mainstream' = '2020-10-13'
							'Extended' = '2025-10-14'
						}
					}
				}
				10586 = @{
					'Version' = '1511'
					'Availability' = '2015-11-10'
					'EndOfServicing' = @{
						1 = '2017-10-10'
						2 = '2017-10-10'
					}
				}
				14393 = @{
					'Version' = '1607'
					'Availability' = @{
						1 = '2016-08-02'
						2 = '2016-08-02'
						3 = '2016-08-02'
						100 = '2016-10-15'
					}
					'EndOfServicing' = @{
						1 = '2018-04-10'
						2 = '2019-04-09'
						# - https://learn.microsoft.com/en-us/lifecycle/products/windows-10-2016-ltsb
						3 = @{
							'Mainstream' = '2021-10-12'
							'Extended' = '2026-10-13'
						}
						100 = @{
							'Mainstream' = '2022-01-11'
							'Extended' = '2027-01-12'
						}
					}
				}
				15063 = @{
					'Version' = '1703'
					'Availability' = '2017-04-11'
					'EndOfServicing' = @{
						1 = '2018-10-09'
						2 = '2019-10-08'
					}
				}
				16299 = @{
					'Version' = '1709'
					'Availability' = '2017-10-17'
					'EndOfServicing' = @{
						1 = '2019-04-09'
						2 = '2020-10-13'
					}
				}
				17134 = @{
					'Version' = '1803'
					'Availability' = '2018-04-30'
					'EndOfServicing' = @{
						1 = '2019-11-12'
						2 = '2021-05-11'
					}
				}
				17763 = @{
					'Version' = '1809'
					'Availability' = '2018-11-13'
					'EndOfServicing' = @{
						1 = '2020-11-10'
						2 = '2021-05-11'
						3 = @{
							'Mainstream' = '2024-01-09'
							'Extended' = '2029-01-09'
						}
						110 = @{
							'Mainstream' = '2024-01-09'
							'Extended' = '2029-01-09'
						}
					}
				}
				18362 = @{
					'Version' = '1903'
					'Availability' = '2019-05-21'
					'EndOfServicing' = @{
						1 = '2020-12-08'
						2 = '2020-12-08'
					}
				}
				18363 = @{
					'Version' = '1909'
					'Availability' = '2019-11-12'
					'EndOfServicing' = @{
						1 = '2021-05-11'
						2 = '2022-05-10'
					}
				}
				19041 = @{
					'Version' = '2004'
					'Availability' = '2020-10-20'
					'EndOfServicing' = @{
						1 = '2021-12-14'
						2 = '2021-12-14'
					}
				}
				19042 = @{
					'Version' = '20H2'
					'Availability' = '2020-10-20'
					'EndOfServicing' = @{
						1 = '2022-05-10'
						2 = '2023-05-09'
					}
				}
				19043 = @{
					'Version' = '21H1'
					'Availability' = '2021-05-18'
					'EndOfServicing' = @{
						1 = '2022-12-13'
						2 = '2022-12-13'
					}
				}
				19044 = @{
					'Version' = '21H2'
					'Availability' = '2021-11-16'
					'EndOfServicing' = @{
						1 = '2023-06-13'
						2 = '2024-06-11'
						3 = @{
							'Mainstream' = '2027-01-12'
							'Extended' = '2027-01-12'
						}
						4 = '2032-01-13'
					}
				}
				19045 = @{
					'Version' = '22H2'
					'Availability' = '2022-10-18'
					'EndOfServicing' = @{
						1 = '2025-10-14'
						2 = '2025-10-14'
					}
				}
				20348 = @{
					'Version' = ''
					'Availability' = '2021-08-18'
					'EndOfServicing' = @{
						120 = @{
							'Mainstream' = '2026-10-13'
							'Extended' = '2031-10-14'
						}
					}
				}
				# - https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information#windows-11-current-versions
				# - https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro
				# - https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education
				# - https://learn.microsoft.com/en-us/lifecycle/products/windows-11-iot-enterprise
				22000 = @{
					'Version' = '21H2'
					'Availability' = '2021-10-04'
					'EndOfServicing' = @{
						1 = '2023-10-10'
						2 = '2024-10-08'
					}
				}
				22621 = @{
					'Version' = '22H2'
					'Availability' = '2022-09-20'
					'EndOfServicing' = @{
						1 = '2024-10-08'
						2 = '2025-10-14'
					}
				}
				22631 = @{
					'Version' = '23H2'
					'Availability' = '2023-10-31'
					'EndOfServicing' = @{
						1 = '2025-11-11'
						2 = '2026-11-10'
					}
				}
				# - https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025
				26100 = @{
					'Version' = @{
						1 = '24H2'
						2 = '24H2'
						130 = ''
					}
					'Availability' = @{
						1 = '2024-10-01'
						2 = '2024-10-01'
						130 = '2024-11-01'
					}
					'EndOfServicing' = @{
						1 = '2026-10-13'
						2 = '2027-10-12'
						130 = @{
							'Mainstream' = '2029-10-09'
							'Extended' = '2034-10-10'
						}
					}
				}
			}
		}
	}

	# Overrides:
	$osVersions["6.0"].Builds[6003] = $osVersions["6.0"].Builds[6002]

	return $osVersions
}

function Get-ADPrivOSVersion($ctx, $row){
	$result = [PSCustomObject][ordered]@{
		Version = $null
		Build = $null
		BuildVersion = $null
		Availability = $null
		EndOfServicingMainstream = $null
		EndOfServicingMainstreamLife = $null
		EndOfServicingExtended = $null
		EndOfServicingExtendedLife = $null
		EndOfServicingMaxLife = $null
	}

	$osMatch = $osVersionPattern.Match($row.'OperatingSystemVersion')
	if($osMatch.Success){
		$osVer = $ctx.osVersions[$osMatch.Groups[1].Value]
		if($osVer){
			$result.Version = $osMatch.Groups[1].Value

			$searchBuild = $osMatch.Groups[2].Value
			if($searchBuild -ne ''){
				$searchBuild = [int]$searchBuild
			}
			$result.Build = $searchBuild
			$build = $osVer.'Builds'[$searchBuild]

			$cats = $osVer.'Categories'
			$tier = $cats[$row.'OperatingSystem']
			if($null -ne $tier -and $build){
				$buildVersion = $build.Version
				if($buildVersion -isnot [string]){
					$buildVersion = $buildVersion[$tier]
				}
				$result.BuildVersion = $buildVersion

				$availability = $build.Availability
				if($availability -isnot [string]){
					$availability = $availability[$tier]
				}
				$result.Availability = $availability

				$endOfServicing = $build.EndOfServicing
				if($endOfServicing -is [string]){
					$result.EndOfServicingMainstream = $endOfServicing
				}else{
					$endOfServicing = $endOfServicing[$tier]
					if($endOfServicing -is [string]){
						$result.EndOfServicingMainstream = $endOfServicing
					}else{
						$result.EndOfServicingMainstream = $endOfServicing['Mainstream']
						$result.EndOfServicingExtended = $endOfServicing['Extended']
					}
				}

				if($result.EndOfServicingMainstream){
					$result.EndOfServicingMainstreamLife = ([datetime]$result.EndOfServicingMainstream - $ctx.params.now.Date).Days
					$result.EndOfServicingMaxLife = $result.EndOfServicingMainstreamLife
				}
				if($result.EndOfServicingExtended){
					$result.EndOfServicingExtendedLife = ([datetime]$result.EndOfServicingExtended - $ctx.params.now.Date).Days
					$result.EndOfServicingMaxLife = [Math]::Max($result.EndOfServicingMainstreamLife, $result.EndOfServicingExtendedLife)
				}
			}
		}
	}

	return $result
}

function Resolve-EIDPrivProps([string]$class, [string]$context=$null, [switch]$generated){
	$props = [System.Collections.ArrayList]::new()
	function Expand-EIDProp($p){
		if($p -is [string]){
			[void]$props.Add($p)
		}elseif($p -is [array]){
			$p | ForEach-Object{
				Expand-EIDProp $_
			}
		}elseif($p.type -ceq 'class'){
			if(!$class -or $class -in $p.class){
				Expand-EIDProp $p.props
			}
		}elseif($p.type -ceq 'generated'){
			if($generated){
				Expand-EIDProp $p.props
			}
		}elseif($p.type -ceq 'context'){
			if($context -and $context -in @($p.context)){
				Expand-EIDProp $p.props
			}
		}else{
			throw "Unhandled property type: $($p.type)"
		}
	}

	Expand-EIDProp $ctx.EIDProps.source
	return $props
}

function Initialize-EIDPrivProps($ctx){
	# - https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all
	$ctx.EIDProps.source = 'objectSid', 'Name',
		@{type='class'; class='user', 'computer'; props=
			'Enabled',
			@{type='generated'; props='lastLogonTimestampDate'}, 'lastLogonTimestamp',
			'PasswordLastSet',
			@{type='context'; context='stalePasswords'; props='RC4'},
			'LastBadPasswordAttempt', 'PasswordExpired', 'PasswordNeverExpires', 'PasswordNotRequired', 'CannotChangePassword', 'userAccountControl'
		},
		'whenCreated', 'whenChanged',
		@{type='class'; class='user', 'computer'; props=
			'UserPrincipalName'
		},
		'sAMAccountName', 'DistinguishedName', 'CanonicalName',
		'DisplayName', 'Description',
		@{type='class'; class='user', 'computer'; props=
			'Company', 'Title', 'Department', 'Manager', 'EmployeeID', 'EmployeeNumber',
			'PrimaryGroupID', 'PrimaryGroup'},
		@{type='class'; class='group'; props=
			'GroupCategory', 'GroupScope', 'groupType'},
		@{type='class'; class='group', 'computer'; props=
			'ManagedBy'},
		@{type='class'; class='computer'; props=
			'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack', 'OperatingSystemHotfix'},
		'ObjectClass', 'ObjectGUID', 'mS-DS-ConsistencyGuid',
		'isCriticalSystemObject', 'ProtectedFromAccidentalDeletion'

	$ctx.EIDProps.allOut = Resolve-EIDPrivProps -generated
	$ctx.EIDProps.userIn = Resolve-EIDPrivProps 'user'
	$ctx.EIDProps.userOut = Resolve-EIDPrivProps 'user' -generated
	$ctx.EIDProps.compIn = Resolve-EIDPrivProps 'computer'
	$ctx.EIDProps.compOut = Resolve-EIDPrivProps 'computer' -generated
	$ctx.EIDProps.groupIn = Resolve-EIDPrivProps 'group'
	$ctx.EIDProps.groupOut = Resolve-EIDPrivProps 'group' -generated
	$ctx.EIDProps.objectIn = Resolve-EIDPrivProps 'object'
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
				$results | Out-GridView -Title $caption
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

	Initialize-EIDPrivProps $ctx

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
		$allUsers = Get-MgUser -All -Property CreatedDateTime, DisplayName, Id, LastPasswordChangeDateTime, OnPremisesSyncEnabled, SignInActivity, UserPrincipalName, UserType
		$allGroups = Get-MgGroup -All
		$allServicePrincipalIds = (Get-MgServicePrincipal -All).Id
		$role = Get-MgRoleManagementDirectoryRoleDefinition -All

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
							$principal = Get-MgServicePrincipal -ServicePrincipalId $principalId -Property DisplayName, AppId, ServicePrincipalType
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
						'OnPremisesSyncEnabled' = if($null -ne $principal -and $principal.PSObject.Properties.Match('OnPremisesSyncEnabled').Count -gt 0) {$principal.OnPremisesSyncEnabled} else {$null}
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
			Write-Log 'Found entries missing RoleName. Adding them at the end.' -Severity WARN
			$orderedList += $invalidRoles | Sort-Object DisplayName
		}

		$orderedList | ConvertTo-EIDPrivRows
	}
}

function Test-PrivilegedRoles($ctx) {
	New-EIDPrivReport -ctx $ctx -name 'privRoles' -title 'Privileged Roles' -dataSource {
		try {
			$servicePlans = (Get-MgSubscribedSku).ServicePlans.ServicePlanName
			$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
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
			$properties = @(
				'Id',
				'DisplayName',
				'Mail',
				'UserPrincipalName',
				'UserType',
				'AccountEnabled',
				'SignInActivity',
				'CreatedDateTime',
				'LastPasswordChangeDateTime',
				'AssignedLicenses'
			)
			$allUsers = Get-MgUser -All -Property $properties | Select-Object $properties
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
			$properties = @(
				'DisplayName',
				'Mail',
				'UserPrincipalName',
				'UserType',
				'AccountEnabled',
				'LastPasswordChangeDateTime'
				'CreatedDateTime',
				'AssignedLicenses'
			)
			$allUsers = Get-MgUser -All -Property $properties | Select-Object $properties
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
		$devices = Get-MgDevice -All
		$staleDevices = $devices | Where-Object {
			($_.ApproximateLastSignInDateTime -lt $now.AddDays(-$staleDaysThreshold))
		}
		if ($staleDevices) {
			$staleDevicesReport = $staleDevices | Select-Object `
				DisplayName,
				DeviceId,
				OperatingSystem,
				OperatingSystemVersion,
				ApproximateLastSignInDateTime

			$staleDevicesReport | ConvertTo-EIDPrivRows
		} else {
			Write-Log -Message 'No stale devices found.'
		}
	}
}

function Test-UnsupportedOS($ctx){
	$ctx.osVersions = Initialize-ADPrivOSVersions

	New-EIDPrivReport -ctx $ctx -name 'unsupportedOS' -title 'Unsupported Operating Systems' -dataSource {
		Get-MgDevice -All `
			| ForEach-Object {
				$row = $_
				$osVer = Get-ADPrivOSVersion $ctx $row
				if($osVer.EndOfServicingMainstreamLife -le 365){
					# Force a copy for now.
					# This should be further optimized later to avoid the need for a second copy of all properties per row in ConvertTo-ADPrivRows...
					$row = $_ | Select-Object -Property *,
						@{n='OS Version'; e={$osVer.Version}},
						@{n='OS Build'; e={$osVer.Build}},
						@{n='OS Build Ver'; e={$osVer.BuildVersion}},
						@{n='OS Availability'; e={$osVer.Availability}},
						@{n='OS EOS Mainstream'; e={$osVer.EndOfServicingMainstream}},
						@{n='OS EOS Mainstream Life'; e={$osVer.EndOfServicingMainstreamLife}},
						@{n='OS EOS Extended'; e={$osVer.EndOfServicingExtended}},
						@{n='OS EOS Extended Life'; e={$osVer.EndOfServicingExtendedLife}},
						@{n='OS EOS Max Life'; e={$osVer.EndOfServicingMaxLife}}
					$row
				}
			}	| Sort-Object -Property 'OS EOS Mainstream Life', 'lastLogonTimestamp' `
			| ConvertTo-EIDPrivRows -property (@('Name', 'OperatingSystem', 'OperatingSystemVersion', 'OS Version', 'OS Build', 'OS Build Ver', 'OS Availability',
				'OS EOS Mainstream', 'OS EOS Mainstream Life', 'OS EOS Extended', 'OS EOS Extended Life', 'OS EOS Max Life', 'lastLogonTimestampDate'))
	}
}

function Test-UserRegistration($ctx){
	New-EIDPrivReport -ctx $ctx -name 'userRegistration' -title 'User Registration' -dataSource {
		$userDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
		$allUsers = @()
		foreach ($userDetail in $userDetails) {
			$user = Get-MgUser -UserId $userDetail.Id

			$allUsers += [PSCustomObject]@{
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
		}
		$allUsers | ConvertTo-EIDPrivRows
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
	try {
		$licensedUsers = [System.Collections.Generic.List[Object]]::new()
		$users = Get-MgUser -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedUserCount -All -Select AccountEnabled, AssignedLicenses, DisplayName, Id, UserPrincipalName, UserType
		foreach ($user in $users) {
			foreach ($license in $user.AssignedLicenses) {
				$obj = [PSCustomObject]@{
					'ObjectId' = $user.Id
					'DisplayName' = $user.DisplayName
					'UserPrincipalName' = $user.UserPrincipalName
					'Type' = $user.UserType
					'AccountEnabled' = $user.AccountEnabled
					'License' = $Global:licenseGUID[$license.SkuId]
				}
				$licensedUsers.Add($obj)
			}
			if ($user.AccountEnabled -eq $false) {
				Write-Log "Licensed user account $($user.UserPrincipalName) is disabled." -Severity WARN
			}
		}
		$licensedUsers = $licensedUsers | Sort-Object @{Expression = {if ($_.AccountEnabled -eq $false) {0} else {1}}}, DisplayName
		$licensedUsers
	} catch {
		Write-Log -Message "Error creating 'User Licenses' report. Error: $_" -Severity ERROR
	}
}

function Get-TenantLicenses {
	Get-LicenseNames
	try {
		$tenantLicenses = Get-MgSubscribedSKU -All | Select-Object SkuPartNumber, SkuId, @{Name = 'ActiveUnits'; Expression = { ($_.PrepaidUnits).Enabled } }, ConsumedUnits, CapabilityStatus |
		ForEach-Object {
			[PSCustomObject]@{
				'License' = $Global:licenseString.($_.SkuPartNumber)
				'Total' = $_.ActiveUnits
				'In Use' = $_.ConsumedUnits
				'Available' = $_.ActiveUnits - $_.ConsumedUnits
				'CapabilityStatus' = if ($_.CapabilityStatus) { $_.CapabilityStatus } else { 'Unknown' }
			}
		}
		$tenantLicenses
	} catch {
		Write-Log -Message "Error creating 'Tenant Licenses' report. Error: $_" -Severity ERROR
	}
}

function Test-AuditStatus {
	try {
		$auditConfig = Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
		if ($auditConfig -match 'True') {
			Write-Log -Message 'Auditing is enabled for your tenant.'
		} else {
			Write-Log -Message 'Auditing is not enabled for your tenant.' -Severity WARN
		}
	} catch {
		Write-Log -Message "Error running 'Test-AuditStatus' report. Error: $_" -Severity ERROR
	}
}

function Test-SharedMailboxSignInAllowed {
	New-EIDPrivReport -ctx $ctx -name 'sharedMailboxSignInAllowed' -title 'Shared Mailbox Sign-In Allowed' -dataSource {
		$sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox
		$enabledMailboxes = [System.Collections.Generic.List[Object]]::new()

		foreach ($mailbox in $sharedMailboxes) {
			try {
				$enabledUsers = $null

				if ($null -ne $mailbox.userPrincipalName) {
					try {
						$enabledUsers = Get-MgUser -Filter 'accountEnabled eq true' | Where-Object {$_.UserPrincipalName -eq $mailbox.UserPrincipalName}
					} catch {
						Write-Log -Message "Error retrieving user $($mailbox.userPrincipalName). Error: $_" -Severity WARN
					}
				}

				if ($null -ne $enabledUsers) {
					$enabledMailboxes += [PSCustomObject]@{
						'Name' = $enabledUsers.DisplayName
						'userPrincipalName' = $enabledUsers.UserPrincipalName
						'Sign-In' = 'Enabled'
					}
					Write-Log -Message "The shared mailbox account for $($mailbox.UserPrincipalName) is enabled." -Severity WARN
					Add-ToWarningsAndErrors -Type 'Warning' -Message "The shared mailbox account for $($mailbox.UserPrincipalName) is enabled." -Function 'Shared Mailbox Sign-In Allowed'
				}
			} catch {

			}
		}
	}
	$enabledMailboxes = $enabledMailboxes | Sort-Object 'DisplayName'
	$enabledMailboxes | ConvertTo-EIDPrivRows
}

function Invoke-EIDPrivReports($ctx){
	# Privileged Users...
	Test-PrivilegedUsers -ctx $ctx

	# Privileged Roles...
	Test-PrivilegedRoles -ctx $ctx

	# Stale Users...
	Test-StaleUsers -ctx $ctx

	# Stale Passwords...
	Test-StalePasswords -ctx $ctx

	# Stale Devices...
	Test-StaleDevices -ctx $ctx

	# Computers with unsupported operating systems...
	Test-UnsupportedOS -ctx $ctx

	# User Registration...
	Test-UserRegistration -ctx $ctx

	# User Licenses...
	New-EIDPrivReport -ctx $ctx -name 'userLicenses' -title 'User Licenses' -dataSource {
		Get-UserLicenses `
			| ConvertTo-EIDPrivRows
	}

	# Tenant Licenses...
	New-EIDPrivReport -ctx $ctx -name 'tenantLicenses' -title 'Tenant Licenses' -dataSource {
		Get-TenantLicenses `
			| ConvertTo-EIDPrivRows
	}

	# Audit Status...
	#Test-AuditStatus

	# Shared Mailbox Sign-In Allowed...
	#Test-SharedMailboxSignInAllowed

	# Warnings...
	New-EIDPrivReport -ctx $ctx -name 'warnings' -title 'Warnings' -mayNotFail -dataSource {
		$warnings `
			| ConvertTo-EIDPrivRows
	}

	# Post-run File Processing
	if(!($ctx.params.noFiles)){
		if(!($ctx.params.noZip)){
			Write-Log 'Creating compressed archive...'
			$zipPath = $ctx.params.filePattern -f '' + '.zip'
			Compress-Archive -Path $ctx.reportFiles.Values -DestinationPath $zipPath -CompressionLevel 'Optimal' -Force
			$ctx.reportFiles['zip'] = $zipPath
		}

		if($ctx.params.firstRunFiles){
			Write-Log 'Copying files as initial run...'
			foreach($f in $ctx.reportFiles.Values){
				$f2 = $f -replace '\.[^\.\\]+$', '-initial$0'
				Copy-Item -Path $f -Destination $f2
			}
		}

		Invoke-EIDPrivReportHistory -ctx $ctx
	}

	if($ctx.params.passThru){
		return [PSCustomObject]$ctx
	}
}

function Invoke-EIDPrivMain(){
	try{
		$ctx = Initialize-EIDPrivReports
		Invoke-EIDPrivReports -ctx $ctx
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
