
<# 

Ultimate Active Directory Health check tool install/configure/utilize!
Prereq install and test run script 

Original script belongs to public module
https://evotec.xyz/what-do-we-say-to-health-checking-active-directory/


The pre-req install and single execution run script created by: Tastyratz

Version:
1.11 2021-12 TR Added ISE window check, keypress for module repair
1.1          TR Added windows capabilities, and dependency handling
1.0b         TR Added powershell minimum version number check at the start
1.0a         TR Extra write-hosts to give visibility into where script is
1.0          TR initial release

#>

################################################################
## Checks for ISE or Consolehost
################################################################

if ($host.Name -match 'ISE')
{
	Write-Host "Running in ISE. Prompts may false trigger in ISE" -ForegroundColor Yellow
	Start-Sleep -s 5
}


################################################################
## Check for minimum version of powershell to function
################################################################

if ($PSVersionTable.PSVersion.Major -gt 4)
{
	Write-Host "Powershell version check passed"
	Start-Sleep -Seconds 2
} else {

	Write-Error '
    Powershell version is too old to support the commands. Please update Windows Management Framework on this machine and then try again
    https://www.microsoft.com/en-us/download/details.aspx?id=54616
    '
	Start-Sleep -Seconds 20
	exit
}


################################################################
## Auto Elevate to Admin if not running as admin
################################################################

# Get the ID and security principal of the current user account
$WindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal ($WindowsID)

# Get the security principal for the Administrator role
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running "as Administrator"
if ($WindowsPrincipal.IsInRole($AdminRole)) {
	# We are running "as Administrator" - so change the title and background color to indicate this
	$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + " (Elevated)"
	$Host.UI.RawUI.BackgroundColor = "DarkBlue"
	Clear-Host
} else {
	# We are not running "as Administrator" - so relaunch as administrator
	# Create a new process object that starts PowerShell
	$NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
	# Specify the current script path and name as a parameter
	$NewProcess.Arguments = $myInvocation.MyCommand.Definition;
	# Indicate that the process should be elevated
	$NewProcess.Verb = "runas";
	# Start the new process
	[System.Diagnostics.Process]::Start($NewProcess);
	# Exit from the current unelevated process
	exit
}


###############################################################
#This function lets you prompt for an entry and times out
#note: If you run the script from ISE, the keyboard buffer pre-flush will NOT work and throw an error
################################################################

function GetKeyPress ([string]$regexPattern = '[ynq]',[string]$message = $null,[int]$timeOutSeconds = 0)
    {
	$key = $null
	$Host.UI.RawUI.FlushInputBuffer()
	if (![string]::IsNullOrEmpty($message))
    {
		Write-Host -NoNewline $message -ForegroundColor Yellow
	}

	$counter = $timeOutSeconds * 1000 / 250
	while ($key -eq $null -and ($timeOutSeconds -eq 0 -or $counter -- -gt 0))
	{
		if (($timeOutSeconds -eq 0) -or $Host.UI.RawUI.KeyAvailable)
		{
			$key_ = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown,IncludeKeyUp")
			if ($key_.KeyDown -and $key_.Character -match $regexPattern)
			{
				$key = $key_
			}
		} else {
			Start-Sleep -m 250 # Milliseconds
			Write-Host -NoNewline "."
		}
	}
	if (-not ($key -eq $null))
	{
		Write-Host -NoNewline "$($key.Character)"
	}

	if (![string]::IsNullOrEmpty($message))
	{
		Write-Host "" # newline
	}
	return $(if ($key -eq $null) { $null } else { $key.Character })
}



Write-Host '
This generates a MASSIVE report of talking points to audit, not all aggressive suggestions need to be addressed. View or share with care.
The report saves in the temp directory.
This can take 10 minutes to run.
'

################################################################
## Uninstall Testimo and dependencies, run this when problems found
################################################################

$host.UI.RawUI.FlushInputBuffer()
$key = GetKeyPress '[yn]' "Uinstall Testimo and dependencies? Do this if you experience errors and can't get the report to function.
([y]/n)?
" 8

if ($key -eq $null)
{
	Write-Host "No key was pressed.";
}
elseif ($key -eq "y") {
	Write-Host "Y key pressed"
	$Modules = @('Testimo','Connectimo','DSInternals','Emailimo','PSWinDocumentation.AD','PSWinDocumentation.DNS','ADEssentials','PSSharedGoods','PSWriteColor','PSWriteHTML')
	foreach ($Module in $Modules) {
		Uninstall-Module $Module -Force -AllVersions -ErrorAction continue
	}

	Uninstall-Module Pester -Force -AllVersions -ErrorAction continue
	Install-Module Pester -Force -AllowClobber -SkipPublisherCheck

} else {

	Write-Host "The key was '$($key)'."
}
Remove-Variable key


################################################################
## Make sure the OS has the required modules to continue
################################################################

function CheckRequiredOSModules {
	if ($MissingModules){ Clear-Variable $MissingModules }
	# Modules we need
	$modulesArray = @(
		"ActiveDirectory",
		"DHCPServer",
		"GroupPolicy",
		"ServerManager"
	)

	# Loop array for dependencies
	foreach ($mod in $modulesArray) {
		if (Get-Module -ListAvailable $mod) {
			# Module exists
			Write-Host "Required Module '$mod' was found" -ForegroundColor Green
		} else {
			# Module does not exist, install it
			Write-Error "The required module '$mod' is missing and needs to be installed!"
			Start-Sleep -s 5
			$MissingModules = 1
			# Install-Module $mod
		}
	}
	if ($MissingModules) { Write-Host "Required modules were not found and are listed above. This will not function correctly without them" }

}
CheckRequiredOSModules


################################################################
## Make sure the gallery is working, if not, fix it
################################################################

if (Get-PSRepository -Name "PSGallery") {
	Write-Host "PSGallery present, checking NuGet"

} else {

	try {
		Register-PSRepository -Name "PSGallery" –SourceLocation "https://www.powershellgallery.com/api/v2/" -InstallationPolicy Trusted
		Write-Host "PSGallery registration submitted, checking NuGet"
	}
	catch [Exception]{
		$_.message
		Write-Host "problem with gallery registration"
		Start-Sleep -Seconds 10
		exit
	}
}


################################################################
## Make sure Required Windows capabilities are present
################################################################

if ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId) {
	"Server 2016  / Windows 10 or newer"
	"Installing RSAT commands only work on windows server 2016 or windows 10"
	Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
	Add-WindowsCapability -Online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
	Add-WindowsCapability –online –Name 'Rsat.Dns.Tools~~~~0.0.1.0'
	Add-WindowsCapability -Online -Name 'Rsat.ServerManager.Tools~~~~0.0.1.0'
} else {
	"2012R2 or older. Installing any missing features"
	Get-WindowsFeature | Sort-Object -Property name | Where-Object { (($_.Name -like "Rsat-DNS*") -or ($_.Name -like "Rsat-AD-Tools") -or ($_.Name -like "GPMC")) -and ($_.InstallState -eq "Available") } | add-WindowsFeature
}


<#
# install the required feature(s)
@(
    'RSAT.ServerManager.Tools*' 
    'RSAT.ActiveDirectory.DS-LDS.Tools*'
    'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
    'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
    'Rsat.Dns.Tools~~~~0.0.1.0' 
) |
    ForEach-Object { Get-WindowsCapability -Name $_ -Online } |
    ForEach-Object { Add-WindowsCapability -Name $_.Name -Online }


# (optional) Display the features
Get-WindowsCapability -Name 'RSAT.*' -Online | 
    Sort-Object State, Name |
    Format-Table Name, State, DisplayName -AutoSize

    #>


################################################################
## Make sure the package provider is installed, if not, fix it
################################################################

if ((Get-PackageProvider -Name NuGet).version -lt 2.8.5.201) {
	try {
		Write-Host "NuGet missing, installing"
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$False -Force
	}
	catch [Exception]{
		$_.message
		Start-Sleep -Seconds 10
		exit
	}
}
else {
	Write-Host "Version of NuGet installed = " (Get-PackageProvider -Name NuGet).version
}

Write-Host 'Gallery & NuGet check complete, installing modules'

#Let's run the report and see what we find!
#Install-module PesterInfrastructureTests -Force -AllowClobber -SkipPublisherCheck
#Write-Host 'Pester done, Testimo next'
#Test-ADPester #Original, non Testimo command


#Just install the latest script every time since it's actively developed, as is pester.
Install-Module Testimo -Force -AllowClobber
Write-Host 'Testimo install done'


# Make a powershell in window report
#Invoke-Testimo -ReturnResults
Write-Host 'Running Testimo report'

#Make a long fancy html report! This snippet was pulled from the evotec description page
#Invoke-Testimo -Sources ForestRoles,DomainRoles -ReturnResults -ExtendedResults


$Sources = @(
	'ForestRoles'
	'ForestOptionalFeatures'
	'ForestOrphanedAdmins'
	'DomainPasswordComplexity'
	#'DomainKerberosAccountAge'
	'DomainDNSScavengingForPrimaryDNSServer'
	'DomainSysVolDFSR'
	'DCRDPSecurity'
	'DCSMBShares'
	#'DomainGroupPolicyMissingPermissions'
	'DCWindowsRolesAndFeatures'
	'DCNTDSParameters'
	'DCInformation'
	'ForestReplicationStatus'
)

Invoke-Testimo -ReturnResults -ExtendedResults -Sources $Sources #-ExcludeDomains 'ad.evotec.pl' #-ExcludeDomainControllers $ExludeDomainControllers



#no longer needed, reports output HTML natively

#$TestResults = Invoke-Testimo -ReturnResults -ExtendedResults -Sources $Sources #-ExcludeDomains 'ad.evotec.pl' #-ExcludeDomainControllers $ExludeDomainControllers
<#New-HTML -FilePath $PSScriptRoot\Output\TestimoSummary.html -UseCssLinks -UseJavaScriptLinks {
	[array]$PassedTests = $TestResults['Results'] | Where-Object { $_.Status -eq $true }
	[array]$FailedTests = $TestResults['Results'] | Where-Object { $_.Status -ne $true }
	New-HTMLTab -Name 'Summary' -IconBrands galactic-senate {
		New-HTMLSection -HeaderText "Tests results" -HeaderBackGroundColor DarkGray {
			New-HTMLPanel {
				New-HTMLChart {
					New-ChartPie -Name 'Passed' -Value ($TestResults['Summary'].Passed) -Color ForestGreen
					New-ChartPie -Name 'Failed' -Value ($TestResults['Summary'].Failed) -Color OrangeRed
					New-ChartPie -Name 'Failed' -Value ($TestResults['Summary'].Skipped) -Color LightBlue
				}
				New-HTMLTable -DataTable $TestResults['Summary'] -HideFooter -DisableSearch {
					New-HTMLTableContent -ColumnName 'Passed' -BackgroundColor ForestGreen -Color White
					New-HTMLTableContent -ColumnName 'Failed' -BackgroundColor OrangeRed -Color White
					New-HTMLTableContent -ColumnName 'Skipped' -BackgroundColor LightBlue -Color White
				}
			}
			New-HTMLPanel {
				New-HTMLTable -DataTable $TestResults['Results'] {
					New-HTMLTableCondition -Name 'Status' -Value $true -Color Green -Row
					New-HTMLTableCondition -Name 'Status' -Value $false -Color Red -Row
				}
			}
		}
	}
	New-HTMLTab -Name 'Forest' -IconBrands first-order {
		foreach ($Source in $TestResults['Forest']['Tests'].Keys) {
			$Name = $TestResults['Forest']['Tests'][$Source]['Name']
			$Data = $TestResults['Forest']['Tests'][$Source]['Data']
			$SourceCode = $TestResults['Forest']['Tests'][$Source]['SourceCode']
			$Results = $TestResults['Forest']['Tests'][$Source]['Results']
			#$Details = $TestResults['Forest']['Tests'][$Source]['Details']
			[array]$PassedTestsSingular = $TestResults['Forest']['Tests'][$Source]['Results'] | Where-Object { $_.Status -eq $true }
			[array]$FailedTestsSingular = $TestResults['Forest']['Tests'][$Source]['Results'] | Where-Object { $_.Status -ne $true }
			New-HTMLSection -HeaderText $Name -HeaderBackGroundColor DarkGray -CanCollapse {
				New-HTMLContainer {
					New-HTMLPanel {
						New-HTMLChart {
							New-ChartPie -Name 'Passed' -Value ($PassedTestsSingular.Count) -Color ForestGreen
							New-ChartPie -Name 'Failed' -Value ($FailedTestsSingular.Count) -Color OrangeRed
						}
						New-HTMLCodeBlock -Code $SourceCode -Style 'PowerShell' -Theme enlighter
					}
				}
				New-HTMLContainer {
					New-HTMLPanel {
						New-HTMLTable -DataTable $Data
						New-HTMLTable -DataTable $Results {
							New-HTMLTableCondition -Name 'Status' -Value $true -Color Green -Row
							New-HTMLTableCondition -Name 'Status' -Value $false -Color Red -Row
						}
					}
				}
			}
		}
	}
	foreach ($Domain in $TestResults['Domains'].Keys) {
		New-HTMLTab -Name "Domain $Domain" -IconBrands deskpro {
			foreach ($Source in $TestResults['Domains'][$Domain]['Tests'].Keys) {
				$Name = $TestResults['Domains'][$Domain]['Tests'][$Source]['Name']
				$Data = $TestResults['Domains'][$Domain]['Tests'][$Source]['Data']
				$SourceCode = $TestResults['Domains'][$Domain]['Tests'][$Source]['SourceCode']
				$Results = $TestResults['Domains'][$Domain]['Tests'][$Source]['Results']
				# $Details = $TestResults['Domains'][$Domain]['Tests'][$Source]['Details']
				[array]$PassedTestsSingular = $TestResults['Domains'][$Domain]['Tests'][$Source]['Results'] | Where-Object { $_.Status -eq $true }
				[array]$FailedTestsSingular = $TestResults['Domains'][$Domain]['Tests'][$Source]['Results'] | Where-Object { $_.Status -ne $true }
				New-HTMLSection -HeaderText $Name -HeaderBackGroundColor DarkGray -CanCollapse {
					New-HTMLContainer {
						New-HTMLPanel {
							New-HTMLChart {
								New-ChartPie -Name 'Passed' -Value ($PassedTestsSingular.Count) -Color ForestGreen
								New-ChartPie -Name 'Failed' -Value ($FailedTestsSingular.Count) -Color OrangeRed
							}
							New-HTMLCodeBlock -Code $SourceCode -Style 'PowerShell' -Theme enlighter
						}
					}
					New-HTMLContainer {
						New-HTMLPanel {
							New-HTMLTable -DataTable $Data
							New-HTMLTable -DataTable $Results {
								New-HTMLTableCondition -Name 'Status' -Value $true -Color Green -Row
								New-HTMLTableCondition -Name 'Status' -Value $false -Color Red -Row
							}
						}
					}
				}
			}
			foreach ($DC in $TestResults['Domains'][$Domain]['DomainControllers'].Keys) {
				New-HTMLSection -HeaderText "Domain Controller - $DC" -HeaderBackGroundColor DarkSlateGray -CanCollapse {
					New-HTMLContainer {
						foreach ($Source in $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'].Keys) {
							$Name = $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'][$Source]['Name']
							$Data = $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'][$Source]['Data']
							$SourceCode = $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'][$Source]['SourceCode']
							$Results = $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'][$Source]['Results']
							#$Details = $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'][$Source]['Details']
							[array]$PassedTestsSingular = $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'][$Source]['Results'] | Where-Object { $_.Status -eq $true }
							[array]$FailedTestsSingular = $TestResults['Domains'][$Domain]['DomainControllers'][$DC]['Tests'][$Source]['Results'] | Where-Object { $_.Status -ne $true }
							New-HTMLSection -HeaderText $Name -HeaderBackGroundColor DarkGray {
								New-HTMLContainer {
									New-HTMLPanel {
										New-HTMLChart {
											New-ChartPie -Name 'Passed' -Value ($PassedTestsSingular.Count) -Color ForestGreen
											New-ChartPie -Name 'Failed' -Value ($FailedTestsSingular.Count) -Color OrangeRed
										}
										New-HTMLCodeBlock -Code $SourceCode -Style 'PowerShell' -Theme enlighter
									}
								}
								New-HTMLContainer {
									New-HTMLPanel {
										New-HTMLTable -DataTable $Data
										New-HTMLTable -DataTable $Results {
											New-HTMLTableCondition -Name 'Status' -Value $true -Color Green -Row
											New-HTMLTableCondition -Name 'Status' -Value $false -Color Red -Row
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
} -ShowHTML

#>