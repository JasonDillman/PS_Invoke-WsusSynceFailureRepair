<#     
.SYNOPSIS      
    Runs a series of Windows Update repair commands on any computer that hasn't synchronized with WSUS within a specified threshold.

.DESCRIPTION    
    Polls all WSUS server(s) in $wsusServers, if any computers are found which have not synced status in longer than
    $syncAgeThreshold, then a series of repair commands are ran to attempt to fix the schronization issue.
    
.EXAMPLE    
    Invoke-WsusSyncFailureRepair.ps1

.NOTES
    Written by Jason Dillman on 02-14-2019
    Revision Date: 
    Rev. 1.0.0

    Changelog
    1.0.0: Date: 02-14-2019:  Script inception    

#>
<# Program Variables #>
$syncAgeThreshold = -2
$wsusServerNames = 'WSUS-SRV1', 'WSUS-SRV2'

function Test-Online {
	<#
	.SYNOPSIS
        Test connectivity to one or more computers in parallel.
    
	.DESCRIPTION
        Tests one or more computers for network connectivity.  The list is done in parallel to quickly check a large number of machines.
    
    .Notes
        Written by Jason Dillman on 3-6-2018
        Rev. 1.0
        This is a streamlined and customized version of the Test-Online function written by Dale Thompson.
        There is no throttling built into this version which will be an issue if too many computers are passed into the function.  In my
        testing performance is not an issue with 100-200 computers.
    
    .EXAMPLE
	    'Computer1','Computer2' | Test-Online -Property Name | Where-Object {$_.OnlineStatus -eq $true}
	    Tests 2 computers (named Computer1 and Computer2) and sends the names of those that are on the network down the pipeline.
    
    .INPUTS
        String
        
	.OUTPUTS
	    Same as input with the OnlineStatus property appended
	#>
	Param (
		[Parameter(
            Mandatory,
            ValueFromPipeline=$true)] 
            $computersToTest
	)
	begin {
        # Declare function variable(s)
		$Jobs = @{}
	}
	process {
		foreach ($computerName in $computersToTest) {
            $job = Test-Connection -Count 2 -ComputerName $computerName -AsJob -ErrorAction SilentlyContinue
            $jobs.add($computerName, $job)
        }
	}
	end { 
        while ($jobs.count -gt 0){
            $runningJobNames = $jobs.keys.clone()
            foreach ($runningJob in $runningJobNames){
                if ($jobs.$runningJob.State -ne 'Completed'){
                    continue
                }
                if ($jobs.$runningJob | Receive-Job | Where-Object {$_.StatusCode -eq 0} | Select-Object -First 1){
                    $output = $runningJob | Add-Member -Force -PassThru -NotePropertyName OnlineStatus -NotePropertyValue $true
                    $output
                    Remove-Job $jobs.$runningJob
                    $jobs.Remove($runningJob)
                } else {
                    $output = $runningJob | Add-Member -Force -PassThru -NotePropertyName OnlineStatus -NotePropertyValue $false
                    $output
                    Remove-Job $jobs.$runningJob
                    $jobs.Remove($runningJob)
                }
            }
            Start-Sleep -Milliseconds 200
        }
     }
} # End function Test-Online

$WsusSyncRepair = [scriptblock]::Create('
    $softwareDistribution = "C:\Windows\SoftwareDistribution"
    $catroot2 = "C:\Windows\system32\catroot2"
    [version]$osVersion = Get-WmiObject -Class "Win32_OperatingSystem" | Select -ExpandProperty "Version"
    $servicesList = Get-Service | Select-Object -ExpandProperty Name
    if ($osVersion -ge "10.0"){
        $services = "bits","wuauserv","appidsvc","cryptsvc"
    } else {
        $services = "bits","wuauserv","cryptsvc"
    }

    "Beginning Windows Update reset on $($env:COMPUTERNAME)"
    if (Test-Path "$($softwareDistribution).bak"){
        Remove-Item "$($softwareDistribution).bak" -Recurse -Force
        "Found and removed a previous SoftwareDistribution.bak"
    }
    if (Test-Path "$($catroot2).bak"){
        Remove-Item "$($catroot2).bak" -Recurse -Force
        "Found and removed a previous catroot2.bak"
    }
    if ($servicesList | Where-Object {$_ -like "RapidRecoveryAgent"}){
        $RRAgent = "RapidRecoveryAgent"
    } elseif ($servicesList | Where-Object {$_ -like "*AppAssureAgent*"}){
        $RRAgent = "AppAssureAgent"
    }
    if (($RRAgent -ne $null) -and ($(Get-Service -Name $RRAgent).Status -eq "Running")){
        Stop-Service -Name $RRAgent
        "Rapid Recovery Agent has been stopped"
    }
    Get-Service $services | Where-Object {$_.status -eq "Running"} | Stop-Service -Force
    "$services have been stopped"
    Rename-Item -Path $softwareDistribution -NewName "$($softwareDistribution).bak"
    Rename-Item -Path $catroot2 -NewName "$($catroot2).bak"
    "Windows Update folders have been renamed"
    Get-Service $services | Where-Object {$_.status -eq "Stopped"} | Start-Service
    "$services have been started"
    if ($RRAgent){
        Start-Service -Name $RRAgent
        "Rapid Recovery Agent has been started"
    }
    if ($osVersion -ge "10.0"){
        usoclient StartScan
        "Initiated usoclient StartScan"
    } else {
        wuauclt /resetauthorization /detectnow 
        wuauclt /reportnow
        "Initiated /resetauthorization /detectnow and /reportnow"
    }
    shutdown.exe /r /f /t 36000
')



<#
########################################################################################################################################################################
#######################################################################   Start of script    ###########################################################################
########################################################################################################################################################################
#>

$computersNotSyncing = $wsusServers | Foreach-Object {Get-WsusServer -Name $_ -PortNumber 8530} | 
    Foreach-Object {Get-WsusComputer -UpdateServer $_} | 
        Where-Object {$_.LastReportedStatusTime -lt $((Get-Date).AddDays($syncAgeThreshold)) -and $_.IPAddress -notlike '10.0.*'} | 
            Where-Object {
                Foreach-Object {
                    Test-Online $_.FullDomainName | Where-Object {$_.OnlineStatus -eq $true}
                }
            }

Invoke-Command -ComputerName $($computersNotSyncing.FullDomainName) -ScriptBlock $WsusSyncRepair