Function Invoke-DataCollection {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )

    #Get-Command -name "Invoke-*ScheduledFunction"

    Start-ThreadJob -Name 'Invoke-ADScheduledFunction'               -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-ADScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-AzureScheduledFunction'            -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-AzureScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-CheckMKScheduledFunction'          -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-CheckMKScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-CheckPointScheduledFunction'       -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-CheckPointScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-CVScheduledFunction'               -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-CVScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-DFEScheduledFunction'              -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-DFEScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-GrafanaScheduledFunction'          -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-GrafanaScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-MetricsScheduledFunction'          -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-MetricsScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-MSGraphScheduledFunction'          -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-MSGraphScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-MSGraphReportsScheduledFunction'   -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-MSGraphReportsScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-NetworkScheduledFunction'          -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-NetworkScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-O365ScheduledFunction'             -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-O365ScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-OMEScheduledFunction'              -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-OMEScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-PlannerScheduledFunction'          -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-PlannerScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-PowerAutomateScheduledFunction'    -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-PowerAutomateScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-SCCMScheduledFunction'             -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-SCCMScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-SentinelScheduledFunction'         -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-SentinelScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-SharepointScheduledFunction'       -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-SharepointScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-QualysScheduledFunction'           -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-QualysScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-WSUSScheduledFunction'             -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-WSUSScheduledFunction -Schedule $Schedule }
    
    Start-ThreadJob -Name 'Invoke-ComplianceScheduledFunction'       -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-ComplianceScheduledFunction -Schedule $Schedule }
    Start-ThreadJob -Name 'Invoke-SwitchesScheduledFunction'         -ThrottleLimit 5 -ArgumentList "$Schedule"  -ScriptBlock { param($Schedule) Invoke-SwitchesScheduledFunction -Schedule $Schedule }


    Get-Job | Wait-Job -Force

    $properties = @(
        "instanceid",
        "name",
        "state",
        "hasmoredata",
        @{Name='output';Expression={$_.Output | ConvertTo-Json -WarningAction SilentlyContinue}},
        @{Name='psbegintime';Expression={([datetime]$_.psbegintime).ToUniversalTime()}},
        @{Name='psendtime';Expression={([datetime]$_.psendtime).ToUniversalTime()}},
        @{Name='error';Expression={$_.Error | ConvertTo-Json -WarningAction SilentlyContinue}},
        @{Name='warning';Expression={$_.Warning | ConvertTo-Json -WarningAction SilentlyContinue}},
        @{Name='Schedule';Expression={$Schedule}}
    )
    $jobs = Get-Job | Select-Object -Property $properties
    Invoke-PGSqlQuery -Type Insert -InputObject $jobs -Schema 'public' -Table 'threadjob_log' -OnConflict 'Do Nothing' -Truncate $false

    Get-Job | Remove-Job -Force



}