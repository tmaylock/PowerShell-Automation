

<#
ncat from nmap is required for calling cmk livestatus

https://nmap.org/dist/nmap-7.92-setup.exe
#>
Function Get-CMKServices {

    $service_stats = "GET services`n"`
        + "Columns: acknowledged check_command check_type checks_enabled current_notification_number description display_name hard_state has_been_checked host_name host_state  last_state last_state_change scheduled_downtime_depth staleness state plugin_output`n"`
        + "OutputFormat: csv`n"`
        + "Separators: 10 94 44 124`n"`
        + "ColumnHeaders: on`n"

    $servers = @(
        'server1',
        'server2',
        'server3'
    )

    $allservices = $servers | ForEach-Object -ThrottleLimit 3 -Parallel {
        $ssl = '--ssl'
        Write-Output $using:service_stats + "`n" | & "$rootdir\Binaries\nmap-7.92\ncat.exe" $ssl $_ 6557 -w 60 | ConvertFrom-Csv -Delimiter '^'
    } 

    $properties = @(
        'acknowledged',
        'check_command',
        'check_type',
        'checks_enabled',
        'current_notification_number',
        'description',
        'display_name',
        'hard_state',
        'has_been_checked',
        'host_name',
        'host_state',
        'last_state',
        @{name = 'last_state_change'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_state_change)) } },
        'scheduled_downtime_depth',
        'staleness',
        'state',
        'plugin_output'
    )

    $inputobject = $allservices.Where({ $null -ne $_.display_name -and $null -ne $_.host_name  }) | Select-Object -Property $properties 

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'checkmk' -Table 'services' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}
Function Get-CMKHosts {

    $host_stats = "GET hosts`n"`
        + "Columns: acknowledged address alias contacts contact_groups current_notification_number display_name execution_time filename hard_state has_been_checked last_check last_hard_state last_hard_state_change last_notification last_state last_state_change last_time_down last_time_unreachable last_time_up name num_services num_services_crit num_services_hard_crit num_services_hard_ok num_services_hard_unknown num_services_hard_warn num_services_ok num_services_pending num_services_unknown num_services_warn state staleness plugin_output`n"`
        + "OutputFormat: csv`n"`
        + "Separators: 10 94 44 124`n"`
        + "ColumnHeaders: on`n"

    $servers = @(
        'server1',
        'server2',
        'server3'
    )

    $allhosts = $servers | ForEach-Object -ThrottleLimit 3 -Parallel {
        $ssl = '--ssl'
        Write-Output $using:host_stats + "`n" | & "$rootdir\Binaries\nmap-7.92\ncat.exe" $ssl $_ 6557 -w 60 | ConvertFrom-Csv -Delimiter '^'
    }

    $properties = @(
        'acknowledged',
        @{name = 'address'; expression = { if ($ipv4grok.IsMatch($_.address)) { $_.address } else { (Resolve-DnsName -Name $_.Address -Type A -DnsOnly -Server $domain_controller -ErrorAction SilentlyContinue)[0].IPAddress } } },
        'alias',
        'contacts',
        'contact_groups',
        'current_notification_number',
        'display_name',
        'execution_time',
        'filename',
        'hard_state',
        'has_been_checked',
        @{name = 'last_check'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_check)) } },
        'last_hard_state',
        @{name = 'last_hard_state_change'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_hard_state_change)) } },
        @{name = 'last_notification'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_notification)) } },
        'last_state',
        @{name = 'last_state_change'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_state_change)) } },
        @{name = 'last_time_down'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_time_down)) } },
        @{name = 'last_time_unreachable'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_time_unreachable)) } },
        @{name = 'last_time_up'; expression = { [datetime]'1970-01-01 00:00:00.000Z' + ([TimeSpan]::FromSeconds($_.last_time_up)) } },
        'name',
        'num_services',
        'num_services_crit',
        'num_services_hard_crit',
        'num_services_hard_ok',
        'num_services_hard_unknown',
        'num_services_hard_warn',
        'num_services_ok',
        'num_services_pending',
        'num_services_unknown',
        'num_services_warn',
        'state',
        'staleness',
        'plugin_output'
    )

    $inputobject = $allhosts.Where({ $null -ne $_.filename } ) | Select-Object -Property $properties
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'checkmk' -Table 'hosts' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Invoke-CheckMKScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )
    switch ($Schedule) {
        '15Minute' {
            
            Write-Output 'Get-CMKServices'; Get-CMKServices
            Write-Output 'Get-CMKHosts'; Get-CMKHosts
        }
        'Hourly' {
        }
        'Daily' {
  
        }
    }
  
}








