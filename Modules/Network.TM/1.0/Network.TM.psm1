Function Get-RouterInfoCSV {
    $csv = Import-Csv -Path E:\PowerShell\Inbox\Ansible_Export\all_cisco_router_ios_information.csv

    $properties = @(
        @{name = 'hostname'; expression = { $_.hostname } },
        @{name = 'model'; expression = { $_.model } },
        @{name = 'serial'; expression = { $_.serial } },
        @{name = 'current_version'; expression = { $_.current_version } },
        @{name = 'target_ver'; expression = { $_.target_ver } },
        @{name = 'at_latest'; expression = { $_.at_latest } },
        @{name = 'free_flash'; expression = { [long]$_.free_flash } },
        @{name = 'firmware_size'; expression = { [long]$_.firmware_size } },
        @{name = 'firmware_filename'; expression = { $_.firmware_filename } },
        @{name = 'firmware_hash'; expression = { $_.firmware_hash } },
        @{name = 'int1_ip'; expression = { $_.int1_ip.trim() } },
        @{name = 'int2_ip'; expression = { $_.int2_ip.trim() } },
        @{name = 'std_user_cfg'; expression = { $_.std_user_cfg } },
        @{name = 'num_users'; expression = { [int]$_.num_users } },
        @{name = 'ntp_synced'; expression = { $_.ntp_synced } },
        @{name = 'snmp_loc'; expression = { $_.snmp_loc } },
        @{name = 'current_boot'; expression = { $_.current_boot } },
        @{name = 'last_update'; expression = { [datetime]$_.last_update.Insert(4, '-').Insert(7, '-') } }
    )

    $inputobject = $csv | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'network' -Table 'router_info' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}


Function Invoke-NetworkScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )
    
    switch ($Schedule) {
        '15Minute' {}
        'Hourly' { 
            Write-Output 'Get-RouterInfoCSV'; Get-RouterInfoCSV
        }
        'Daily' {
        }
    }
   
}



