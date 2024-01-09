

Function Get-IntuneDeviceTotals {
    $query = @'
	insert into metrics.running_totals (
         select now()::date, site, 'intune_mdm' as metric, count(*) as value
    FROM "MSGraph".intunemanageddevices 
    join "Office365".userid on intunemanageddevices.userid = userid.id
    join "ActiveDirectory".users on lower(userid.userprincipalname) = lower(users.userprincipalname)
    where managementagent in ('mdm','googleCloudDevicePolicyController')
    group by site
		) on conflict (time,site,metric) DO UPDATE SET value=EXCLUDED.value;
'@

     try {
            Invoke-PGSqlQuery -Type Select -Query $query 
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    
}



Function Invoke-MetricsScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )  
    switch ($Schedule) {
        '15Minute' {
        }
        'Hourly' {
            Write-Output "Get-IntuneDeviceTotals"; Get-IntuneDeviceTotals
        }
        'Daily' {
        }
    }
 
}






