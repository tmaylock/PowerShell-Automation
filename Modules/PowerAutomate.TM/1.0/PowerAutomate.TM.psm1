

Function Get-PowerAutomateFlowsandRuns {

    $cred = Get-O365Creds
    $SPSite = "https://$mycompany-admin.sharepoint.com/"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $environment = "Default-$tenantid"
    $allflows = Get-PnPFlow -AsAdmin -Environment $environment -Connection $SharePoint
    $creatorids = @() #add EntraID user ids of users you have access to, we don't want to get the runs of every flow in the org...
    $filteredflows = $allflows | Where-Object { $_.Properties.Creator.ObjectId -in $creatorids}

    $flowruns = $filteredflows | ForEach-Object -ThrottleLimit 10 -Parallel {
        Import-Module PnP.PowerShell
        $sharepoint = $using:sharepoint
        $environment = $using:environment
        $flowname = $_.name
        $flowdisplayname = $_.Properties.displayname
        $runproperties = @(
            @{Name = 'name'; Expression = { $flowname } },
            @{Name = 'displayname'; Expression = { $flowdisplayname } },
            @{Name = 'run_name'; Expression = { $_.name } },
            @{Name = 'starttime'; Expression = { $_.properties.starttime } },
            @{Name = 'endtime'; Expression = { $_.properties.endtime } },
            @{Name = 'status'; Expression = { $_.properties.status } }
        )
        if ($_.properties.state -eq 'Started') { 
            Get-PnPFlowRun -Environment $environment -Flow $_.Name -Connection $SharePoint | Select-Object -Property $runproperties 
        }
    }


    $flowproperties = @(
        'name',
        @{Name = 'displayname'; Expression = { $_.Properties.DisplayName } },
        @{Name = 'State'; Expression = { [string]$_.Properties.State } },
        @{Name = 'createdtime'; Expression = { $_.Properties.createdtime } },
        @{Name = 'lastmodifiedtime'; Expression = { $_.Properties.lastmodifiedtime } },
        @{Name = 'creator'; Expression = { $_.Properties.creator.userid } },
        @{Name = 'definitionsummary'; Expression = { $_.Properties.definitionsummary | ConvertTo-Json } }
    )

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $flowruns -OnConflict 'Do Nothing' -Schema 'powerautomate' -Table 'flow_runs' -Truncate $false
        Invoke-PGSqlQuery -Type Insert -InputObject ($allflows | Select-Object -Property $flowproperties) -OnConflict 'Do Nothing' -Schema 'powerautomate' -Table 'flows' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }


}

Function Invoke-PowerAutomateScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )
    switch ($Schedule) {
        '15Minute' {
            Write-Output 'Get-PowerAutomateFlowsandRuns'; Get-PowerAutomateFlowsandRuns
        }
        'Hourly' {
            
        }
        'Daily' {
            
        }
    }    
}

