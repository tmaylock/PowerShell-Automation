
$wsus_server = 'WSUS_Server'

Function Get-WindowsUpdateTotals {
      
    $SCCMUpdates = @'
insert into metrics.running_totals (
    --noncompliant
select now()::date,site,'WindowsUpdates-NonCompliant' as metric, count(device) as value from (
select distinct device,site
from sccm.client_update_details 
join "ActiveDirectory".computers on device = name
where status = 2 
and enabled = 'True'
) noncompliant
group by site
union all
--compliant
select now()::date,site,'WindowsUpdates-Compliant' as metric, count(device) as value from (
select distinct device,site
from sccm.client_update_details 
join "ActiveDirectory".computers on device = name
where status = 3 
and device not in (select distinct device from sccm.client_update_details where status = 2)
and enabled = 'True'
) compliant
group by site
order by site
   ) on conflict (time,site,metric) DO UPDATE SET value=EXCLUDED.value;
'@


    try {
        Invoke-PGSqlQuery -Type Select -Query $SCCMUpdates
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-WindowsServerUpdateTotals {


    $WindowsServerUpdateTotals = @'
	insert into metrics.running_totals (
         select now()::date, server_updates_per_device.site, 'WSUS-Servers-NonCompliant' as metric,count(distinct computername) as value
from wsus.server_updates_per_device
inner join "ActiveDirectory".computers on server_updates_per_device.computername = computers.name
where (downloaded != 0 or missing != 0 or pendingreboot != 0) and enabled = 'True' and server_updates_per_device.site != 'All Computers'
group by server_updates_per_device.site
		) on conflict (time,site,metric) DO UPDATE SET value=EXCLUDED.value;
'@
    
    try {
        Invoke-PGSqlQuery -Type Select -Query $WindowsServerUpdateTotals
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Update-ServerUpdateDetails {

    $serverupdatedetailsquery = @"
    SELECT        
    UPPER(REPLACE([SUSDB].[PUBLIC_VIEWS].[vComputerTarget].[Name],'$dns_suffix','')) as Name,
    SUSDB.PUBLIC_VIEWS.vComputerTarget.LastReportedStatusTime, 
    SUSDB.PUBLIC_VIEWS.vUpdate.DefaultTitle as Title,
    CASE WHEN State = 5 then 1 else state end as 'State',
    SUSDB.PUBLIC_VIEWS.vUpdate.InstallationRebootBehavior,
    SUSDB.PUBLIC_VIEWS.vUpdateApproval.Action,
    [SUSDB].[dbo].[tbTargetGroup].[Name] as Site,
    SUSDB.PUBLIC_VIEWS.vUpdate.UpdateId,
    KnowledgebaseArticle
    FROM SUSDB.PUBLIC_VIEWS.vUpdateInstallationInfo INNER JOIN
    SUSDB.PUBLIC_VIEWS.vComputerTarget ON SUSDB.PUBLIC_VIEWS.vUpdateInstallationInfo.ComputerTargetId = SUSDB.PUBLIC_VIEWS.vComputerTarget.ComputerTargetId FULL OUTER JOIN
    SUSDB.PUBLIC_VIEWS.vUpdateEffectiveApprovalPerComputer ON 
    SUSDB.PUBLIC_VIEWS.vUpdateEffectiveApprovalPerComputer.ComputerTargetId = SUSDB.PUBLIC_VIEWS.vUpdateInstallationInfo.ComputerTargetId AND 
    SUSDB.PUBLIC_VIEWS.vUpdateEffectiveApprovalPerComputer.UpdateId = SUSDB.PUBLIC_VIEWS.vUpdateInstallationInfo.UpdateId FULL OUTER JOIN
    SUSDB.PUBLIC_VIEWS.vUpdateApproval ON SUSDB.PUBLIC_VIEWS.vUpdateApproval.UpdateApprovalId = SUSDB.PUBLIC_VIEWS.vUpdateEffectiveApprovalPerComputer.UpdateApprovalId FULL OUTER JOIN
    SUSDB.dbo.tbTargetGroup ON SUSDB.PUBLIC_VIEWS.vUpdateApproval.ComputerTargetGroupId = SUSDB.dbo.tbTargetGroup.TargetGroupID INNER JOIN
    SUSDB.PUBLIC_VIEWS.vUpdate ON SUSDB.PUBLIC_VIEWS.vUpdateInstallationInfo.UpdateId = SUSDB.PUBLIC_VIEWS.vUpdate.UpdateId AND 
    SUSDB.PUBLIC_VIEWS.vUpdate.ClassificationId != 'E0789628-CE08-4437-BE74-2495B842F43B'
    WHERE        (SUSDB.PUBLIC_VIEWS.vUpdateApproval.Action = 'Install') AND (SUSDB.PUBLIC_VIEWS.vUpdateInstallationInfo.State NOT IN ('0', '1'))
"@
    
    $updatedetails = Invoke-Sqlcmd -Query $serverupdatedetailsquery -Database SUSDB -ServerInstance $wsus_server\SQLEXPRESS
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $updatedetails -OnConflict 'Do Nothing' -Schema 'wsus' -Table 'server_update_details' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}
    
    
Function Update-ServerUpdatesPerDevice {
    
    $ServerUpdatesPerDevicequery = @"
        SELECT 
        UPPER(REPLACE([SUSDB].[PUBLIC_VIEWS].[vComputerTarget].[Name],'$dns_suffix','')) as ComputerName
        ,SUM (CASE WHEN [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[State] = '2' then 1 else 0 end) as Missing
        ,SUM (CASE WHEN [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[State] = '3' then 1 else 0 end) as Downloaded
        ,SUM (CASE WHEN [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[State] = '6' then 1 else 0 end) as 'PendingReboot'
        ,[SUSDB].[dbo].[tbTargetGroup].[Name] as Site
    FROM [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo]
    INNER JOIN [SUSDB].[PUBLIC_VIEWS].[vComputerTarget] ON ([SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[ComputerTargetId] = [SUSDB].[PUBLIC_VIEWS].[vComputerTarget].[ComputerTargetId])
    INNER JOIN [SUSDB].[PUBLIC_VIEWS].[vUpdate] ON vUpdateInstallationInfo.UpdateId = [SUSDB].[PUBLIC_VIEWS].[vUpdate].UpdateId
    Full Outer JOIN [SUSDB].[PUBLIC_VIEWS].[vUpdateEffectiveApprovalPerComputer] ON
      ([SUSDB].[PUBLIC_VIEWS].[vUpdateEffectiveApprovalPerComputer].[ComputerTargetId] = [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[ComputerTargetId] 
      and	
      [SUSDB].[PUBLIC_VIEWS].[vUpdateEffectiveApprovalPerComputer].[UpdateId] = [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[UpdateId]
    )
    Full Outer JOIN [SUSDB].[PUBLIC_VIEWS].[vUpdateApproval] ON ([SUSDB].[PUBLIC_VIEWS].[vUpdateApproval].[UpdateApprovalId] = [SUSDB].[PUBLIC_VIEWS].[vUpdateEffectiveApprovalPerComputer].UpdateApprovalId )
    Full Outer JOIN [SUSDB].[dbo].[tbTargetGroup] ON [SUSDB].[PUBLIC_VIEWS].[vUpdateApproval].[ComputerTargetGroupId]=[SUSDB].[dbo].[tbTargetGroup].[TargetGroupID]
    Where Action = 'Install'  and state NOT IN ('0','1')  and ClassificationId != 'E0789628-CE08-4437-BE74-2495B842F43B' and [SUSDB].[dbo].[tbTargetGroup].[Name] != 'All Computers'
    group by [SUSDB].[PUBLIC_VIEWS].[vComputerTarget].[Name],[SUSDB].[dbo].[tbTargetGroup].[Name]
"@
        
    $ServerUpdatesPerDevice = Invoke-Sqlcmd -Query $ServerUpdatesPerDevicequery -Database SUSDB -ServerInstance $wsus_server\SQLEXPRESS
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $ServerUpdatesPerDevice -OnConflict 'Do Nothing' -Schema 'wsus' -Table 'server_updates_per_device' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}
    

Function Invoke-WSUSScheduledFunction {
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
            Write-Output 'Update-ServerUpdatesPerDevice'; Update-ServerUpdatesPerDevice
            Write-Output 'Get-WindowsUpdateTotals'; Get-WindowsUpdateTotals
            Write-Output 'Get-WindowsServerUpdateTotals'; Get-WindowsServerUpdateTotals
            Write-Output 'Update-ServerUpdateDetails'; Update-ServerUpdateDetails

        }
        'Daily' {
            
        }
    }
 
}








