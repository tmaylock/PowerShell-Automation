Function Connect-SCCM {
 
    #Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"
    #Import-Module 'C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\ConfigurationManager.psd1' 
    Import-Module ConfigurationManager


    if ($null -eq (Get-PSDrive -Name $sccm_site -PSProvider CMSite -ErrorAction SilentlyContinue) ) {
        New-PSDrive -Name $sccm_site -PSProvider CMSite -Root $sccm_server
    }

    Set-Location "$($sccm_site):\"

}




Function Get-SCCMDevices {

    
    

    $cmdevices = Get-CMDevice -Fast | Select-Object name, clienttype, adsitename, resourceid 
    $inputobject = $cmdevices | Select-Object name, @{name = 'clienttype'; expression = { if ($_.clienttype -eq 1) { '1' }else { '0' } } }, adsitename, resourceid


    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'sccm' -Table 'computers' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-SCCMClientNetworkInfo {
    $query = @"

    SELECT vSMS_R_System.Name0 as name
    ,v_GS_NETWORK_ADAPTER.Name0 as adaptername
          ,[IPAddress0] as ipaddress
          ,[IPSubnet0] as ipsubnet
          ,v_GS_NETWORK_ADAPTER_CONFIGURATION.MACAddress0 as macaddress
          ,[DefaultIPGateway0] as defaultgateway
          ,[DNSDomain0] as dnsdomain
          ,[DNSHostName0] as dnshostname
          ,[DHCPEnabled0] as dhcpenabled
          ,[DHCPServer0] as dhcpserver
      FROM [CM_$sccm_site].[dbo].[v_GS_NETWORK_ADAPTER_CONFIGURATION]
      join v_GS_NETWORK_ADAPTER on v_GS_NETWORK_ADAPTER_CONFIGURATION.ResourceID =  v_GS_NETWORK_ADAPTER.ResourceID
      and v_GS_NETWORK_ADAPTER_CONFIGURATION.MACAddress0 =  v_GS_NETWORK_ADAPTER.MACAddress0
      join vSMS_R_System on v_GS_NETWORK_ADAPTER_CONFIGURATION.ResourceID = vSMS_R_System.ItemKey
      where IPAddress0 is not null
"@

    $Properties = @(
        'name',
        'adaptername',
        @{Name = 'ipaddress'; Expression = { ($_.ipaddress).Split(',')[0] } },
        @{Name = 'ipsubnet'; Expression = { ($_.ipsubnet).Split(',')[0] } },
        'macaddress',
        @{Name = 'defaultgateway'; Expression = { ($_.defaultgateway).Split(',')[0] } },
        'dnsdomain',
        'dnshostname',
        'dhcpenabled',
        'dhcpserver'
    )

    $ClientNetworkInfo = Invoke-Sqlcmd -server $sccm_server -Database "CM_$sccm_site" -Query $query | Select-Object -Property $Properties | Where-Object { $_.ipaddress -match $ipv4grok }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $ClientNetworkInfo -OnConflict 'Do Nothing' -Schema 'sccm' -Table 'clientnetworkinfo' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Remove-SCCMInactiveDevices {

    $adcomputers = Get-ADComputer -Filter * -Server $domain_controller -Properties OperatingSystem | Select-Object name, operatingsystem, enabled
    $disabled = $adcomputers | Where-Object { $_.Enabled -eq $false }
    $cmdevices = Get-CMDevice -CollectionName 'All Systems' -Fast | Select-Object Name
    $dccdevices = Get-CMDevice -CollectionName 'Dell Connected Config - Deployment' -Fast | Select-Object Name
    
    $cmdevices = Compare-Object -ReferenceObject $cmdevices -DifferenceObject $dccdevices -Property name -PassThru -IncludeEqual | Where-Object { $_.SideIndicator -ne '==' }
    $deletedcomputers = Compare-Object -ReferenceObject $adcomputers -DifferenceObject $cmdevices -Property Name | Where-Object { $_.SideIndicator -eq '=>' }
    $disabledcomputers = Compare-Object -ReferenceObject $cmdevices -DifferenceObject $disabled -IncludeEqual -ExcludeDifferent -Property Name
    
    $deletedcomputers = $deletedcomputers | Where-Object { $_.name -notin ('Provisioning Device (Provisioning Device)', 'x64 Unknown Computer (x64 Unknown Computer)', 'x86 Unknown Computer (x86 Unknown Computer)') }
    
    #Write-Host "Deleted:" $deletedcomputers.Count
    #Write-Host "Disabled:" $disabledcomputers.Count
    #Write-Host "Total:" ($deletedcomputers.Count + $disabledcomputers.Count)
    
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

    #Remove computers that aren't in AD anymore
    foreach ($computer in $deletedcomputers) {
        Remove-CMDevice -Name $computer.Name -Force 
    }
    #Remove computers that are disabled in AD
    foreach ($computer in $disabledcomputers) {
        Remove-CMDevice -Name $computer.Name -Force
    }

    Invoke-CMCollectionUpdate -Name 'Inactive Clients' -Confirm:$false
    Start-Sleep -Seconds 10
    $inactive = Get-CMDevice -CollectionName 'Inactive Clients' | Where-Object { $_.LastActiveTime -lt (Get-Date).AddDays(-30) }
    foreach ($computer in $inactive) {
        Remove-CMDevice -Name $computer.Name -Force
    }
}


<#
All of the Dell Warranty information requires the Dell Command | Integration Suite for System Center
https://www.dell.com/support/kbdoc/en-us/000178049/dell-command-integration-suite-for-microsoft-system-center

You can automate this data pull with a scheduled task:

Program: DellWarranty-CLI.exe
Arguments: /ICS="Data Source=$SCCM_Server;Database=CM_$Site_Site;Integrated Security=true;" /OCS="Data Source=$SCCM_Server;Database=DellCommandWarranty;Integrated Security=true;"
StartIn: C:\Program Files (x86)\Dell\CommandIntegrationSuite
#>

Function Get-SCCMDellAssets {
    $query = 'select * from Dell_Asset where shipdate is not null'
    $dellassets = Invoke-Sqlcmd -Query $query -ServerInstance $sccm_server -Database DellCommandWarranty
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $dellassets -OnConflict 'Do Nothing' -Schema 'sccm' -Table 'dellasset' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}
Function Get-SCCMDellAssetEntitlements {
    $query = 'SELECT * FROM [DellCommandWarranty].[dbo].[Dell_AssetEntitlements] where StartDate is not null'
    $dellAssetEntitlements = Invoke-Sqlcmd -Query $query -ServerInstance $sccm_server -Database DellCommandWarranty

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $dellAssetEntitlements -OnConflict 'Do Nothing' -Schema 'sccm' -Table 'dellassetentitlements' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}
Function Get-SCCMSerialNumbers {
    
    $query = "select distinct(v_R_System.name0) as name,
    SerialNumber0 as serialnumber
    from v_R_System
    join v_GS_SYSTEM_ENCLOSURE on v_R_System.Resourceid = v_GS_SYSTEM_ENCLOSURE.Resourceid
    where serialnumber0  != ''"
    
    $serialnumbers = Invoke-Sqlcmd -Query $query -ServerInstance $sccm_server -Database "CM_$sccm_site"

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $serialnumbers -OnConflict 'Do Nothing' -Schema 'sccm' -Table 'serialnumbers' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}
  

Function Get-SCCMF3Users {
    
    $query = 
    @" 
SELECT distinct(CONCAT('$ad_domain\',samaccountname)) as smsid
FROM `"Office365`".userid
inner join `"ActiveDirectory`".users on lower(`"Office365`".userid.userprincipalname) = lower(`"ActiveDirectory`".users.userprincipalname)
inner join `"Office365`".licensing on userid.id = licensing.userid
inner join `"Office365`".licensingsku on licensing.licenseskuid = licensingsku.skuid
where skupartnumber = 'SPE_F1' and enabled = 'True'
"@
    $f3users = Invoke-PGSqlQuery -Type Select -Query $query
    $CollectionId = $sccm_site + '001E7'
    $CollectionMembers = Get-CMCollectionMember -CollectionId $CollectionId | Select-Object smsid, resourceid
    $compare = Compare-Object @($collectionmembers) @($f3users) -Property smsid -PassThru -CaseSensitive
    $missing = $AllSCCMUsers | Where-Object { $_.smsid -cin ($compare | Where-Object { $_.sideindicator -eq '=>' }).smsid }
    $extra = $AllSCCMUsers | Where-Object { $_.smsid -cin ($compare | Where-Object { $_.sideindicator -eq '<=' }).smsid }

    if ($missing) {
        Add-CMUserCollectionDirectMembershipRule -CollectionId $CollectionId -ResourceId $missing.resourceid
    }
    if ($extra) {
        Remove-CMUserCollectionDirectMembershipRule -CollectionId $CollectionId -ResourceId $extra.resourceid -Force
    }


}


Function Get-SCCMEMSUsers {
    
    $query = @" 
SELECT distinct(CONCAT('$ad_domain',samaccountname)) as smsid
FROM `"Office365`".userid
inner join `"ActiveDirectory`".users on lower(`"Office365`".userid.userprincipalname) = lower(`"ActiveDirectory`".users.userprincipalname)
inner join `"Office365`".licensing on userid.id = licensing.userid
inner join `"Office365`".licensingsku on licensing.licenseskuid = licensingsku.skuid
where skupartnumber = 'EMS' and enabled = 'True'
"@
    $collectionid = $sccm_site + '001E6'
    $e3users = Invoke-PGSqlQuery -Type Select -Query $query
    $CollectionMembers = Get-CMCollectionMember -CollectionId $CollectionId | Select-Object smsid, resourceid
    $compare = Compare-Object @($collectionmembers) @($e3users) -Property smsid -PassThru -CaseSensitive
    $missing = $AllSCCMUsers | Where-Object { $_.smsid -cin ($compare | Where-Object { $_.sideindicator -eq '=>' }).smsid }
    $extra = $AllSCCMUsers | Where-Object { $_.smsid -cin ($compare | Where-Object { $_.sideindicator -eq '<=' }).smsid }

    if ($missing) {
        Add-CMUserCollectionDirectMembershipRule -CollectionId $CollectionId -ResourceId $missing.resourceid
    }
    if ($extra) {
        Remove-CMUserCollectionDirectMembershipRule -CollectionId $CollectionId -ResourceId $extra.resourceid -Force
    }

}

Function Get-SCCMEnterprisePackUsers {
    
    $query = @" 
SELECT distinct(CONCAT('$ad_domain\',samaccountname)) as smsid
FROM `"Office365`".userid
inner join `"ActiveDirectory`".users on lower(`"Office365`".userid.userprincipalname) = lower(`"ActiveDirectory`".users.userprincipalname)
inner join `"Office365`".licensing on userid.id = licensing.userid
inner join `"Office365`".licensingsku on licensing.licenseskuid = licensingsku.skuid
where skupartnumber = 'ENTERPRISEPACK' and enabled = 'True'
"@
    
    $enterprisepackusers = Invoke-PGSqlQuery -Type Select -Query $query
    $collectionid = $sccm_site + '001D5'
    $CollectionMembers = Get-CMCollectionMember -CollectionId $CollectionId | Select-Object smsid, resourceid
    $compare = Compare-Object @($collectionmembers) @($enterprisepackusers) -Property smsid -PassThru -CaseSensitive
    $missing = $AllSCCMUsers | Where-Object { $_.smsid -cin ($compare | Where-Object { $_.sideindicator -eq '=>' }).smsid }
    $extra = $AllSCCMUsers | Where-Object { $_.smsid -cin ($compare | Where-Object { $_.sideindicator -eq '<=' }).smsid }

    if ($missing) {
        Add-CMUserCollectionDirectMembershipRule -CollectionId $CollectionId -ResourceId $missing.resourceid
    }
    if ($extra) {
        Remove-CMUserCollectionDirectMembershipRule -CollectionId $CollectionId -ResourceId $extra.resourceid -Force
    }
}



Function Get-SCCMClientUpdateDetails {
    $query = @'
    select name0 as device
    ,user_name0 as username
    ,upd.title
    --,upd.IsDeployed
    --,upd.IsSuperseded
    --,upd.CIType_ID
    , x.status,
	CategoryInstanceName
    from v_R_System
    join (
    select v_Update_ComplianceStatusAll.ci_id,resourceid,status,CategoryInstanceName
    from v_Update_ComplianceStatusAll 
     join v_CICategoryInfo_All cls on cls.CI_ID=v_Update_ComplianceStatusAll.CI_ID 
      where status in (2,3) 
      AND cls.CategoryInstanceID IN (16777243,16777247,16777251)
      ) x on v_R_System.Resourceid = x.ResourceID
      join (SELECT        ci.CI_ID, loc.DisplayName AS Title,IsDeployed,CIType_ID,IsSuperseded
    FROM            dbo.v_UpdateCIs AS ci 
    JOIN dbo.v_LocalizedCIProperties_SiteLoc AS loc ON loc.CI_ID = ci.CI_ID
    WHERE  ci.IsHidden = 0 and IsSuperseded = 0 and IsDeployed = 1
    ) upd on x.CI_ID =upd.CI_ID
'@
    $updatedetails = Invoke-Sqlcmd -Query $query -server $sccm_server -Database $sccm_server
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $updatedetails -OnConflict 'Do Nothing' -Schema 'sccm' -Table 'client_update_details' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Get-SCCMUpdatesPerDevice {

    $updatesperdevice_q = @'
SELECT device as "Device",username,	
0 as "Exclusion",
SUM(case when status = 3 then 1 else 0 end) as Installed,
SUM(case when status = 2 then 1 else 0 end) as Missing 
FROM sccm.client_update_details
group by device,username
'@


    $exclusionquery = @"
SELECT 
	  UPPER(trim('$dns_suffix' FROM [SUSDB].[PUBLIC_VIEWS].[vComputerTarget].[Name])) as Device
	  , "Exclusion" = 1
	  ,SUM (CASE WHEN [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[State] = '2' then 1 else 0 end) as Missing
	  ,SUM (CASE WHEN [SUSDB].[PUBLIC_VIEWS].[vUpdateInstallationInfo].[State] = '4' then 1 else 0 end) as Installed
      
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
Where Action = 'Install'  AND ClassificationId != 'E0789628-CE08-4437-BE74-2495B842F43B'
group by [SUSDB].[PUBLIC_VIEWS].[vComputerTarget].[Name]
"@
   

    try {

 
        $all = @()
        $all += Invoke-PGSqlQuery -Type Select -Query $updatesperdevice_q
        $all += Invoke-Sqlcmd -Query $exclusionquery -server 'sccm_exclusion_wsus_server' -Database 'SUSDB'

        Invoke-PGSqlQuery -Type Insert -InputObject $all -OnConflict 'Do Nothing' -Schema 'sccm' -Table 'updates_per_device' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}



Function Set-SoftwareRemovalCollection {

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $SoftwareName,
        [Parameter()]
        [ValidateSet('DfE')]
        $Source
    )
    
    

    if ($Source -eq 'DfE') {
        $query = @'
        SELECT devicename as name, numberofweaknesses,  softwarename, softwarevendor, softwareversion
	    FROM defenderatp.software_inventory_assessment
	    where numberofweaknesses > 0
'@
        $query = $query + " and softwarename = '$($SoftwareName.ToLower())'"  
    }

   
    
    $targetdevices = Invoke-PGSqlQuery -Type Select -Query $query
    
    if ($null -eq $targetdevices) {
        Write-Output "No Devices Found with $SoftwareName"
        return
    }
    $cmdevices = Get-CMDevice -CollectionName 'All Desktop Clients' -Fast | Select-Object Name, ResourceID
    $cmresources = Compare-Object -ReferenceObject @($cmdevices) -DifferenceObject @($targetdevices) -Property Name -PassThru -IncludeEqual -ExcludeDifferent


    $collection = Get-CMDeviceCollection -Name "Software Removal - $SoftwareName"

    if (!$collection) {
        New-CMDeviceCollection -Name "Software Removal - $SoftwareName" -LimitingCollectionName 'All Desktop Clients'
        Move-CMObject -FolderPath "$sccm_site`:\DeviceCollection\Software Removal" -InputObject (Get-CMDeviceCollection -Name "Software Removal - $SoftwareName")
        $collection = Get-CMDeviceCollection -Name "Software Removal - $SoftwareName"
    }

 
    $collectionmembers = Get-CMDevice -Collection $collection

    $compare = Compare-Object @($cmresources) @($collectionmembers) -Property ResourceID -IncludeEqual -PassThru
    $missing = $compare | Where-Object { $_.sideindicator -eq '<=' }
    $extra = Compare-Object @($targetdevices) @($collectionmembers) -Property name -PassThru | Where-Object { $_.SideIndicator -eq '=>' }

    
    if ($missing) {
        Add-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $missing.resourceid -WarningAction SilentlyContinue
    }
    
    if ($extra) {
        Remove-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $extra.ResourceID -Force
    }
    
}

Function Set-SCCMChromeRemovalCollection {

   
    
    
$SoftwareName = 'Google Chrome'
 

 $query = @"
select ad_name as name from defenderatp.chromeclients
"@

   
    $targetdevices = Invoke-PGSqlQuery -Type Select -Query $query
    
    if ($null -eq $targetdevices) {
        Write-Output "No Devices Found with $SoftwareName"
        return
    }
    $cmdevices = Get-CMDevice -CollectionName 'All Desktop Clients' -Fast | Select-Object Name, ResourceID
    $cmresources = Compare-Object -ReferenceObject @($cmdevices) -DifferenceObject @($targetdevices) -Property Name -PassThru -IncludeEqual -ExcludeDifferent


    $collection = Get-CMDeviceCollection -Name "Software Removal - $SoftwareName"

    $collectionmembers = Get-CMDevice -Collection $collection

    $compare = Compare-Object @($cmresources) @($collectionmembers) -Property ResourceID -IncludeEqual -PassThru
    $missing = $compare | Where-Object { $_.sideindicator -eq '<=' }
    $extra = Compare-Object @($targetdevices) @($collectionmembers) -Property name -PassThru | Where-Object { $_.SideIndicator -eq '=>' }

    
    if ($missing) {
        Add-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $missing.resourceid -WarningAction SilentlyContinue
    }
    
    if ($extra) {
        Remove-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $extra.ResourceID -Force
    }
    
}

Function Set-SCCMJreRemovalCollection {
    #remove the dns suffix to match up with AD table
    $regexp = "\.int\.mycompany\.com"
    
    $query = @"
SELECT UPPER(regexp_replace(devicename,'$regexp','')) as "Name",site
FROM defenderatp.jreclients
join "ActiveDirectory".computers on lower(regexp_replace(devicename,'$regexp','')) = lower(computers.name)
where deviceid2 is null
"@
    
    
    $targetdevices = Invoke-PGSqlQuery -Type Select -Query $query
    
    $cmdevices = Get-CMDevice -CollectionName 'Installed Software - Java' -Fast | Select-Object Name, ResourceID
    $cmresources = Compare-Object -ReferenceObject $cmdevices -DifferenceObject $targetdevices -Property Name -PassThru -IncludeEqual -ExcludeDifferent

    $collectionname = 'Jre Removal'
    $collection = Get-CMDeviceCollection -Name $collectionname

    if (!$collection) {
        New-CMDeviceCollection -Name $collectionname -LimitingCollectionName 'Installed Software - Java'
        Move-CMObject -FolderPath "$sccm_site`:\DeviceCollection\Software Removal"-InputObject (Get-CMDeviceCollection -Name $collectionname)
        $collection = Get-CMDeviceCollection -Name $collectionname
    }

  
    $collectionmembers = Get-CMDevice -Collection $collection | Select-Object Name, ResourceID

    $compare = Compare-Object $cmresources @($collectionmembers) -Property ResourceID -IncludeEqual -PassThru
    $missing = $compare | Where-Object { $_.sideindicator -eq '<=' }
    $extra = Compare-Object $targetdevices @($collectionmembers) -Property name -PassThru | Where-Object { $_.SideIndicator -eq '=>' }

    
    if ($missing) {
        Add-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $missing.resourceid
    }
    
    if ($extra) {
        Remove-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $extra.ResourceID -Force
    }


    
}

Function Set-SCCMZoomRemovalCollection {
    $query = @'
SELECT zoomclients.devicename as name
	FROM defenderatp.zoomclients
	left join (
	  SELECT devicename, numberofweaknesses,  softwarename, softwareversion
	    FROM defenderatp.software_inventory_assessment
	    where numberofweaknesses > 0 and softwarevendor = 'zoom') sia on zoomclients.devicename = sia.devicename
		where numberofweaknesses is not null and deviceid2 is null
		order by zoomclients.devicename
'@

    $targetdevices = Invoke-PGSqlQuery -Type Select -Query $query
    
    if ($null -eq $targetdevices) {
        Write-Output "No Devices Found with $SoftwareName"
        return
    }
    $cmdevices = Get-CMDevice -CollectionName 'All Desktop Clients' -Fast | Select-Object Name, ResourceID
    $cmresources = Compare-Object -ReferenceObject $cmdevices -DifferenceObject $targetdevices -Property Name -PassThru -IncludeEqual -ExcludeDifferent

    $SoftwareName = 'Zoom'

    $collection = Get-CMDeviceCollection -Name "Software Removal - $SoftwareName"

    if (!$collection) {
        New-CMDeviceCollection -Name "Software Removal - $SoftwareName" -LimitingCollectionName 'All Desktop Clients'
        Move-CMObject -FolderPath "$sccm_site`:\DeviceCollection\Software Removal" -InputObject (Get-CMDeviceCollection -Name "Software Removal - $SoftwareName")
        $collection = Get-CMDeviceCollection -Name "Software Removal - $SoftwareName"
    }


    $collectionmembers = Get-CMDevice -Collection $collection

    $compare = Compare-Object $cmresources @($collectionmembers) -Property ResourceID -IncludeEqual -PassThru
    $missing = $compare | Where-Object { $_.sideindicator -eq '<=' }
    $extra = Compare-Object $targetdevices @($collectionmembers) -Property name -PassThru | Where-Object { $_.SideIndicator -eq '=>' }

   
    if ($missing) {
        Add-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $missing.resourceid -WarningAction SilentlyContinue
    }

    if ($extra) {
        Remove-CMDeviceCollectionDirectMembershipRule -CollectionId $collection.CollectionID -ResourceId $extra.ResourceID -Force
    }

}

Function Import-DellConnectedConfigClients {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [bool]
        $DebugImport
    )
    

    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Dell Connected Config Assets' -Connection $SharePoint
    $items = Get-PnPListItem -List $list -Connection $SharePoint | Where-Object { $_.FieldValues.field_1 -eq $false }

    $computerproperties = @(
        @{name = 'ID'; expression = { $_.ID } },
        @{name = 'Dell Service Tag'; expression = { $_.Title } }, 
        @{name = 'MAC'; expression = { $_.field_17 } }, 
        @{name = 'MAC2'; expression = { $_.field_18 } },
        @{name = 'Ship City'; expression = { $_.field_27 } }, 
        @{name = 'Chassis Style'; expression = { $_.field_11 } },
        @{name = 'PassthroughMAC'; expression = { $_.field_34 } }

    )


    $Assets = $items.FieldValues | Select-Object -Property $computerproperties
    $groups = $assets | Group-Object -Property 'Ship City'

    foreach ($group in $groups) {

        $Site = (Invoke-PGSqlQuery -Type Select -Query "select site from sccm.dell_cc_cities where city = '$($Group.Name)'").Site

        if ($null -eq $site) {
            [string]$html = $group.group | ConvertTo-Html -Head $grafanatableheaders
            Send-MailMessage -Body $html -BodyAsHtml -To "tyler.maylock@$mycompany.com" -SmtpServer "smtp.$mycompany.com" -Subject "Dell CFI Ship City Missing - $($Group.Name)" -From "SCCM@$mycompany.com" -WarningAction SilentlyContinue
            break
        }
        $SCCMComputersList = Invoke-PGSqlQuery -Type Select -Query "select name from sccm.computers where name ~* '^$Site(LT|PC)\d\d\d$' order by name"
        
        foreach ($computer in $group.group) {
            if ($computer.'Chassis Style' -ne 'NOTEBOOK') {
                $computer.'Chassis Style' = 'PC'
            }
        }

        $chassisstyles = $group.group | Group-Object -Property 'Chassis Style'

        foreach ($chassis in  $chassisstyles) {
            switch ($Chassis.Name) {
                'NOTEBOOK' {  
                    [int[]] $LTNumbers = ($SCCMComputersList | Where-Object { $_.Name -match "^$Site`LT\d\d\d$" } ).Name -replace '\D'
                    $UnusedLTNumbers = Compare-Object $LTNumbers (400..999) -PassThru | Where-Object { $_ -ge 400 }
                    $UnusedLTNames = @()
                    $UnusedLTNumbers.ForEach({ $UnusedLTNames += "$Site`LT" + '{0:d3}' -f $_ })
                    [array]$SelectedNames = $UnusedLTNames | Select-Object -First ([int]$chassis.Group.count)
                }
                'PC' {
                    [int[]] $PCNumbers = ($SCCMComputersList | Where-Object { $_.Name -match "^$Site`PC\d\d\d$" } ).Name -replace '\D'
                    $UnusedPCNumbers = Compare-Object $PCNumbers (400..999) -PassThru | Where-Object { $_ -ge 400 }
                    $UnusedPCNames = @()
                    $UnusedPCNumbers.ForEach({ $UnusedPCNames += "$Site`PC" + '{0:d3}' -f $_ })
                    [array]$SelectedNames = $UnusedPCNames | Select-Object -First ([int]$chassis.Group.count)
                }
            }
            if ($SelectedNames.count -eq 0) {
                break
            }
            $computernumber = 0
            foreach ($Computer in $chassis.group) {
                $SelectedName = $SelectedNames[$computernumber]
                try {
                    if ($Computer.mac -eq 'NA' -and $Computer.mac2 -ne '' -and $computer.PassthroughMAC -ne '') { $Computer.mac = $Computer.PassthroughMAC }
                    if ($DebugImport) {
                        "Dell Connected Config - $Site - $SelectedName - $($Computer.'Dell Service Tag') - $($Computer.MAC)"
                    }
                    if ($DebugImport -eq $false) {
                        "Dell Connected Config - $Site - $SelectedName - $($Computer.MAC)"
                        Import-CMComputerInformation -CollectionName "Dell Connected Config - $Site" -ComputerName $SelectedName -Confirm:$false -MacAddress $Computer.MAC
                        Set-PnPListItem -List $list -Identity $computer.ID -Values @{'field_1' = 'True'; 'field_2' = "$SelectedName" } -Connection $SharePoint

                        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) - $SelectedName" -Severity 1 -Schedule $Schedule
                    }
                    $computernumber++
                }
                catch {
                    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
                }
                
            }
        }
    }
    if ($DebugImport -eq $false) {
        Invoke-CMCollectionUpdate -Name 'All Systems'
    }
}

Function Invoke-SCCMScheduledFunction {
    [CmdletBinding()]
    param (
        [ValidateSet('15Minute', 'Hourly', 'Daily')]
        [string]
        $Schedule
    )

    

    switch ($Schedule) {
        '15Minute' {  }
        'Hourly' {
            Connect-SCCM
            Write-Output 'Get-SCCMDevices'; Get-SCCMDevices
            Write-Output 'Get-SCCMClientUpdateDetails'; Get-SCCMClientUpdateDetails
            Write-Output 'Get-SCCMUpdatesPerDevice'; Get-SCCMUpdatesPerDevice
            Write-Output 'Import-DellConnectedConfigClients'; Import-DellConnectedConfigClients
            Write-Output 'Set-SCCMChromeRemovalCollection'; Set-SCCMChromeRemovalCollection

        }
        'Daily' {
            Connect-SCCM
            $AllSCCMUsers = Get-CMUser -CollectionName 'All Users' | Select-Object SMSID, ResourceID
            #Write-Output "Remove-SCCMInactiveDevices"; Remove-SCCMInactiveDevices
            Write-Output 'Get-SCCMDellAssets'; Get-SCCMDellAssets
            Write-Output 'Get-SCCMDellAssetEntitlements'; Get-SCCMDellAssetEntitlements
            Write-Output 'Get-SCCMSerialNumbers'; Get-SCCMSerialNumbers
            Write-Output 'Get-SCCMClientNetworkInfo'; Get-SCCMClientNetworkInfo
            Write-Output 'Get-SCCMF3Users'; Get-SCCMF3Users
            Write-Output 'Get-SCCMEMSUsers'; Get-SCCMEMSUsers
            Write-Output 'Get-SCCMEnterprisePackUsers'; Get-SCCMEnterprisePackUsers
            Write-Output "Set-SoftwareRemovalCollection -SoftwareName 'Command_Update' -Source DfE"; Set-SoftwareRemovalCollection -SoftwareName 'Command_Update' -Source DfE
            Write-Output "Set-SoftwareRemovalCollection -SoftwareName 'SupportAssist' -Source DfE"; Set-SoftwareRemovalCollection -SoftwareName 'SupportAssist' -Source DfE
            Write-Output "Set-SoftwareRemovalCollection -SoftwareName 'Teams' -Source DfE"; Set-SoftwareRemovalCollection -SoftwareName 'Teams' -Source DfE
            Write-Output "Set-SoftwareRemovalCollection -SoftwareName 'Office' -Source DfE"; Set-SoftwareRemovalCollection -SoftwareName 'Office' -Source DfE
            Write-Output 'Set-SCCMJreRemovalCollection'; Set-SCCMJreRemovalCollection
            Write-Output 'Set-SCCMZoomRemovalCollection'; Set-SCCMZoomRemovalCollection
                
        }
    }
  
}


















