Function Get-ExceptionTrackingList {
  $cred = Get-O365Creds
  $SPSite = "https://$mycompany.sharepoint.com/sites/site"
  $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
  $list = Get-PnPList -Identity 'Exception Tracking' -Connection $SharePoint
  $items = Get-PnPListItem -List $list -Connection $SharePoint

  $properties = @(
    @{name = 'Device'; expression = { ($_.Title).Trim() } }, 
    @{name = 'Admin'; expression = { $_.Admin.Email } }, 
    @{name = 'ID'; expression = { $_.ID } }, 
    @{name = 'ExceptionType'; expression = { $_.ExceptionType } }, 
    @{name = 'Reason'; expression = { $_.Reason } }, 
    @{name = 'DateOfReview'; expression = { $_.DateofReview } }
  )

  $inputobject = $items.FieldValues | Select-Object -Property $properties 
  try {
    Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'compliance' -Table 'exceptiontracking' -Truncate $true
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}


Function Invoke-ExceptionTrackingListCleanup {

  $cred = Get-O365Creds
  $SPSite = "https://$mycompany.sharepoint.com/sites/site"
  $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
  $list = Get-PnPList -Identity 'Exception Tracking' -Connection $SharePoint
  $items = Get-PnPListItem -List $list -Connection $SharePoint

  $removequery = @'
  SELECT admin, device,computers.site, exceptiontype, id, reason, dateofreview
	FROM compliance.exceptiontracking
	left join "ActiveDirectory".computers on UPPER(exceptiontracking.device) = computers.name
	where site is null
  order by device
'@

  $remove = Invoke-PGSqlQuery -Type Select -Query $removequery

  foreach ($exception in $remove) {

    $item = $items | Where-Object { $_.Id -eq $exception.id }

    Remove-PnPListItem -List $list -Identity $item -Force -Connection $SharePoint
  }


}

Function Sync-GrafanaTeamMembers {

  [CmdletBinding()]
  param (
    [Parameter()]
    [string]
    $TeamName,
    [Parameter()]
    [string]
    $GroupName
  )

  $username = 'grafana_user'
  $password = Get-SecretFromVault -Name $username -Vault SecretStore -AsPlainText
  $credPair = "$($username):$($password)"
  $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
  $headers = @{ Authorization = "Basic $encodedCredentials" }

  $usersuri = "https://grafana_server/grafana/api/users"
  $users = Invoke-RestMethod -Uri $usersuri -Method Get -Headers $headers

  $teamsuri = "https://grafana_server/grafana/api/teams/search?"
  $teams = (Invoke-RestMethod -Uri $teamsuri -Method Get -Headers $headers).teams

  $team = $teams | Where-Object { $_.name -eq "$TeamName" }

  $teammembersuri = "https://grafana_server/grafana/api/teams/$($team.id)/members"
  $teammembers = (Invoke-RestMethod -Uri $teammembersuri -Method Get -Headers $headers)

  $teamgroupmembers = Get-ADGroupMember -Identity $GroupName -Server $domain_controller | Select-Object @{name = 'login'; expression = { $_.samaccountname } }

  $missing = Compare-Object @($teammembers) @($teamgroupmembers) -Property login -PassThru | Where-Object { $_.sideindicator -eq '=>' }
  $missingusers = Compare-Object @($users) @($missing) -Property login -PassThru -IncludeEqual -ExcludeDifferent | Select-Object login, id, sideindicator

  #Write-Output "Team: $TeamName - Group: $GroupName - Missing Members: $($missingusers.count)"

  foreach ($user in $missingusers) {
    $body = "{`"userId`": $($user.id)}"
    Invoke-RestMethod -Method Post -Uri "https://grafana_server/grafana/api/teams/$($team.id)/members" -Body $body -Headers $headers -ContentType 'application/json'
  }

}

Function Get-WindowsServerVersionCompliancePerSite {

       
  $server_version = @'
  insert into metrics.site_compliance_history (
    select Site, 'Windows Server Version' as metric,
  SUM(CASE WHEN osmajorversion >= 6.3  THEN 1 ELSE 0 END) * 1.0 / count(*) * 1.0 * 100 as value,
   now()::date
  from "ActiveDirectory".computers
  where  ostype = 'Server' and enabled = 'True' and site not in ('Domain Controllers')
  group by site
) on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $server_version
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}
Function Get-Windows10VersionCompliancePerSite {

       
  $windows10_version = @'
	insert into metrics.site_compliance_history(
	  select Site,
		 'Windows 10 Version' as metric,
    SUM(CASE WHEN osminorversion >= 19044 OR operatingsystem like '%LTSB' OR operatingsystem like '%LTSC' THEN 1 ELSE 0 END) * 1.0 / count(*) * 100 as value,
		now()::date
    from "ActiveDirectory".computers
    where ostype != 'Server' and osmajorversion = 10 and osminorversion < 22000 and enabled = 'True'
    group by site
	)
    on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $windows10_version
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}
Function Get-PasswordNeverExpiresCompliancePerSite {

  $password_never_expires = @'
  insert into metrics.site_compliance_history (
    select site, 
       'Password Never Expires' as metric,
       (sum("Logon Workstations") * 1.0 / count(*)) * 100 as value,
       now()::date
  from (
  SELECT distinct(samaccountname) as "Name"
  , site
  , case 
  when (passwordneverexpires = 'True' and userworkstation is not null) OR (passwordneverexpires = 'False') then 1
  when passwordneverexpires = 'True' and userworkstation is null then null else null
  end as "Logon Workstations"
  FROM "ActiveDirectory".users
  left join "ActiveDirectory".userworkstations USING (userprincipalname)
  where enabled = 'True' and site not in ('CN=Users','Domain Controllers')
  ) x
  group by site
     )
      on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $password_never_expires
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }

}
Function Get-SecurityBaselineCompliancePerSite {

  $security_baseline = @'
  insert into metrics.site_compliance_history (
    select site,
   'Security Baseline' as metric,
  SUM (
  case when (osmajorversion = 10 and osminorversion >= 18363 and baselineexc.member_name is null)  or (osmajorversion = 6.1 and baselineexc.member_name is null) then 1 else 0 end)::decimal
  / count(*) * 100 as value,
   now()::date
  from "ActiveDirectory".computers
  left join (select member_name from "ActiveDirectory".group_members('Baseline-Exclusions')) baselineexc on "ActiveDirectory".computers.name = baselineexc.member_name
  where enabled = 'True' 
  and ostype = 'Client' 
and osmajorversion != 5.1
  group by site
 )
  on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $security_baseline
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }

}
Function Get-BitLockerUSBCompliancePerSite {
  $bitlocker_usb = @'
  insert into metrics.site_compliance_history (
    select site,
   'BitLocker USB Compliance' as metric,
((SUM(case when exceptions.member_name is null then 1 else 0 end)::decimal/COUNT(*)) * 100)::double precision as value,
   now()::date
    from "ActiveDirectory".computers
    left join (select distinct(member_name) from "ActiveDirectory".group_members('USB-Exceptions')) exceptions on "ActiveDirectory".computers.name = exceptions.member_name
    where enabled = 'True' 
    and ostype = 'Client' and osmajorversion != 5.1 
    group by site
 )
  on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $bitlocker_usb
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}
Function Get-BitLockerOSDCompliancePerSite {

  $collectionid = "MBAM/TPM Supported Computers Collection ID"
  $bitlockerosd_q = @"

  DECLARE @baseline_CI_UniqueID nvarchar(512)
  DECLARE @OSD_CI_UniqueID nvarchar(512)
  DECLARE @FDD_CI_UniqueID nvarchar(512)
  DECLARE @CICompliant int 
  DECLARE @CINotCompliant int 
  
  -- Set CI compliant value 
  SET @CICompliant = 1
  
  -- Set CI non compliant value 
  SET @CINotCompliant = 2
  
  -- Set the Baseline CI_UniqueID (AuthoringScopeId + LogicalName) based on a predefined value matching MBAM proprietary baseline
  SET @baseline_CI_UniqueID = N'ScopeId_MBAM_97199067-B6C4-408C-A742-7D3CB731A297/Baseline_81dc716a-6940-4d0d-b54c-dab1c2bfd1e5'
  
  -- Set the OS Drive CI_UniqueID (AuthoringScopeId + LogicalName + CIVersion) based on a predefined value matching MBAM proprietary baseline
  SELECT @OSD_CI_UniqueID = ConfigItems.CI_UniqueID
  FROM [v_ConfigurationItems] ConfigItems
    INNER JOIN [v_CIRelation] Relation
      ON ConfigItems.CI_ID = Relation.ToCIID 
      AND  Relation.FromCIID = (SELECT CI.CI_ID
                                FROM [v_ConfigurationItems] CI
                                WHERE CI.CI_UniqueID = @baseline_CI_UniqueID)
  WHERE ConfigItems.ModelName = N'ScopeId_MBAM_97199067-B6C4-408C-A742-7D3CB731A297/BusinessPolicy_OSD_23e5fbbb-e2c7-4de5-bb3c-7439bd5d34b1'
  
  -- Set the Fixed Data Drive CI_UniqueID (AuthoringScopeId + LogicalName + CIVersion) based on a predefined value matching MBAM proprietary baseline
  SELECT @FDD_CI_UniqueID = ConfigItems.CI_UniqueID
  FROM [v_ConfigurationItems] ConfigItems
    INNER JOIN [v_CIRelation] Relation
      ON ConfigItems.CI_ID = Relation.ToCIID 
      AND  Relation.FromCIID = (SELECT CI.CI_ID
                                FROM [v_ConfigurationItems] CI
                                WHERE CI.CI_UniqueID = @baseline_CI_UniqueID)
  WHERE  ConfigItems.ModelName = N'ScopeId_MBAM_97199067-B6C4-408C-A742-7D3CB731A297/BusinessPolicy_FDD_027ce743-e826-41a6-8067-3354f8cb8e5f'
  

select AD_OU as "site", (sum(case when total.OSDComplianceStatus = 1 and ComplianceStatusDetails = 0 then 1 else 0 end)) * 1.0 / (count(*)) * 100 as value from
(
  SELECT AD_OU,
  Netbios_Name0 as "Device",
   -- MAX(CASE WHEN ItemType = 1 THEN ComplianceStatus ELSE NULL END) AS "Overall Compliance",
    MAX(CASE WHEN ItemType = 2 THEN ComplianceStatus ELSE NULL END) AS OSDComplianceStatus,
    MAX(ComplianceStatusDetails) [ComplianceStatusDetails]
  FROM (SELECT y.AD_OU,
Rsystem.Netbios_Name0,
          RSystem.ResourceID [ResourceID],
          ComputerSystem.Domain0 [DomainName],
          ComputerSystemExt.PCSystemType0 [ComputerType],
          OpSystem.Caption0 [OS],
  CompStat.ComplianceState [ComplianceStatus],
          AssignmentStatus.LastEvaluationMessageTime [ComplianceStatusUpdateDate],
          CASE
            WHEN ConfigItems.CI_UniqueID = @baseline_CI_UniqueID THEN 1 
            WHEN ConfigItems.CI_UniqueID = @OSD_CI_UniqueID THEN 2 
            WHEN ConfigItems.CI_UniqueID = @FDD_CI_UniqueID THEN 3
          END [ItemType],
          CASE
            WHEN MBAMPolicy.MBAMPolicyEnforced0 IS NULL THEN -1 -- (when outer join returns null : N/A)
            WHEN CompStat.ComplianceState = @CINotCompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 3 THEN 1 -- tmp user exempt
            WHEN CompStat.ComplianceState = @CICompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 2 THEN 2 -- user exempt    
            ELSE 0 -- not exempted
          END [Exemption],
          CASE     
            WHEN (CompStat.ComplianceState = @CICompliant) AND ((MBAMPolicy.MBAMPolicyEnforced0 = 2) OR (MBAMPolicy.MBAMPolicyEnforced0 = 3)) THEN MBAMPolicy.LastConsoleUser0 
            ELSE N'' -- no user is exempted 
          END [ExemptedUser],
          CASE
            WHEN CompStat.ComplianceState = @CICompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 0 THEN 50 -- policy not enforced
            WHEN CompStat.ComplianceState = @CICompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 1 THEN 0 -- no error
            WHEN CompStat.ComplianceState = @CINotCompliant AND MBAMPolicy.MBAMMachineError0 IS NOT NULL THEN MBAMPolicy.MBAMMachineError0 -- MBAM agent error status
            ELSE -1 -- No Details \ Errors
          END [ComplianceStatusDetails],
          ComputerSystem.Manufacturer0 [Manufacturer],
          ComputerSystem.Model0 [Model],
          MBAMPolicy.EncryptionMethod0 [PolicyCipherStrength],
          MBAMPolicy.OSDriveEncryption0 [PolicyOSDriveEncryptRequired],
          MBAMPolicy.OsDriveProtector0 [PolicyOSDrive],
          MBAMPolicy.FixedDataDriveEncryption0 [PolicyFixedDriveEncryptRequired],
          MBAMPolicy.FixedDataDrivePassphrase0 [PolicyFixedDrivePasswordRequired],
          (RSystem.User_Domain0 + N'\' + RSystem.User_Name0) [DeviceUsers]
        FROM v_R_System_Valid RSystem
          INNER JOIN v_SMSCICurrentComplianceStatus CompStat
            ON CompStat.ItemKey = RSystem.ResourceID
          INNER JOIN v_ConfigurationItems ConfigItems
            ON ConfigItems.ModelID = CompStat.ModelID
          INNER JOIN v_GS_COMPUTER_SYSTEM_EXT ComputerSystemExt
            ON RSystem.ResourceID = ComputerSystemExt.ResourceID
          INNER JOIN v_GS_COMPUTER_SYSTEM ComputerSystem
            ON RSystem.ResourceID = ComputerSystem.ResourceID
          INNER JOIN v_GS_OPERATING_SYSTEM OpSystem
            ON RSystem.ResourceID = OpSystem.ResourceID
          LEFT OUTER JOIN v_CIAssignmentToCI AssignmentCI 
            ON AssignmentCI.CI_ID = ConfigItems.CI_ID
          LEFT OUTER JOIN v_CIAssignmentStatus AssignmentStatus
            ON AssignmentStatus.AssignmentID = AssignmentCI.AssignmentID 
            AND AssignmentStatus.ResourceID = RSystem.ResourceID
          LEFT OUTER JOIN v_GS_MBAM_POLICY MBAMPolicy
            ON MBAMPolicy.ResourceID = RSystem.ResourceID
INNER JOIN (select ItemKey,RIGHT(LEFT(RIGHT(Distinguished_Name0,29),6),3) as AD_OU from vSMS_R_System ) y ON MBAMPolicy.resourceid = y.ItemKey
        JOIN v_FullCollectionMembership on MBAMPolicy.resourceid = v_FullCollectionMembership.ResourceID
WHERE((ConfigItems.CI_UniqueID = @baseline_CI_UniqueID) OR (ConfigItems.CI_UniqueID = @OSD_CI_UniqueID) OR (ConfigItems.CI_UniqueID = @FDD_CI_UniqueID))
and v_FullCollectionMembership.CollectionID = '$collectionid' 
          ) Tmp
  GROUP BY Netbios_Name0,AD_OU
 
) total
where AD_OU !=''
group by AD_OU
"@

  $bitlockerosd = Invoke-Sqlcmd -server $sccm_server -Database "CM_$sccm_site" -Query $bitlockerosd_q | Select-Object site, value, @{name = 'metric'; expression = { 'BitLocker OSD Compliance' } }, @{name = 'date'; expression = { ([datetime]::now).ToString('yyyy-MM-dd') } }

  try {
    Invoke-PGSqlQuery -Type Insert -InputObject $bitlockerosd -OnConflict 'Set Excluded' -Schema metrics -Table 'site_compliance_history' -Truncate $false
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }

}


Function Get-ClientTotalsPerSite {
  $client_totals = @'
  insert into metrics.site_compliance_history (
    select site,
  'Total Clients' as metric,
  count(*) as value,
  now()::date
 from "ActiveDirectory".computers
 where enabled = 'True' and site not in ('Domain Controllers') and ostype = 'Client'
 group by site
)
 on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $client_totals
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }

}

Function Get-ServerTotalsPerSite {
  $server_totals = @'
  insert into metrics.site_compliance_history (
    select site,
'Total Servers' as metric,
count(*) as value,
now()::date
from "ActiveDirectory".computers
where enabled = 'True' and site not in ('Domain Controllers') and ostype = 'Server'
group by site
)
on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $server_totals
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}


Function Get-LocalAdminExceptionsPerSite {
  $local_admin = @'
  insert into metrics.site_compliance_history (
    select site,
'Local Admin Exceptions' as metric,
sum(case when localadmins.member_name is not null then 1 else 0 end) as value,
now()::date
from "ActiveDirectory".computers
left join (select member_name from "ActiveDirectory".group_members('LocalAdminChange-Exceptions')) localadmins on "ActiveDirectory".computers.name = localadmins.member_name
where enabled = 'True' 
and ostype = 'Client' and osmajorversion != 5.1 
group by site
)
on conflict (site,metric,date) DO UPDATE SET value=EXCLUDED.value;
'@

  try {
    Invoke-PGSqlQuery -Type Select -Query $local_admin
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}




Function Get-BitLockerOSD {
  $collectionid = "MBAM/TPM Supported Computers Collection ID"
  $query = @"

    DECLARE @baseline_CI_UniqueID nvarchar(512)
              DECLARE @OSD_CI_UniqueID nvarchar(512)
              DECLARE @FDD_CI_UniqueID nvarchar(512)
              DECLARE @CICompliant int 
              DECLARE @CINotCompliant int 
              
              -- Set CI compliant value 
              SET @CICompliant = 1
              
              -- Set CI non compliant value 
              SET @CINotCompliant = 2
              
              -- Set the Baseline CI_UniqueID (AuthoringScopeId + LogicalName) based on a predefined value matching MBAM proprietary baseline
              SET @baseline_CI_UniqueID = N'ScopeId_MBAM_97199067-B6C4-408C-A742-7D3CB731A297/Baseline_81dc716a-6940-4d0d-b54c-dab1c2bfd1e5'
              
              -- Set the OS Drive CI_UniqueID (AuthoringScopeId + LogicalName + CIVersion) based on a predefined value matching MBAM proprietary baseline
              SELECT @OSD_CI_UniqueID = ConfigItems.CI_UniqueID
              FROM [v_ConfigurationItems] ConfigItems
                INNER JOIN [v_CIRelation] Relation
                  ON ConfigItems.CI_ID = Relation.ToCIID 
                  AND  Relation.FromCIID = (SELECT CI.CI_ID
                                            FROM [v_ConfigurationItems] CI
                                            WHERE CI.CI_UniqueID = @baseline_CI_UniqueID)
              WHERE ConfigItems.ModelName = N'ScopeId_MBAM_97199067-B6C4-408C-A742-7D3CB731A297/BusinessPolicy_OSD_23e5fbbb-e2c7-4de5-bb3c-7439bd5d34b1'
              
              -- Set the Fixed Data Drive CI_UniqueID (AuthoringScopeId + LogicalName + CIVersion) based on a predefined value matching MBAM proprietary baseline
              SELECT @FDD_CI_UniqueID = ConfigItems.CI_UniqueID
              FROM [v_ConfigurationItems] ConfigItems
                INNER JOIN [v_CIRelation] Relation
                  ON ConfigItems.CI_ID = Relation.ToCIID 
                  AND  Relation.FromCIID = (SELECT CI.CI_ID
                                            FROM [v_ConfigurationItems] CI
                                            WHERE CI.CI_UniqueID = @baseline_CI_UniqueID)
              WHERE  ConfigItems.ModelName = N'ScopeId_MBAM_97199067-B6C4-408C-A742-7D3CB731A297/BusinessPolicy_FDD_027ce743-e826-41a6-8067-3354f8cb8e5f'
              
              SELECT 
              Netbios_Name0 as "Device",
              model0 [Model],
              tmp.ResourceID,
              MAX(DeviceUsers) [User],
               -- MAX(CASE WHEN ItemType = 1 THEN ComplianceStatus ELSE NULL END) AS "Overall Compliance",
                MAX(CASE WHEN ItemType = 2 THEN ComplianceStatus ELSE NULL END) AS OSDComplianceStatus,
                MAX(ComplianceStatusDetails) [ComplianceStatusDetails],
                MAX(ComplianceStatusUpdateDate) [Compliance_Status_Date],
                EncryptionMethod [Cipher_Strength],
            --	KeyProtectorTypes [Protector Type],
                ProtectionStatus [Protector_State],
                ConversionStatus [Encryption_State]
              FROM (SELECT 
              Rsystem.Netbios_Name0,
              model0,
                      RSystem.ResourceID [ResourceID],
                      ComputerSystem.Domain0 [DomainName],
                      ComputerSystemExt.PCSystemType0 [ComputerType],
                      OpSystem.Caption0 [OS],
                      CompStat.ComplianceState [ComplianceStatus],
                      AssignmentStatus.LastEvaluationMessageTime [ComplianceStatusUpdateDate],
                      CASE
                        WHEN ConfigItems.CI_UniqueID = @baseline_CI_UniqueID THEN 1 
                        WHEN ConfigItems.CI_UniqueID = @OSD_CI_UniqueID THEN 2 
                        WHEN ConfigItems.CI_UniqueID = @FDD_CI_UniqueID THEN 3
                      END [ItemType],
                      CASE
                        WHEN MBAMPolicy.MBAMPolicyEnforced0 IS NULL THEN -1 -- (when outer join returns null : N/A)
                        WHEN CompStat.ComplianceState = @CINotCompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 3 THEN 1 -- tmp user exempt
                        WHEN CompStat.ComplianceState = @CICompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 2 THEN 2 -- user exempt    
                        ELSE 0 -- not exempted
                      END [Exemption],
                      CASE     
                        WHEN (CompStat.ComplianceState = @CICompliant) AND ((MBAMPolicy.MBAMPolicyEnforced0 = 2) OR (MBAMPolicy.MBAMPolicyEnforced0 = 3)) THEN MBAMPolicy.LastConsoleUser0 
                        ELSE N'' -- no user is exempted 
                      END [ExemptedUser],
                      CASE
                        WHEN CompStat.ComplianceState = @CICompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 0 THEN 50 -- policy not enforced
                        WHEN CompStat.ComplianceState = @CICompliant AND MBAMPolicy.MBAMPolicyEnforced0 = 1 THEN 0 -- no error
                        WHEN CompStat.ComplianceState = @CINotCompliant AND MBAMPolicy.MBAMMachineError0 IS NOT NULL THEN MBAMPolicy.MBAMMachineError0 -- MBAM agent error status
                        ELSE -1 -- No Details \ Errors
                      END [ComplianceStatusDetails],
                      ComputerSystem.Manufacturer0 [Manufacturer],
                      ComputerSystem.Model0 [Model],
                      MBAMPolicy.EncryptionMethod0 [PolicyCipherStrength],
                      MBAMPolicy.OSDriveEncryption0 [PolicyOSDriveEncryptRequired],
                      MBAMPolicy.OsDriveProtector0 [PolicyOSDrive],
                      MBAMPolicy.FixedDataDriveEncryption0 [PolicyFixedDriveEncryptRequired],
                      MBAMPolicy.FixedDataDrivePassphrase0 [PolicyFixedDrivePasswordRequired],
                      (RSystem.User_Domain0 + N'\' + RSystem.User_Name0) [DeviceUsers]
                    FROM v_R_System_Valid RSystem
                      INNER JOIN v_SMSCICurrentComplianceStatus CompStat
                        ON CompStat.ItemKey = RSystem.ResourceID
                              INNER JOIN v_ConfigurationItems ConfigItems
                                ON ConfigItems.ModelID = CompStat.ModelID
                      INNER JOIN v_GS_COMPUTER_SYSTEM_EXT ComputerSystemExt
                        ON RSystem.ResourceID = ComputerSystemExt.ResourceID
                      INNER JOIN v_GS_COMPUTER_SYSTEM ComputerSystem
                        ON RSystem.ResourceID = ComputerSystem.ResourceID
                      INNER JOIN v_GS_OPERATING_SYSTEM OpSystem
                        ON RSystem.ResourceID = OpSystem.ResourceID
                      LEFT OUTER JOIN v_CIAssignmentToCI AssignmentCI 
                        ON AssignmentCI.CI_ID = ConfigItems.CI_ID
                      LEFT OUTER JOIN v_CIAssignmentStatus AssignmentStatus
                        ON AssignmentStatus.AssignmentID = AssignmentCI.AssignmentID 
                        AND AssignmentStatus.ResourceID = RSystem.ResourceID
                      LEFT OUTER JOIN v_GS_MBAM_POLICY MBAMPolicy
                        ON MBAMPolicy.ResourceID = RSystem.ResourceID
                      JOIN v_FullCollectionMembership on MBAMPolicy.resourceid = v_FullCollectionMembership.ResourceID
                      left join v_GS_TPM on RSystem.ResourceID = v_GS_TPM.ResourceID
                    WHERE((ConfigItems.CI_UniqueID = @baseline_CI_UniqueID) OR (ConfigItems.CI_UniqueID = @OSD_CI_UniqueID) OR (ConfigItems.CI_UniqueID = @FDD_CI_UniqueID))
                    and v_FullCollectionMembership.CollectionID = '$collectionid'
                      ) Tmp
            LEFT JOIN (
             SELECT BitlockerDetails.DriveLetter0 [DriveLetter],
                BitlockerDetails.MbamVolumeType0 [MbamVolumeType],
                BitlockerDetails.EncryptionMethod0 [EncryptionMethod],
                BitlockerDetails.ConversionStatus0 [ConversionStatus],
                BitlockerDetails.ProtectionStatus0 [ProtectionStatus],
                rsystem.resourceid
              FROM v_GS_BITLOCKER_DETAILS BitlockerDetails
                INNER JOIN v_R_System_Valid RSystem 
                  ON BitlockerDetails.ResourceID = RSystem.ResourceID
                INNER JOIN v_GS_COMPUTER_SYSTEM ComputerSystem
                  ON RSystem.ResourceID = ComputerSystem.ResourceID
                LEFT OUTER JOIN v_GS_MBAM_POLICY MBAMPolicy
                  ON MBAMPolicy.ResourceID = RSystem.ResourceID
              WHERE (BitlockerDetails.MbamVolumeType0 = 1) 
            ) volume on tmp.resourceid = volume.resourceid
              GROUP BY (Netbios_Name0),model0, tmp.resourceid,EncryptionMethod,ConversionStatus,ProtectionStatus--,KeyProtectorTypes
"@
    
    
  $bitlockerosd = Invoke-Sqlcmd -server $sccm_server -Database "CM_$sccm_site" -Query $query
  try {
    Invoke-PGSqlQuery -Type Insert -InputObject $bitlockerosd -OnConflict 'Do Nothing' -Schema 'compliance' -Table 'bitlockerosd' -Truncate $true
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}
Function New-GrafanaPlannerTask {
  param(
    [Parameter()]
    [string]
    $Site,
    [string]
    $Bucket,
    [string]
    $Title,
    [string]
    $Description,
    [switch]
    $RemoveExistingTask,
    [switch]
    $DebugTaskCreation
  )

  $accessToken = (Get-MSGraphDelegatedAuth).AccessToken | ConvertTo-SecureString -AsPlainText -Force
  Connect-MgGraph -AccessToken $accessToken | Out-Null



  $assignments = @{}
  $assignmentvalues = @{
    '@odata.type' = '#microsoft.graph.plannerAssignment'
    orderHint     = ' !'
  }

 
  $planid = ''
  try {
    $bucketassignment = Get-MgPlannerPlanBucket -PlannerPlanId $planid | Where-Object { $_.Name -eq $Bucket }
    if ($null -eq $bucketassignment) {
      New-MgPlannerBucket -PlanId $planid -Name $Bucket | Out-Null
      $bucketassignment = Get-MgPlannerPlanBucket -PlannerPlanId $planid | Where-Object { $_.Name -eq $Bucket }
    }
  }
  catch {
    $_.Exception
  }


  $query = @"
with o365 as (	
select id,
lower(jsonb_path_query(proxyaddresses, '$[*] ? (@.Name[*] == "smtp" || @.Name[*] == "SMTP").Value')->>0) as mail
FROM "Office365".userid),
admin_email as (select array_agg(site order by site) as sites, lower(admin_email) as mail from public.site_admins group by admin_email)
select * from o365 
join admin_email using (mail)
where sites && ARRAY['$Site']
order by sites,mail
"@


  $users = Invoke-PGSqlQuery -Type Select -Query $query
  foreach ($user in $users) {
    $assignments.Add($user.id.guid, $assignmentvalues)
  }

  $Details = @{
    '@odata.type' = '#microsoft.graph.plannerTaskDetails'
    'description' = $Description
  }

  $params = @{
    planId      = $planid
    bucketId    = $bucketassignment.id
    title       = $Title
    assignments = $assignments
    duedatetime = (Get-Date).AddDays(7)
    Details     = $Details
  }
  
  try {
    $existingtask = Get-MgPlannerBucketTask -PlannerBucketId $bucketassignment.id | Where-Object { $_.Title -eq $Title }

    if ($existingtask) {

      $result = 'Failure: Task Already Exists'
      $taskid = $existingtask.id

      if ($RemoveExistingTask) {

        foreach ($task in $existingtask) {
          Remove-MgPlannerTask -PlannerTaskId $task.id -IfMatch $task.AdditionalProperties.'@odata.etag'
        }

        if (!$DebugTaskCreation) {
          $newtask = New-MgPlannerTask -BodyParameter $params 
          $taskid = $newtask.id
          $result = 'Success'
        }

      }

    }
    else {
      if (!$DebugTaskCreation) {
        $newtask = New-MgPlannerTask -BodyParameter $params 
        $taskid = $newtask.id
        $result = 'Success'
      }
    }
    [PSCustomObject]@{
      Title       = $Title
      Bucket      = $Bucket
      Assignments = ($users.mail -join ',')
      Result      = $result
      TaskLink    = "https://tasks.office.com/$TenantName/Home/Task/$($taskid)"
      Params      = $params
    }
  }
  catch {
    $_.exception
  }
  finally {
    Get-GrafanaPlannerTasks
  }

}

Function Get-GrafanaPlannerTasks {
  $accessToken = (Get-MSGraphDelegatedAuth).AccessToken | ConvertTo-SecureString -AsPlainText -Force
  Connect-MgGraph -AccessToken $accessToken | Out-Null

  Import-Module Microsoft.Graph.Planner

  $planproperties = @(
      'planid',
      'details',
      'bucketid',
      'title',
      'percentcomplete',
      'startdatetime',
      'createddatetime',
      'duedatetime',
      'completeddatetime',
      'checklistitemcount',
      'activechecklistitemcount',
      'id',
      'appliedcategories',
      'assignments'
  )

  $tasks = Get-MgGroupPlannerPlanTask -GroupId '' -PlannerPlanId '' -All -Property $planproperties -ExpandProperty Details


  $properties = @(
      'planid',
      'bucketid',
      'title',
      'percentcomplete',
      'startdatetime',
      'createddatetime',
      'duedatetime',
      'completeddatetime',
      'checklistitemcount',
      'activechecklistitemcount',
      'id',
      @{name = 'appliedcategories'; expression = { $_.appliedcategories | ConvertTo-Json -Compress -WarningAction SilentlyContinue } },
      @{name = 'assignments'; expression = { $_.assignments | ConvertTo-Json -Compress -WarningAction SilentlyContinue } },
      @{name = 'description'; expression = { $_.Details.Description.Trim() } }
  )

  $inputobject = $tasks | Select-Object -Property $properties
  Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'planner' -Table 'tasks' -Truncate $false

}

Function Set-MaterializedViews {
  Invoke-PGSqlQuery -Type Select -Query 'SELECT public.refresh_all_materialized_views();' | Out-Null
}


Function Invoke-GrafanaScheduledFunction {
  [CmdletBinding()]
  param (
    [ValidateSet('15Minute', 'Hourly', 'Daily')]
    [string]
    $Schedule
  )
  try {
    switch ($Schedule) {
      '15Minute' {}
      'Hourly' { 
        Write-Output 'Get-ExceptionTrackingList'; Get-ExceptionTrackingList
        Write-Output 'Sync-GrafanaTeamMembers'; Sync-GrafanaTeamMembers -TeamName 'IT' -GroupName 'IT'
        Write-Output 'Get-WindowsServerVersionCompliancePerSite'; Get-WindowsServerVersionCompliancePerSite
        Write-Output 'Get-Windows10VersionCompliancePerSite'; Get-Windows10VersionCompliancePerSite
        Write-Output 'Get-PasswordNeverExpiresCompliancePerSite'; Get-PasswordNeverExpiresCompliancePerSite
        Write-Output 'Get-SecurityBaselineCompliancePerSite'; Get-SecurityBaselineCompliancePerSite
        Write-Output 'Get-BitLockerOSDCompliancePerSite'; Get-BitLockerOSDCompliancePerSite
        Write-Output 'Get-BitLockerUSBCompliancePerSite'; Get-BitLockerUSBCompliancePerSite
        Write-Output 'Get-ClientTotalsPerSite'; Get-ClientTotalsPerSite
        Write-Output 'Get-ServerTotalsPerSite'; Get-ServerTotalsPerSite
        Write-Output 'Get-LocalAdminExceptionsPerSite'; Get-LocalAdminExceptionsPerSite
        Write-Output 'Get-BitLockerOSD'; Get-BitLockerOSD
        Write-Output 'Set-MaterializedViews'; Set-MaterializedViews
      }
      'Daily' {
        
      }
    }
  }
  catch {
    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
  }
}
















