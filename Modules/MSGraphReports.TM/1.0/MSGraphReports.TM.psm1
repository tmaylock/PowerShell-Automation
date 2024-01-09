

Function Get-MailboxActivity {

    $properties = @(
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'SendCount'; expression = { $_.'Send Count' } },
        @{name = 'ReceiveCount'; expression = { $_.'Receive Count' } },
        @{name = 'ReadCount'; expression = { $_.'Read Count' } },
        @{Name = 'meeting_created_count'; Expression = { $_.'Meeting Created Count' } },
        @{Name = 'meeting_interacted_count'; Expression = { $_.'Meeting Interacted Count' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(date=$ReportDate)"
    $MailboxActivityUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties  
 
    if ($MailboxActivityUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $MailboxActivityUsageData -OnConflict 'Set Excluded' -Schema 'MSGraph' -Table 'mailboxactivity' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET MailboxActivity      = 1 WHERE date = `'$ReportDate`'" 
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}
Function Get-MailboxUsage {

    $properties = @(
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'ItemCount'; expression = { $_.'Item Count' } },
        @{name = 'StorageUsed'; expression = { $_.'Storage Used (Byte)' } },
        @{Name = 'created_date'; Expression = { $_.'Created Date' } }
        @{Name = 'last_activity_date'; Expression = { $_.'Last Activity Date' } }
        @{Name = 'issue_warning_quota_byte'; Expression = { $_.'Issue Warning Quota (Byte)' } }
        @{Name = 'prohibit_send_quota_byte'; Expression = { $_.'Prohibit Send Quota (Byte)' } }
        @{Name = 'prohibit_send_receive_quota_byte'; Expression = { $_.'Prohibit Send/Receive Quota (Byte)' } }
        @{Name = 'deleted_item_count'; Expression = { $_.'Deleted Item Count' } }
        @{Name = 'deleted_item_size_byte'; Expression = { $_.'Deleted Item Size (Byte)' } }
        @{Name = 'deleted_item_quota_byte'; Expression = { $_.'Deleted Item Quota (Byte)' } }
        @{Name = 'has_archive'; Expression = { $_.'Has Archive' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period='D7')"
    $MailboxUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties
    if ($MailboxUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $MailboxUsageData -OnConflict 'Set Excluded' -Schema 'MSGraph' -Table 'mailboxusage' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule

        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - No Data" -Severity 2

    }
}
Function Get-Office365Activations {

    $properties = @(
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'LastActivatedDate'; expression = { if ($_.'Last Activated Date') { $_.'Last Activated Date' }else { '1970-1-1' } } },
        @{name = 'DisplayName'; expression = { $_.'Display Name' } },
        @{name = 'ProductType'; expression = { $_.'Product Type' } },
        @{name = 'Windows'; expression = { $_.'Windows' } },
        @{name = 'Mac'; expression = { $_.'Mac' } },
        @{name = 'Windows10Mobile'; expression = { $_.'Windows 10 Mobile' } },
        @{name = 'iOS'; expression = { $_.iOS } },
        @{name = 'Android'; expression = { $_.Android } },
        @{name = 'ActivatedOnSharedComputer'; expression = { $_.'Activated On Shared Computer' } }
    )

    $Uri = 'https://graph.microsoft.com/v1.0/reports/getOffice365ActivationsUserDetail'
    $Office365ActivationUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties  

    if ($Office365ActivationUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $Office365ActivationUsageData -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'activations' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2

    }

}
Function Get-Office365UserDetail {

    $properties = @(
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'DisplayName'; expression = { $_.'Display Name' } },
        @{name = 'HasExchangeLicense'; expression = { if ($_.'Has Exchange License' -eq 'True') { '1' }else { '0' } } },
        @{name = 'HasOneDriveLicense'; expression = { if ($_.'Has OneDrive License' -eq 'True') { '1' }else { '0' } } },
        @{name = 'HasSharePointLicense'; expression = { if ($_.'Has SharePoint License' -eq 'True') { '1' }else { '0' } } },
        @{name = 'HasSkypeForBusinessLicense'; expression = { if ($_.'Has Skype For Business License' -eq 'True') { '1' }else { '0' } } },
        @{name = 'HasYammerLicense'; expression = { if ($_.'Has Yammer License' -eq 'True') { '1' }else { '0' } } },
        @{name = 'HasTeamsLicense'; expression = { if ($_.'Has Teams License' -eq 'True') { '1' }else { '0' } } },
        @{name = 'ExchangeLastActivityDate'; expression = { $_.'Exchange Last Activity Date' } },
        @{name = 'OneDriveLastActivityDate'; expression = { $_.'OneDrive Last Activity Date' } },
        @{name = 'SharePointLastActivityDate'; expression = { $_.'SharePoint Last Activity Date' } },
        @{name = 'SkypeForBusinessLastActivityDate'; expression = { $_.'Skype For Business Last Activity Date' } },
        @{name = 'YammerLastActivityDate'; expression = { $_.'Yammer Last Activity Date' } },
        @{name = 'TeamsLastActivityDate'; expression = { $_.'Teams Last Activity Date' } }
    )



    $Uri = "https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(date=$ReportDate)"
    $Office365UserDetailData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties  

    if ($Office365UserDetailData) {    
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $Office365UserDetailData -OnConflict 'Do Nothing' -Schema 'Office365' -Table 'userdetail' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET office365userdetail = 1 WHERE date = `'$ReportDate`'" 
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule

        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }

    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2

    }

}


Function Get-OneDriveActivity {

    $properties = @(
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'ViewedOrEditedFileCount'; expression = { $_.'Viewed Or Edited File Count' } },
        @{name = 'SyncedFileCount'; expression = { $_.'Synced File Count' } },
        @{name = 'SharedInternallyFileCount'; expression = { $_.'Shared Internally File Count' } },
        @{name = 'SharedExternallyFileCount'; expression = { $_.'Shared Externally File Count' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getOneDriveActivityUserDetail(date=$ReportDate)"
    $OneDriveActivityUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 


    if ($OneDriveActivityUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $OneDriveActivityUsageData -OnConflict 'Do Nothing' -Schema 'MSGraph' -Table 'onedriveactivity' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET OneDriveActivity = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    } 
}
Function Get-OneDriveUsage {

    $properties = @(
        @{name = 'OwnerDisplayName'; expression = { $_.'Owner Display Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'FileCount'; expression = { $_.'File Count' } },
        @{name = 'ActiveFileCount'; expression = { $_.'Active File Count' } },
        @{name = 'StorageUsed'; expression = { $_.'Storage Used (Byte)' } },
        @{Name = 'IsDeleted'; Expression = { $_.'Is Deleted' } },
        @{Name = 'OwnerPrincipalName'; Expression = { $_.'Owner Principal Name' } }
    )

    $cleanup_query = @'
	delete from "MSGraph".onedriveusage
	where ownerprincipalname not in (select distinct userprincipalname from "Office365".userid)
'@

    $Uri = "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(date=$ReportDate)"
    $OneDriveUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 

    if ($OneDriveUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $OneDriveUsageData -OnConflict 'Set Excluded' -Schema 'MSGraph' -Table 'onedriveusage' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET onedriveusage = 1 WHERE date = `'$ReportDate`'"
            Invoke-PGSqlQuery -Type Select -Query $cleanup_query
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}
Function Get-SharePointSiteUsage {

    $properties = @(
        @{name = 'SiteID'; expression = { $_.'Site Id' } },
        @{name = 'SiteURL'; expression = { $_.'Site URL' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'OwnerDisplayName'; expression = { $_.'Owner Display Name' } },
        @{name = 'IsDeleted'; expression = { if ($_.'Is Deleted' -eq 'True') { '1' } else { '0' } } },
        @{name = 'FileCount'; expression = { $_.'File Count' } },
        @{name = 'ActiveFileCount'; expression = { $_.'Active File Count' } },
        @{name = 'StorageUsed'; expression = { $_.'Storage Used (Byte)' } },
        @{name = 'LastActivityDate'; expression = { $_.'Last Activity Date' } },
        @{name = 'PageViewCount'; expression = { $_.'Page View Count' } },
        @{name = 'VisitedPageCount'; expression = { $_.'Visited Page Count' } },
        @{name = 'StorageAllocated'; expression = { $_.'Storage Allocated (Byte)' } },
        @{name = 'OwnerPrincipalName'; expression = { $_.'Owner Principal Name' } },
        @{name = 'RootWebTemplate'; expression = { $_.'Root Web Template' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageDetail(date=$ReportDate)"
    $SharePointSiteUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 

    if ($SharePointSiteUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $SharePointSiteUsageData -OnConflict 'Set Excluded' -Schema 'MSGraph' -Table 'sharepointsiteusage' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET sharepointsiteusage = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}
Function Get-TeamsUserActivity {

    $properties = @(
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'TeamChatMessageCount'; expression = { $_.'Team Chat Message Count' } },
        @{name = 'PrivateChatMessageCount'; expression = { $_.'Private Chat Message Count' } },
        @{name = 'CallCount'; expression = { $_.'Call Count' } },
        @{name = 'MeetingCount'; expression = { $_.'Meeting Count' } },
        @{Name = 'user_id'; Expression = { $_.'User Id' } },
        @{Name = 'last_activity_date'; Expression = { $_.'Last Activity Date' } },
        @{Name = 'is_deleted'; Expression = { $_.'Is Deleted' } },
        @{Name = 'deleted_date'; Expression = { $_.'Deleted Date' } },
        @{Name = 'assigned_products'; Expression = { $_.'Assigned Products' } },
        @{Name = 'meetings_organized_count'; Expression = { $_.'Meetings Organized Count' } },
        @{Name = 'meetings_attended_count'; Expression = { $_.'Meetings Attended Count' } },
        @{Name = 'ad_hoc_meetings_organized_count'; Expression = { $_.'Ad Hoc Meetings Organized Count' } },
        @{Name = 'ad_hoc_meetings_attended_count'; Expression = { $_.'Ad Hoc Meetings Attended Count' } },
        @{Name = 'scheduled_one-time_meetings_organized_count'; Expression = { $_.'Scheduled One-time Meetings Organized Count' } },
        @{Name = 'scheduled_one-time_meetings_attended_count'; Expression = { $_.'Scheduled One-time Meetings Attended Count' } },
        @{Name = 'scheduled_recurring_meetings_organized_count'; Expression = { $_.'Scheduled Recurring Meetings Organized Count' } },
        @{Name = 'scheduled_recurring_meetings_attended_count'; Expression = { $_.'Scheduled Recurring Meetings Attended Count' } },
        @{Name = 'audio_duration_in_seconds'; Expression = { $_.'Audio Duration In Seconds' } },
        @{Name = 'video_duration_in_seconds'; Expression = { $_.'Video Duration In Seconds' } },
        @{Name = 'screen_share_duration_in_seconds'; Expression = { $_.'Screen Share Duration In Seconds' } },
        @{Name = 'has_other_action'; Expression = { $_.'Has Other Action' } },
        @{Name = 'urgent_messages'; Expression = { $_.'Urgent Messages' } },
        @{Name = 'post_messages'; Expression = { $_.'Post Messages' } },
        @{Name = 'tenant_display_name'; Expression = { $_.'Tenant Display Name' } },
        @{Name = 'shared_channel_tenant_display_names'; Expression = { $_.'Shared Channel Tenant Display Names' } },
        @{Name = 'reply_messages'; Expression = { $_.'Reply Messages' } },
        @{Name = 'is_licensed'; Expression = { $_.'Is Licensed' } } 
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityUserDetail(date=$ReportDate)"
    $TeamsUserActivityData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 

    if ($TeamsUserActivityData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $TeamsUserActivityData -OnConflict 'Set Excluded' -Schema 'MSGraph' -Table 'teamsuseractivity' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET teamsuseractivity = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}
Function Get-TeamsDeviceUsage {    

    $properties = @(
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'UsedWeb'; expression = { if ($_.'Used Web' -eq 'Yes') { '1' } else { '0' } } },
        @{name = 'UsediOS'; expression = { if ($_.'Used iOS' -eq 'Yes') { '1' } else { '0' } } },
        @{name = 'UsedAndroidPhone'; expression = { if ($_.'Used Android Phone' -eq 'Yes') { '1' } else { '0' } } },
        @{name = 'UsedWindows'; expression = { if ($_.'Used Windows' -eq 'Yes') { '1' } else { '0' } } },
        @{name = 'UserId'; expression = { $_.'User Id' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getTeamsDeviceUsageUserDetail(date=$ReportDate)"
    $TeamsDeviceUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 

    if ($TeamsDeviceUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $TeamsDeviceUsageData -OnConflict 'Set Excluded' -Schema 'MSGraph' -Table 'teamsdeviceusage' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET teamsdeviceusage = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    } 
}
Function Get-YammerActivity {

    $properties = @(
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'PostedCount'; expression = { $_.'Posted Count' } },
        @{name = 'ReadCount'; expression = { $_.'Read Count' } },
        @{name = 'LikedCount'; expression = { $_.'Liked Count' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getYammerActivityUserDetail(date=$ReportDate)"
    $YammerUsageData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 

    if ($YammerUsageData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $YammerUsageData -OnConflict 'Do Nothing' -Schema 'MSGraph' -Table 'yammeractivity' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET yammeractivity = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}

Function Get-YammerGroupsActivityDetail {

    $properties = @(
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'GroupDisplayName'; expression = { $_.'Group Display Name' } },
        @{name = 'IsDeleted'; expression = { $_.'Is Deleted' } },
        @{name = 'OwnerPrincipalName'; expression = { $_.'Owner Principal Name' } },
        @{name = 'LastActivityDate'; expression = { $_.'Last Activity Date' } },
        @{name = 'GroupType'; expression = { $_.'Group Type' } },
        @{name = 'Office365Connected'; expression = { $_.'Office 365 Connected' } },
        @{name = 'MemberCount'; expression = { $_.'Member Count' } },
        @{name = 'PostedCount'; expression = { $_.'Posted Count' } },
        @{name = 'ReadCount'; expression = { $_.'Read Count' } },
        @{name = 'LikedCount'; expression = { $_.'Liked Count' } },
        @{name = 'ReportPeriod'; expression = { $_.'Report Period' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getYammerGroupsActivityDetail(date=$ReportDate)"
    $YammerGroupsActivityDetailData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 

    if ($YammerGroupsActivityDetailData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $YammerGroupsActivityDetailData -OnConflict 'Do Nothing' -Schema 'MSGraph' -Table 'yammergroupsactivity' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET yammergroupsactivity = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}

Function Get-YammerGroupsActivityGroupCounts {

    $properties = @(
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        "Total",
        "Active",
        @{name = 'ReportPeriod'; expression = { $_.'Report Period' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getYammerGroupsActivityGroupCounts(period='D7')"
    $YammerGroupsActivityGroupCountsData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 

    if ($YammerGroupsActivityGroupCountsData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $YammerGroupsActivityGroupCountsData -OnConflict 'Do Nothing' -Schema 'MSGraph' -Table 'yammergroupsactivitygroupcounts' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET yammergroupsactivity = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}

Function Get-YammerDeviceUsageUserDetail {

    $properties = @(
        @{name = 'ReportRefreshDate'; expression = { $_.'Report Refresh Date' } },
        @{name = 'UserPrincipalName'; expression = { $_.'User Principal Name' } },
        @{name = 'DisplayName'; expression = { $_.'Display Name' } },
        @{name = 'UserState'; expression = { $_.'User State' } },
        @{name = 'StateChangeDate'; expression = { $_.'State Change Date' } },
        @{name = 'LastActivityDate'; expression = { $_.'Last Activity Date' } },
        @{name = 'UsedWeb'; expression = { $_.'Used Web' } },
        @{name = 'UsedWindowsPhone'; expression = { $_.'Used Windows Phone' } },
        @{name = 'UsedAndroidPhone'; expression = { $_.'Used Android Phone' } },
        @{name = 'UsediPhone'; expression = { $_.'Used iPhone' } },
        @{name = 'UsediPad'; expression = { $_.'Used iPad' } },
        @{name = 'UsedOthers'; expression = { $_.'Used Others' } },
        @{name = 'ReportPeriod'; expression = { $_.'Report Period' } }
    )

    $Uri = "https://graph.microsoft.com/v1.0/reports/getYammerDeviceUsageUserDetail(date=$ReportDate)"
    $YammerDeviceUsageUserDetailData = Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-MSGraphAPIHeaders) | ConvertFrom-Csv | Select-Object -Property $properties 
    
    if ($YammerDeviceUsageUserDetailData) {
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $YammerDeviceUsageUserDetailData -OnConflict 'Do Nothing' -Schema 'MSGraph' -Table 'yammerdeviceusageuserdetail' -Truncate $false
            Invoke-PGSqlQuery -Type Select -Query "UPDATE public.queue  SET yammerdeviceusageuserdetail = 1 WHERE date = `'$ReportDate`'"
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
    else {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) -Value "$($MyInvocation.MyCommand) - $reportdate - No Data" -Severity 2
    }
}


Function Set-Queue($queuedate) {

    $inputobject = [PSCustomObject]@{
        date                        = $queuedate
        mailboxactivity             = 0
        mailtransportrules          = 0
        office365userdetail         = 0
        onedriveactivity            = 0
        onedriveusage               = 0
        sharepointsiteusage         = 0
        teamsuseractivity           = 0
        teamsdeviceusage            = 0
        yammeractivity              = 0
        yammergroupsactivity        = 0
        yammerdeviceusageuserdetail = 0
    }

    Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema 'public' -Table 'queue' -OnConflict 'Do Nothing' -Truncate $false

}

Function Get-MissingO365Data {

    $retrydate = (Get-Date).AddDays(-30).ToString('yyyy-MM-dd')
    $query = "SELECT * 
FROM public.queue 
where (date >= '$retrydate' and date < '$reportdate')
and (
mailboxactivity = 0
OR office365userdetail = 0
OR onedriveactivity = 0
OR onedriveusage = 0
OR sharepointsiteusage = 0
OR teamsuseractivity = 0
OR teamsdeviceusage = 0
OR yammeractivity = 0
OR yammerdeviceusageuserdetail = 0
OR yammergroupsactivity = 0
)
and to_char(date, 'Day') not like 'Saturday%'
and to_char(date, 'Day') not like 'Sunday%'
;"

    $queue = Invoke-PGSqlQuery -Type Select -Query $query 

    foreach ($result in $queue) {
        $global:reportdate = $($result.date.ToString('yyyy-MM-dd'))
        if (([datetime]$reportdate).DayOfWeek -notin ('Saturday', 'Sunday')) {

            if ($result.mailboxactivity -eq 0) {
                Write-Output "Retry Get-MailboxActivity: $reportdate"
                Get-MailboxActivity
            }
            if ($result.office365userdetail -eq 0) {
                Write-Output "Retry Get-Office365UserDetail: $reportdate"
                Get-Office365UserDetail
            }
            if ($result.onedriveactivity -eq 0) {
                Write-Output "Retry Get-OneDriveActivity: $reportdate"
                Get-OneDriveActivity
            }
            if ($result.onedriveusage -eq 0) {
                Write-Output "Retry Get-OneDriveUsage : $reportdate"
                Get-OneDriveUsage    
            }
            if ($result.sharepointsiteusage -eq 0) {
                Write-Output "Retry Get-SharePointSiteUsage: $reportdate"
                Get-SharePointSiteUsage
            }
            if ($result.teamsuseractivity -eq 0) {
                Write-Output "Retry Get-TeamsUserActivity: $reportdate"
                Get-TeamsUserActivity
            }
            if ($result.teamsdeviceusage -eq 0) {
                Write-Output "Retry Get-TeamsDeviceUsage: $reportdate"
                Get-TeamsDeviceUsage
            }     
            if ($result.yammeractivity -eq 0) {
                Write-Output "Retry Get-YammerActivity: $reportdate"
                Get-YammerActivity
            }
            if ($result.yammerdeviceusageuserdetail -eq 0) {
                Write-Output "Retry Get-YammerDeviceUsageUserDetail: $reportdate"
                Get-YammerDeviceUsageUserDetail
            }
            if ($result.yammergroupsactivity -eq 0) {
                Write-Output "Retry Get-YammerGroupsActivityDetail: $reportdate"
                Get-YammerGroupsActivityDetail
            }
            Start-Sleep -Seconds 10     
        }
    }

}

Function Get-MSGraphReports {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $global:ReportDate,
        [Parameter()]
        [switch]$Retry
    )
    if (!($ReportDate)) { $global:ReportDate = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd') }
    if (([datetime]$global:ReportDate).DayOfWeek -notin ('Saturday', 'Sunday')) {
        Write-Output "Fetching O365 Data: $reportdate"
        Set-Queue -queuedate $reportdate
        Write-Output "Get-MailboxActivity: $reportdate"; Get-MailboxActivity
        Write-Output "Get-Office365UserDetail: $reportdate"; Get-Office365UserDetail
        Write-Output "Get-OneDriveActivity: $reportdate"; Get-OneDriveActivity
        Write-Output "Get-OneDriveUsage : $reportdate"; Get-OneDriveUsage
        Write-Output "Get-SharePointSiteUsage: $reportdate"; Get-SharePointSiteUsage
        Write-Output "Get-TeamsUserActivity: $reportdate"; Get-TeamsUserActivity
        Write-Output "Get-TeamsDeviceUsage: $reportdate"; Get-TeamsDeviceUsage
        Write-Output "Get-YammerActivity: $reportdate"; Get-YammerActivity
        Write-Output "Get-YammerGroupsActivityDetail: $reportdate" ; Get-YammerGroupsActivityDetail 
        Write-Output "Get-MailboxUsage: $reportdate"; Get-MailboxUsage
        Write-Output "Get-Office365Activations: $reportdate"; Get-Office365Activations

    }
    if ($Retry) { Get-MissingO365Data }
}
Function Invoke-MSGraphReportsScheduledFunction {
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

        }
        'Daily' {
            Write-Output 'Get-MSGraphReports -Retry'; Get-MSGraphReports -Retry
        }
    }
 
}



















