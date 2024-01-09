$countdown = @{
    '14' = 14 
    '21' = 7  
    '27' = 3  
}


<#
Compliance is a multi-step process:

1 - exception type must be added to exception tracking sharepoint list

2 - a view must be defined that shows compliance 

3 - join exception tracking list on your device like this-
    ## LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING sccmexclusion ON CLIENTS."Device" = UPPER(sccmexclusion.DEVICE) and sccmexclusion.EXCEPTIONTYPE = 'Client Stats - SCCM Exclusion'

4 - add your columns for status and reason like this -
    ## 	"SCCM Client Status",
		CASE
	WHEN "SCCM Client Status" = 2 AND sccmexclusion.REASON IS NULL THEN 'Missing' 
	WHEN "SCCM Client Status" = 2 AND sccmexclusion.REASON IS NOT NULL THEN sccmexclusion.REASON
	ELSE null END AS "SCCM Client Reason",

5 - create a powershell function like "Get-ComplianceClientSecurityBaselineExceptions" to store your exceptions in a table with the device name, date, and exception type

6 - create view for use by the powershell alerting function, this will use the get-*exceptions query in it plus a few other things. compare with other views. this will tell us how old the exception is and we'll use the age for automatic remediation.

7 - You need a postgres table called site_admins with each site and admin email in it. I've just kept mine in the public schema.
#>

# To Do: I need to add some steps to only include devices in the email report that have been successfully remediated with a try{} catch{}



Function Get-ComplianceLocalRiskAssessmentListItems {
    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Local Risk Assessment' -Connection $SharePoint
  
    $items = Get-PnPListItem -List $list -Connection $SharePoint


    $properties = @(
        @{name = 'ID'; expression = { $_.ID } },
        @{name = 'Location'; expression = { $_.Location } },
        @{name = 'Local_Global_Risk'; expression = { $_.Local_x002f_GlobalRisk } },
        @{name = 'GroupRiskCategory'; expression = { $_.GroupRiskCategory } },
        @{name = 'Risk Description'; expression = { $_.Title } },
        @{name = 'RiskReviewDescription'; expression = { $_.RiskReviewDescription } },
        @{name = 'RiskOwner'; expression = { $_.RiskOwner.Email } },
        @{name = 'Reviewer'; expression = { $_.Reviewer.Email } },
        @{name = 'ReviewDate'; expression = { $_.ReviewDate } },
        @{name = 'Impact'; expression = { $_.Impact } },
        @{name = 'Likelihood'; expression = { $_.Likelihood } }
    )

    $itemvalues = $items.fieldvalues | Select-Object -Property $properties
    
    
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $itemvalues -OnConflict 'Do Nothing' -Schema 'compliance' -Table 'localriskassessment' -Truncate $false
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}


Function Get-ComplianceBitLockerUSBExceptions {

    $bitlockerusbquery = @'
SELECT "Device" as device, current_date as date,'BitLockerUSB - Configuration' as "exception_type"
	FROM compliance.bitlocker_usb
	left JOIN COMPLIANCE.EXCEPTIONTRACKING ON lower(bitlocker_usb."Device") = lower(EXCEPTIONTRACKING.DEVICE) AND EXCEPTIONTYPE = 'BitLockerUSB - Configuration'
	where "Configuration" = 3 and reason is null
	order by site
'@
    $bitlockerusb = Invoke-PGSqlQuery -Type Select -Query $bitlockerusbquery | Select-Object device, date, exception_type
    Invoke-PGSqlQuery -Type Insert -InputObject $bitlockerusb -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false

}

Function Get-ComplianceClientSecurityBaselineExceptions {

    $client_security_baseline_query = @'
SELECT "Device",current_date  as date,'Client Stats - Security Baseline' as "exception_type"
FROM COMPLIANCE.CLIENTS
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING securitybaseline ON lower(CLIENTS."Device") = lower(securitybaseline.DEVICE) and securitybaseline.EXCEPTIONTYPE = 'Client Stats - Security Baseline'
where "Security Baseline" = 2 AND securitybaseline.REASON IS NULL
'@


    $client_security_baseline = Invoke-PGSqlQuery -Type Select -Query $client_security_baseline_query | Select-Object device, date, exception_type
    Invoke-PGSqlQuery -Type Insert -InputObject $client_security_baseline -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false

}

Function Get-ComplianceClientSCCMExclusions {

    $client_sccm_exclusion_query = @'
SELECT "Device",current_date  as date,'Client Stats - SCCM Exclusion' as "exception_type"
FROM COMPLIANCE.CLIENTS
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING sccmexclusion ON lower(CLIENTS."Device") = lower(sccmexclusion.DEVICE) and sccmexclusion.EXCEPTIONTYPE = 'Client Stats - SCCM Exclusion'
where "SCCM Client Status" in (1,2) AND sccmexclusion.REASON IS NULL
'@


    $client_sccm_exclusion = Invoke-PGSqlQuery -Type Select -Query $client_sccm_exclusion_query | Select-Object device, date, exception_type
    Invoke-PGSqlQuery -Type Insert -InputObject $client_sccm_exclusion -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false

}


Function Get-ComplianceClientLocalAdminExceptions {

    $local_admin_query = @'
SELECT "Device",current_date  as date,'Client Stats - Local Admin' as "exception_type"
	FROM COMPLIANCE.CLIENTS
	LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING localadmin ON CLIENTS."Device" = UPPER(localadmin.DEVICE) and localadmin.EXCEPTIONTYPE = 'Client Stats - Local Admin'
	WHERE "Local Admin" = 1 and localadmin.REASON IS NULL
'@


    $local_admin = Invoke-PGSqlQuery -Type Select -Query $local_admin_query | Select-Object device, date, exception_type
    if ($local_admin) {
        Invoke-PGSqlQuery -Type Insert -InputObject $local_admin -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false
    }

}

Function Get-ComplianceClientWin10OSVersion {

    $client_version_query = @'
    SELECT name AS device,
    CURRENT_DATE AS date,
    'Client Stats - OS Version Compliance' AS exception_type
   FROM compliance.win10_version
     LEFT JOIN compliance.exceptiontracking ON win10_version.name = exceptiontracking.device AND exceptiontracking.exceptiontype = 'Client Stats - OS Version Compliance'
  WHERE win10_version."Status" = 0 AND exceptiontracking.reason IS NULL
'@

    $client_version = Invoke-PGSqlQuery -Type Select -Query $client_version_query | Select-Object device, date, exception_type
    if ($client_version) {
        Invoke-PGSqlQuery -Type Insert -InputObject $client_version -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false
    }

}

Function Get-ComplianceClientWin7OSVersion {

    $client_7_version_query = @'
    SELECT name AS device,
    CURRENT_DATE AS date,
    'Client Stats - OS Version Compliance' AS exception_type
   FROM compliance.win7_clients
     LEFT JOIN compliance.exceptiontracking ON win7_clients.name = exceptiontracking.device AND exceptiontracking.exceptiontype = 'Client Stats - OS Version Compliance'
  WHERE exceptiontracking.reason IS NULL
'@

    $client_7_version = Invoke-PGSqlQuery -Type Select -Query $client_7_version_query | Select-Object device, date, exception_type
    if ($client_7_version) {
        Invoke-PGSqlQuery -Type Insert -InputObject $client_7_version -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false
    }

}



Function Get-ComplianceServerOSVersion {

    $server_version_query = @'
SELECT "Name" as device,current_date  as date,'Server Stats - OS Version Compliance' as "exception_type"
FROM COMPLIANCE.SERVER
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING ON SERVER."Name" = EXCEPTIONTRACKING.DEVICE AND EXCEPTIONTYPE = 'Server Stats - OS Version Compliance'
where "OS Version Compliance" = 0 AND EXCEPTIONTRACKING.REASON IS NULL
'@

    $server_version = Invoke-PGSqlQuery -Type Select -Query $server_version_query | Select-Object device, date, exception_type
    if ($server_version) {
        Invoke-PGSqlQuery -Type Insert -InputObject $server_version -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false
    }

}

Function Get-ComplianceServerUpdatesExceptions {

    $server_updates_query = @'
SELECT computers.name as device,current_date  as date,'Server Updates Exclusion' as "exception_type"
FROM  "ActiveDirectory".computers
join (select member_name from "ActiveDirectory".group_members('ADM-Updates-AutoInstall-Exclusions')) exclusions on name = exclusions.member_name
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING ServerUpdatesExclusion ON lower(computers.name) = lower(ServerUpdatesExclusion.DEVICE) and ServerUpdatesExclusion.EXCEPTIONTYPE = 'Server Updates Exclusion'
where  ostype = 'Server' AND enabled = 'True' and ServerUpdatesExclusion.REASON IS NULL
'@

    $server_updates = Invoke-PGSqlQuery -Type Select -Query $server_updates_query | Select-Object device, date, exception_type
    if ($server_updates) {
        Invoke-PGSqlQuery -Type Insert -InputObject $server_updates -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false
    }

}

Function Get-ComplianceServerSecurityBaselineExceptions {

    $server_security_baseline_query = @'
SELECT upper(computers.name) AS device, current_date as date,'Server Stats - Security Baseline' as "exception_type"
FROM "ActiveDirectory".computers
JOIN ( SELECT group_members.member_name FROM "ActiveDirectory".group_members('SEC-Baseline-Exclusions'::text)) baselineexc ON computers.name = baselineexc.member_name
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING securitybaseline ON lower(computers.name) = lower(securitybaseline.DEVICE) and securitybaseline.EXCEPTIONTYPE = 'Server Stats - Security Baseline'
WHERE computers.enabled = 'True'::text AND computers.ostype = 'Server'::text AND osmajorversion = 10 AND osminorversion >= 14393 and securitybaseline.reason is null
'@
    $server_security_baseline = Invoke-PGSqlQuery -Type Select -Query $server_security_baseline_query | Select-Object device, date, exception_type
    if ($server_security_baseline) {
        Invoke-PGSqlQuery -Type Insert -InputObject $server_security_baseline -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false
    }

}

Function Get-ComplianceServerLocalAdminExceptions {

    $server_local_admin_query = @'
SELECT upper(computers.name) AS device,  current_date  as date,'Server Stats - Local Admin' as "exception_type"
   FROM "ActiveDirectory".computers
 JOIN ( SELECT group_members.member_name FROM "ActiveDirectory".group_members('SEC-LocalAdminChange-Exceptions'::text)) localadmins ON computers.name = localadmins.member_name
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING localadmin ON lower(computers.name) = lower(localadmin.DEVICE) and localadmin.EXCEPTIONTYPE = 'Server Stats - Local Admin'
  WHERE computers.enabled = 'True'::text AND computers.ostype = 'Server'::text and localadmin.reason is null
'@
    $server_local_admin = Invoke-PGSqlQuery -Type Select -Query $server_local_admin_query | Select-Object device, date, exception_type
    if ($server_local_admin) {
        Invoke-PGSqlQuery -Type Insert -InputObject $server_local_admin -Schema 'compliance' -Table 'exception_history' -OnConflict 'Do Nothing' -Truncate $false
    }

}




Function Invoke-ComplianceBitLockerUSBRemediation {

  
    $bitlocker_usb_remediation_query = @'
    SELECT distinct(device), date, "current_date", age,site,admin_email
    FROM compliance.client_bitlockerusb
    join public.site_admins using (site)
    where age >= 30
'@
    
    $bitlocker_usb_remediation = Invoke-PGSqlQuery -Type Select -Query $bitlocker_usb_remediation_query
    $sites = $bitlocker_usb_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert: BitLocker USB - $($site.name) | Remediated"
            $status = "The following devices have been removed from the group 'SEC-USB-Exceptions'."
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device
            foreach ($client in $site.group) {
                Remove-ADGroupMember -Identity 'SEC-USB-Exceptions' -Members (Get-ADComputer $client.device) -Confirm:$false
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }
}

Function Invoke-ComplianceClientSecurityBaselineRemediation {


    $client_security_baseline_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.client_secbaseline
join public.site_admins using (site)
where age >= 30
'@
    
    $client_security_baseline_remediation = Invoke-PGSqlQuery -Type Select -Query $client_security_baseline_remediation_query
    $sites = $client_security_baseline_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert: Client Security Baseline - $($site.name) | Remediated"
            $status = "The following devices have been removed from the group 'SEC-Baseline-Exclusions'."
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device
            foreach ($client in $site.group) {
                Remove-ADGroupMember -Identity 'SEC-Baseline-Exclusions' -Members (Get-ADComputer $client.device) -Confirm:$false
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }
    
}

Function Invoke-ComplianceClientSCCMExclusionsRemediation {



    $client_sccm_exclusion_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.client_sccmexclusion
join public.site_admins using (site)
where age >= 30
'@
    
    $client_sccm_exclusion_remediation = Invoke-PGSqlQuery -Type Select -Query $client_sccm_exclusion_remediation_query
    $sites = $client_sccm_exclusion_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert: SCCM Exclusion - $($site.name) | Remediated"
            $status = "The following devices have been removed from the group 'SCCM-Exclusions'."
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device
            foreach ($client in $site.group) {
                Remove-ADGroupMember -Identity 'SCCM-Exclusions' -Members (Get-ADComputer $client.device) -Confirm:$false
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }
    
}

Function Invoke-ComplianceClientLocalAdminRemediation {

    $local_admin_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.client_localadmin
join public.site_admins using (site)
where age >= 30
'@

    $local_admin_remediation = Invoke-PGSqlQuery -Type Select -Query $local_admin_remediation_query
    $sites = $local_admin_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert:  Client Local Admin - $($site.name) | Remediated"
            $status = "The following devices have been removed from the group 'SEC-LocalAdminChange-Exceptions'."
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device
            foreach ($client in $site.group) {
                Remove-ADGroupMember -Identity 'SEC-LocalAdminChange-Exceptions' -Members (Get-ADComputer $client.device) -Confirm:$false
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }
}
Function Invoke-ComplianceClientWin10OSVersionRemediation {

    $client_version_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.client_osversion_win10
join public.site_admins using (site)
where age >= 30
'@

    $client_version_remediation = Invoke-PGSqlQuery -Type Select -Query $client_version_remediation_query
    $sites = $client_version_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert:  Client OS Version - $($site.name) | Remediated"
            $status = 'The following clients have been disabled in Active Directory.'
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device

            foreach ($client in $site.group) {
                #Disable-ADAccount -Identity (Get-ADComputer $client.device) -Confirm:$False
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }

}

Function Invoke-ComplianceClientWin7OSVersionRemediation {

    $client_7_version_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.client_osversion_win7
join public.site_admins using (site)
where age >= 30
'@

    $client_7_version_remediation = Invoke-PGSqlQuery -Type Select -Query $client_7_version_remediation_query
    $sites = $client_7_version_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert:  Win7 Client OS Version - $($site.name) | Remediated"
            $status = 'The following clients have been disabled in Active Directory.'
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device

            foreach ($client in $site.group) {
                #Disable-ADAccount -Identity (Get-ADComputer $client.device) -Confirm:$False
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }

}

Function Invoke-ComplianceServerOSVersionRemediation {

    $server_version_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.server_osversion
join public.site_admins using (site)
where age >= 30
'@

    $server_version_remediation = Invoke-PGSqlQuery -Type Select -Query $server_version_remediation_query
    $sites = $server_version_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert:  Server OS Version - $($site.name) | Remediated"
            $status = 'The following servers have been disabled in Active Directory.'
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device

            foreach ($server in $site.group) {
                #Disable-ADAccount -Identity (Get-ADComputer $server.device) -Confirm:$False
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }

}

Function Invoke-ComplianceServerUpdatesExceptionRemediation {

    $server_updates_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.server_updatesexception
join public.site_admins using (site)
where age >= 30
'@

    $server_updates_remediation = Invoke-PGSqlQuery -Type Select -Query $server_updates_remediation_query
    $sites = $server_updates_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert:  Server Updates Exclusion - $($site.name) | Remediated"
            $status = "The following servers have been removed from the group 'ADM-Updates-AutoInstall-Exclusions'."
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device
            foreach ($server in $site.group) {
                Remove-ADGroupMember -Identity 'ADM-Updates-AutoInstall-Exclusions' -Members (Get-ADComputer $server.device) -Confirm:$false
            }
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }
}


Function Invoke-ComplianceServerSecurityBaselineRemediation {

    $server_security_baseline_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.server_securitybaseline
join public.site_admins using (site)
where age >= 30
'@

    $server_security_baseline_remediation = Invoke-PGSqlQuery -Type Select -Query $server_security_baseline_remediation_query
    $sites = $server_security_baseline_remediation | Group-Object -Property Site

    foreach ($site in $sites) {
        try {
            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert:  Server Security Baseline - $($site.name) | Remediated"
            $status = "The following servers have been removed from the group 'SEC-Baseline-Exclusions'."
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device

            foreach ($server in $site.group) {
                Remove-ADGroupMember -Identity 'SEC-Baseline-Exclusions' -Members (Get-ADComputer $server.device) -Confirm:$false
            }

            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }

}

Function Invoke-ComplianceServerLocalAdminRemediation {

    $server_local_admin_remediation_query = @'
SELECT distinct(device), date, "current_date", age,site,admin_email
FROM compliance.server_localadmin
join public.site_admins using (site)
where age >= 30
'@

    $server_local_admin_remediation = Invoke-PGSqlQuery -Type Select -Query $server_local_admin_remediation_query
    $sites = $server_local_admin_remediation | Group-Object -Property Site

    foreach ($site in $sites) {

        try {
            foreach ($server in $site.group) {
                Remove-ADGroupMember -Identity 'SEC-LocalAdminChange-Exceptions' -Members (Get-ADComputer $server.device) -Confirm:$false
            }

            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Exceptions Alert:  Server Local Admin - $($site.name) | Remediated"
            $status = "The following servers have been removed from the group 'SEC-LocalAdminChange-Exceptions'."
            $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } } -Unique | Sort-Object -Property Device
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        
        }
        catch {
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
        }
    }
}

Function Invoke-ComplianceAssignGrafanaTasksServerUpdates {

    $query = @'
select x.site,x."ComputerName",x."Operating System",x."Auto Install",x."Days Since Last Update", x."Failed",x."Missing",x."Downloaded",x."Pending Reboot", x."Update Exclusion Reason" ,
case when "Auto Install" != 2 and osmajorversion >= 10 and "Days Since Last Update" >= 35 and site != 'Domain Controllers' and task_title is null then 'Missing'
when  "Auto Install" != 2 and osmajorversion >= 10 and "Days Since Last Update" >= 35 and site != 'Domain Controllers' and task_title is not null then 'Assigned'
else null end as "Planner"
from (
select site,name as "ComputerName", 
operatingsystem as "Operating System",
case when saturday.member_name is null and exclusions.member_name is null then 0
when saturday.member_name is not null then 1
when exclusions.member_name is not null then 2 else 0 end as "Auto Install",
coalesce(now()::date - su."time"::date, -1) as "Days Since Last Update",
"Failed",
"Missing",
"Downloaded",
"Pending Reboot",
CASE
	WHEN exclusions.member_name is not null and ServerUpdatesExclusion.REASON IS NULL THEN 'Missing' 
	WHEN exclusions.member_name is not null and ServerUpdatesExclusion.REASON IS NOT NULL  THEN ServerUpdatesExclusion.REASON
	ELSE null END AS "Update Exclusion Reason",
	osmajorversion
from (SELECT computers.name, 
	  computers.site,
operatingsystem,
	  osmajorversion,
SUM (CASE WHEN State = '1' then 1 else 0 end) as "Failed",
SUM (CASE WHEN State = '2' then 1 else 0 end) as "Missing",
SUM (CASE WHEN State = '3' then 1 else 0 end) as "Downloaded",
SUM (CASE WHEN State = '6' then 1 else 0 end) as "Pending Reboot"
FROM  "ActiveDirectory".computers
left JOIN wsus.server_update_details on "ActiveDirectory".computers.name = server_update_details.name
where ostype = 'Server' 
AND enabled = 'True'
group by computers.name) x
left join (select member_name from "ActiveDirectory".group_members('ADM-Updates-AutoInstall-Sat2300')) saturday on name = saturday.member_name
left join (select member_name from "ActiveDirectory".group_members('ADM-Updates-AutoInstall-Exclusions')) exclusions on name = exclusions.member_name
left join (SELECT MAX("time") AS TIME,
			HOSTNAME
		FROM WSUS.SERVER_UPDATES
		GROUP BY HOSTNAME) su on name = su.hostname
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING ServerUpdatesExclusion ON lower(name) = lower(ServerUpdatesExclusion.DEVICE) and ServerUpdatesExclusion.EXCEPTIONTYPE = 'Server Updates Exclusion'
) x
left join planner.grafana_tasks on x."ComputerName" = grafana_tasks.task_title and bucket_name = 'Windows Updates - Servers' 
where "Auto Install" != 2 and osmajorversion >= 10 and "Days Since Last Update" >= 35 and site != 'Domain Controllers' and (task_title is null or grafana_tasks.createddatetime < now() - interval '30 days')
'@

    $server_update_task_machines = Invoke-PGSqlQuery -Type Select -Query $query

    foreach ($server in $server_update_task_machines) {
        New-GrafanaPlannerTask -Site $server.site -Bucket 'Windows Updates - Servers' -Title $server.ComputerName -Description "Days Since Last Update: $($server.'Days Since Last Update')" -RemoveExistingTask
    }

}

Function Send-ComplianceBitLockerUSBExceptionsAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.client_bitlockerusb
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $bitlockerusbexceptions = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $bitlockerusbexceptions | Group-Object -Property Site

    foreach ($site in $sites) {

        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: BitLocker USB - $($site.name)"
        $status = "Exception reason missing for the following devices. Devices will be removed from the group 'SEC-USB-Exceptions' automatically."
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
}
    
Function Send-ComplianceClientSCCMExclusionsAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.client_sccmexclusion
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ClientSCCMExclusions = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ClientSCCMExclusions | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: SCCM Exclusion - $($site.name)"
        $status = "Exception reason missing for the following devices. Devices will be removed from the group 'SCCM-Exclusions' automatically."
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
    
}

Function Send-ComplianceClientSecurityBaselineExceptionsAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.client_secbaseline
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ClientSecurityBaselineExceptions = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ClientSecurityBaselineExceptions | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Client Security Baseline - $($site.name)"
        $status = "Exception reason missing for the following devices. Devices will be removed from the group 'SEC-Baseline-Exclusions' automatically."
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
    
}

Function Send-ComplianceClientLocalAdminExceptionsAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.client_localadmin
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ComplianceClientLocalAdminExceptions = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ComplianceClientLocalAdminExceptions | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Client Local Admin - $($site.name)"
        $status = "Exception reason missing for the following devices. Devices will be removed from the group 'SEC-LocalAdminChange-Exceptions' automatically."
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
    
}


Function Send-ComplianceClientWin10OSVersionRemediationAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.client_osversion_win10
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ComplianceClientOSVersionRemediation = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ComplianceClientOSVersionRemediation | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Client OS Version - $($site.name)"
        $status = 'Exception reason missing for the following devices. Devices will be disabled in Active Directory automatically.'
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
    
}

Function Send-ComplianceClientWin7OSVersionRemediationAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.client_osversion_win7
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ComplianceClient7OSVersionRemediation = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ComplianceClient7OSVersionRemediation | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Win7 Client OS Version - $($site.name)"
        $status = 'Exception reason missing for the following devices. Devices will be disabled in Active Directory automatically.'
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
    
}

Function Send-ComplianceServerOSVersionRemediationAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.server_osversion
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ComplianceServerOSVersionRemediation = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ComplianceServerOSVersionRemediation | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Server OS Version - $($site.name)"
        $status = 'Exception reason missing for the following devices. Devices will be disabled in Active Directory automatically.'
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
    
}

Function Send-ComplianceServerUpdatesExceptionAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.server_updatesexception
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ComplianceServerUpdatesExceptions = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ComplianceServerUpdatesExceptions | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Server Updates Exclusion - $($site.name)"
        $status = "Exception reason missing for the following devices. Devices will be removed from the group 'ADM-Updates-AutoInstall-Exclusions' automatically."
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
}

Function Send-ComplianceServerSecurityBaselineExceptionsAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.server_securitybaseline
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ComplianceServerSecurityBaselineExceptions = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ComplianceServerSecurityBaselineExceptions | Group-Object -Property Site

    foreach ($site in $sites) { 
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Server Security Baseline - $($site.name)"
        $status = "Exception reason missing for the following devices. Devices will be removed from the group 'SEC-Baseline-Exclusions' automatically."
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
}

Function Send-ComplianceServerLocalAdminExceptionsAlert {
    $query = @'
    SELECT device, date, "current_date", age,site,admin_email
	FROM compliance.server_localadmin
	join public.site_admins using (site)
	where age in (14,21,27)
'@

    $ComplianceServerLocalAdminExceptions = Invoke-PGSqlQuery -Type Select -Query $query

    $sites = $ComplianceServerLocalAdminExceptions | Group-Object -Property Site

    foreach ($site in $sites) {
        $to = @($site.group.admin_email | Select-Object -Unique)
        $cc = @("tyler.maylock@$mycompany.com")
        $subject = "Exceptions Alert: Server Local Admin - $($site.name)"
        $status = "Exception reason missing for the following devices. Devices will be removed from the group 'SEC-LocalAdminChange-Exceptions' automatically."
        $resolution = "Please add a valid reason to the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
        $devices = $site.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Days Until Remediation'; Expression = { $countdown["$($_.age)"] } } -Unique | Sort-Object -Property Device, 'Days Until Remediation'
        Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
    }
}

Function Send-ComplianceHyperVBackupAlerts {

    if ((Get-Date).DayOfWeek -eq 'Tuesday') {
        $query = @'
SELECT site, vmhost, vmname,site_admins.*
FROM compliance.hyperv_backup_missing
join public.site_admins using (site)
'@

        $hyperv_backup_missing = Invoke-PGSqlQuery -Type Select -Query $query

        $sites = $hyperv_backup_missing | Group-Object -Property Site

        foreach ($site in $sites) {

            $to = @($site.group.admin_email | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = 'Backup Alert: Virtual Machines Missing'
            $status = 'The following virtual machines are not being backed up:'
            $resolution = @'
Please rename the virtual machine(s) to either name.nobackup, name.daily, or name.weekly. If the name is correct, open the Commvault subclient and verify the VM is included under Content > Preview.
<br><br>Also, if a VM is being replicated, be sure to rename the replica machine to _replica, otherwise VMs with duplicate names are not included.
'@
            $devices = $site.group | Select-Object @{Name = 'Host'; Expression = { $_.vmhost } }, @{Name = 'VM'; Expression = { $_.vmname } } -Unique | Sort-Object -Property Host, VM
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From '$mycompany Backup Alerts <backupalerts@$mycompany.com>' -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution -Title 'Backup Alert') -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
    }

}

Function Set-ExceptionMailBody {
    param (
        [Parameter(Mandatory = $True)]
        [object]
        $Devices,
        [Parameter(Mandatory = $True)]
        [string]
        $Status,
        [Parameter(Mandatory = $True)]
        [string]
        $Resolution,
        [string]
        $Title = 'Exception Alert'
    )
    
# adjust <img src="https://www.$mycompany.com/globalassets/email/logo.png" width="238" height="26"> accordingly to include a company logo

    $devicetable = $devices | ConvertTo-Html -Fragment
    $devicetable = $devicetable -replace '<th>(Device|Host)', '<th style="text-align: left;">Device'
    $devicetable = $devicetable -replace '<th>(Exception Type|VM)', '<th style="text-align: left;">Exception Type'
    $devicetable = foreach ($row in $devicetable) {
        [System.Text.RegularExpressions.Regex]::Replace($row , '(<td>)(?=\d+<\/td>)', "<td style=`"text-align: right;`">")
    }



    $messagebody = @"
    <!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <meta http-equiv="X-UA-Compatible" content="IE=edge">
                  <style>
                    body {
                            height: 100% !important;
                            margin: 0 !important;
                            padding: 0 !important;
                            width: 100% !important;
                        }
                    a {
                        text-decoration: none;
                        color: #007ACC;
                    }
                    body, table, td {font-family: Segoe UI, Helvetica, Arial, sans-serif !important;}
                </style>
            </head>
            <body>
            <!-- OUTER WRAPPER -->
            <div style="background:#E5E5E5; min-height:100vh; font-family: Segoe UI, Helvetica, Arial, sans-serif; color:black; font-size:14px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" height="100%">
                    <tr>
                            <td style="background: #E5E5E5;padding: 75px 0 "></td>
                            <td width="640" style="background: #E5E5E5;padding: 75px 0 ">
                                <!-- INNER WRAPPER -->
                                <table border="0" cellpadding="0" cellspacing="0" style="min-width: 100%; background: white;">
                                    <!-- LOGO -->
                                    <tr>
                                        <td style="padding: 0 32px; background: #FFFFFF;">
                                            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                                <tr>
                                                    <td>
                                                        <table border="0" cellpadding="0" cellspacing="0">
                                                            <tr>
                                                                <td align="" valign="top" style="padding: 24px 0;">
                                                                    <img src="https://www.$mycompany.com/globalassets/email/logo.png" width="238" height="26">
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- /LOGO -->
                                    <tr>
                                        <td valign="middle" style="padding: 0;">
                                            <table border="0" cellspacing="0" cellpadding="0" width="100%">
                                                <tr>
                                                    <td style="background-color:white;font-size:28px;color:black;padding:0 32px">
                                                        <p style="margin: 0"><strong>$Title</strong></p>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- SECTION MAIN -->
                                    <tr>
                                        <td valign="middle" style="padding: 32px; background:white;">
                                            <table border="0" cellspacing="0" cellpadding="0">
                                                <tr>
                                                    <td style="margin: 0 0 15px">
                                                         <div>
                                                         <div>
                                                            <p style="margin: 0px 0 6px"><strong>Status</strong></p>
                                                            <p style="margin: 0px 0 0px">$status</p>
                                                         </div>
                                                         <br></br>
                                                         $devicetable
                                                        <div>
                                                        <p style="margin: 30px 0 6px"><strong>Resolution</strong></p>
                                                        <p style="margin: 0">$Resolution</p>
                                                     </div>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- FOOTER -->
                                    <tr>
                                        <td style="padding: 0 32px;">
                                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="min-width:100%;">
                                                <tr>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- /FOOTER -->
                                </table>
                            </td>
                            <td style="background: #E5E5E5;padding: 75px 0"></td>
                        </tr>
                    </table>
                </div>
        </html><!-- cV: W5QodS5LYUmVCwxH.4.1.1.3 -->
"@
    
    
    
    

    return $messagebody
    

}

Function Set-ExceptionRemediationMailBody {
    param (
        [Parameter(Mandatory = $True)]
        [object]
        $Devices,
        [Parameter(Mandatory = $True)]
        [string]
        $Status
    )

  # adjust <img src="https://www.$mycompany.com/globalassets/email/logo.png" width="238" height="26"> accordingly to include a company logo


    $devicetable = $devices | ConvertTo-Html -Fragment
    $devicetable = $devicetable -replace '<th>Device', '<th style="text-align: left;">Device'
    $devicetable = $devicetable -replace '<th>Exception Type', '<th style="text-align: left;">Exception Type'
    $devicetable = foreach ($row in $devicetable) {
        [System.Text.RegularExpressions.Regex]::Replace($row , '(<td>)(?=\d+<\/td>)', "<td style=`"text-align: right;`">")
    }


    $messagebody = @"
    <!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <meta http-equiv="X-UA-Compatible" content="IE=edge">
                  <style>
                    body {
                            height: 100% !important;
                            margin: 0 !important;
                            padding: 0 !important;
                            width: 100% !important;
                        }
                    a {
                        text-decoration: none;
                        color: #007ACC;
                    }
                    body, table, td {font-family: Segoe UI, Helvetica, Arial, sans-serif !important;}
                </style>
            </head>
            <body>
            <!-- OUTER WRAPPER -->
            <div style="background:#E5E5E5; min-height:100vh; font-family: Segoe UI, Helvetica, Arial, sans-serif; color:black; font-size:14px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" height="100%">
                    <tr>
                            <td style="background: #E5E5E5;padding: 75px 0 "></td>
                            <td width="640" style="background: #E5E5E5;padding: 75px 0 ">
                                <!-- INNER WRAPPER -->
                                <table border="0" cellpadding="0" cellspacing="0" style="min-width: 100%; background: white;">
                                    <!-- LOGO -->
                                    <tr>
                                        <td style="padding: 0 32px; background: #FFFFFF;">
                                            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                                <tr>
                                                    <td>
                                                        <table border="0" cellpadding="0" cellspacing="0">
                                                            <tr>
                                                                <td align="" valign="top" style="padding: 24px 0;">
                                                                    <img src="https://www.$mycompany.com/globalassets/email/logo.png" width="238" height="26">
                                                                </td>
                                                            </tr>
                                                        </table>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- /LOGO -->
                                    <tr>
                                        <td valign="middle" style="padding: 0;">
                                            <table border="0" cellspacing="0" cellpadding="0" width="100%">
                                                <tr>
                                                    <td style="background-color:white;font-size:28px;color:black;padding:0 32px">
                                                        <p style="margin: 0"><strong>Exception Alert</strong></p>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- SECTION MAIN -->
                                    <tr>
                                        <td valign="middle" style="padding: 32px; background:white;">
                                            <table border="0" cellspacing="0" cellpadding="0">
                                                <tr>
                                                    <td style="margin: 0 0 15px">
                                                         <div>
                                                         <div>
                                                            <p style="margin: 0px 0 6px"><strong>Status</strong></p>
                                                            <p style="margin: 0px 0 0px">$status</p>
                                                         </div>
                                                         <br></br>
                                                         $devicetable
                                                        <div>
                                                     </div>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- FOOTER -->
                                    <tr>
                                        <td style="padding: 0 32px;">
                                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="min-width:100%;">
                                                <tr>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <!-- /FOOTER -->
                                </table>
                            </td>
                            <td style="background: #E5E5E5;padding: 75px 0"></td>
                        </tr>
                    </table>
                </div>
        </html><!-- cV: W5QodS5LYUmVCwxH.4.1.1.3 -->
"@
    
    
    
    

    return $messagebody
    

}


Function Send-ComplianceExceptionTrackingYearlyReviewAlert {
    $query = @'
    SELECT admin, device,  exceptiontype, id, reason, dateofreview
    FROM compliance.exceptiontracking
    WHERE DATE_PART('year', dateofreview) <= DATE_PART('year', NOW() - INTERVAL '1 year')
      AND DATE_PART('month', dateofreview) = DATE_PART('month', NOW() )
'@



    $TotalDaysInMonth = Get-TotalDaysInMonth
    $DaysLeftInMonth = Get-DaysLeftInMonth


    $devices = Invoke-PGSqlQuery -Type Select -Query $query

    $expiration = @(
        14, 
        7,  
        3
    )

    if ($TotalDaysInMonth -eq $DaysLeftInMonth -or $DaysLeftInMonth -in $expiration) {
    
        $month = (Get-Date).ToString('MMMM')
        $admindevices = $devices | Group-Object -Property admin

        foreach ($admin in $admindevices) {

            $to = @($admin.group.admin | Select-Object -Unique)
            $cc = @("tyler.maylock@$mycompany.com")
            $subject = "Yearly Exceptions Review: $month"
            $status = 'Yearly review required for the following exceptions.'
            $resolution = "Please update the `"Date of Review`" column in the <a href = `"https://$mycompany.sharepoint.com/sites/site/Lists/Compliance%20Tracking/AllItems.aspx`">Exception Tracking List</a>."
            $devices = $admin.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Exception Type'; Expression = { $_.ExceptionType } }, @{Name = 'Days Until Removal'; Expression = { $DaysLeftInMonth } } -Unique | Sort-Object -Property Device, 'Days Until Removal'
            Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionMailBody -Devices $devices -Status $status -Resolution $resolution) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        }
    }
}


Function Invoke-ComplianceExceptionTrackingYearlyReviewRemediation {
    Get-ExceptionTrackingList
    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Exception Tracking' -Connection $SharePoint
    $items = Get-PnPListItem -List $list -Connection $SharePoint


    $query = @'
    SELECT admin, device,  exceptiontype, id, reason, dateofreview
    FROM compliance.exceptiontracking
    WHERE DATE_PART('year', dateofreview) <= DATE_PART('year', NOW() - INTERVAL '1 year')
      AND DATE_PART('month', dateofreview) = DATE_PART('month', NOW() )
'@


    $DaysLeftInMonth = Get-DaysLeftInMonth
    $devices = Invoke-PGSqlQuery -Type Select -Query $query


    if ($DaysLeftInMonth -eq 1) {
    
        $month = (Get-Date).ToString('MMMM')
        $year = (Get-Date).AddYears(-1).Year
        $admindevices = $devices | Group-Object -Property admin

        foreach ($admin in $admindevices) {

            try {
                foreach ($device in $admin.group) {
                    Remove-PnPListItem -List $list -Connection $SharePoint -Identity ($items | Where-Object { $_.id -eq $device.id }) -Force
                }

                $to = @($admin.group.admin | Select-Object -Unique)
                $cc = @("tyler.maylock@$mycompany.com")
                $subject = "Yearly Exceptions Review: $month - $year | Remediated"
                $status = 'The following exceptions have been deleted.'
                $devices = $admin.group | Select-Object @{Name = 'Device'; Expression = { $_.Device } }, @{Name = 'Exception Type'; Expression = { $_.ExceptionType } } | Sort-Object -Property Device, 'Exception Type'
                Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To $to -Subject $subject -Body (Set-ExceptionRemediationMailBody -Devices $devices -Status $status) -BodyAsHtml -Cc $cc -WarningAction SilentlyContinue
        
            }
            catch {
                Send-MailMessage -SmtpServer "smtp.$mycompany.com" -From "$mycompany Exception Alerts <exceptionalerts@$mycompany.com>" -To "tyler.maylock@$mycompany.com" -Subject $subject -Body $_.exception -WarningAction SilentlyContinue
            }
        }
    }
}

Function Invoke-ComplianceExceptionTrackingMissingDeviceCleanup {

    Get-ExceptionTrackingList

    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Exception Tracking' -Connection $SharePoint
    $items = Get-PnPListItem -List $list -Connection $SharePoint

    $devicequery = @'
SELECT admin, device, computers.enabled, exceptiontype, id, reason, dateofreview
	FROM compliance.exceptiontracking
	left join "ActiveDirectory".computers on lower(device) = lower(computers.name)
	where enabled is null
'@

    $devices = Invoke-PGSqlQuery -Type Select -Query $devicequery


    
    try {
        foreach ($device in $devices) {
            Remove-PnPListItem -List $list -Identity ($items | Where-Object { $_.id -eq $device.id }) -Connection $SharePoint -Force
        }
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}

Function Invoke-ComplianceExceptionHistoryDeviceCleanup {

    $query = @'
	delete from compliance.exception_history
	where (date,device,exception_type) in (
	select exception_history.date,exception_history.device,exception_history.exception_type from compliance.exception_history
	left join "ActiveDirectory".computers on exception_history.device = computers.name
	where computers.name is null
	and date < now() - interval '30 days'
	)
'@

    $query2 = @'
delete from compliance.exception_history
where (date,device,exception_type) in (
SELECT date, device, exception_type
FROM compliance.exception_overview
where reason is null 
and (CURRENT_DATE - date > 30)
and exception_type in ('Client Stats - OS Version Compliance','Server Stats - OS Version Compliance')
)
'@
    
    try {
        Invoke-PGSqlQuery -Type Select -Query $query
        Invoke-PGSqlQuery -Type Select -Query $query2
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}

Function Invoke-ComplianceExceptionTrackingAdminReplacement {
    # Use this if you have a site admin who leaves or their email address changes, otherwise those email alerts don't go anywhere...
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $OldAdminEmail,
        [Parameter(Mandatory = $true)]
        [string]
        $NewAdminEmail
    )
    $OldAdminEmail = '@$mycompany.com'
    $NewAdminEmail = '@$mycompany.com'

    Get-ExceptionTrackingList

    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Exception Tracking' -Connection $SharePoint

    $devicequery = @"
    SELECT admin, device, exceptiontype, id, reason, dateofreview
	FROM compliance.exceptiontracking
	where admin ~* '$OldAdminEmail'
"@

    $devices = Invoke-PGSqlQuery -Type Select -Query $devicequery

    
    try {
        foreach ($device in $devices) {
            Set-PnPListItem -List $list -Id $device.id -Connection $SharePoint -Values @{'Admin' = "$NewAdminEmail" }
        }
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule 'Manual'
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule 'Manual'
    }
    
}

Function Invoke-ComplianceExceptionAdminEmailFix {

    Get-ExceptionTrackingList
    
    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Exception Tracking' -Connection $SharePoint

    $adminnames = @{

    }

    $devicequery = @'
            SELECT admin, users.mail, users.enabled, device, site, exceptiontype, id, reason, dateofreview
            FROM compliance.exceptiontracking
            left join "ActiveDirectory".users on lower(admin) = lower(users.mail)
            where users.mail is null
            and admin like 'account_%'
            order by admin,device
'@
        
    $devices = Invoke-PGSqlQuery -Type Select -Query $devicequery
    $admins = $devices | Group-Object -Property admin
    foreach ($admin in $admins) {
        $aduser = $null

        $regularuser = ($admin.Name -replace 'account_', '').Split('@')[0]
        if ($regularuser -in $adminnames.Keys) {
            $regularuser = $adminnames["$regularuser"]
        }
        try {
            $aduser = Get-ADUser -Identity $regularuser -ErrorAction SilentlyContinue -Properties 'mail'
            if ($aduser) {
                foreach ($item in $admin.group) {
                    Set-PnPListItem -List $list -Id $item.id -Connection $SharePoint -Values @{'Admin' = "$($aduser.mail)" }
                }
            }
        }
        catch {
            Write-Error "Could not find $regularuser"
        }
    }
        
}

Function Invoke-ComplianceBitLockerOSDGroupRemediation {

    $query = @'
SELECT 
concat(BITLOCKER_OSDrive.DEVICE,'$') as device
FROM COMPLIANCE.BITLOCKER_OSDrive
LEFT JOIN COMPLIANCE.EXCEPTIONTRACKING ON BITLOCKER_OSDrive.Device = EXCEPTIONTRACKING.DEVICE AND EXCEPTIONTYPE = 'BitLocker - OSDComplianceStatus'
left join (select member_name as device from "ActiveDirectory".group_members('SEC-Bitlocker')) bitlocker on BITLOCKER_OSDrive.device = bitlocker.device
where COMPLIANCESTATUSDETAILS = 50
and bitlocker.device is null
order by 1
'@

    $adgroupmissing = Invoke-PGSqlQuery -Type Select -Query $query

    try {
        Add-ADGroupMember -Members $adgroupmissing.device -Identity 'SEC-Bitlocker' -Server $domain_controller
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
    
}

Function Invoke-ComplianceScheduledFunction {
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
            Write-Output 'Get-ComplianceLocalRiskAssessmentListItems'; Get-ComplianceLocalRiskAssessmentListItems
        }
        
        'Daily' {
            Write-Output 'Invoke-ComplianceExceptionTrackingMissingDeviceCleanup'; Invoke-ComplianceExceptionTrackingMissingDeviceCleanup
            Write-Output 'Invoke-ComplianceExceptionHistoryDeviceCleanup'; Invoke-ComplianceExceptionHistoryDeviceCleanup
            Write-Output 'Get-ComplianceBitLockerUSBExceptions'; Get-ComplianceBitLockerUSBExceptions
            Write-Output 'Get-ComplianceClientSCCMExclusions'; Get-ComplianceClientSCCMExclusions
            Write-Output 'Get-ComplianceClientSecurityBaselineExceptions'; Get-ComplianceClientSecurityBaselineExceptions
            Write-Output 'Get-ComplianceClientLocalAdminExceptions'; Get-ComplianceClientLocalAdminExceptions
            Write-Output 'Get-ComplianceClientWin10OSVersion'; Get-ComplianceClientWin10OSVersion
            Write-Output 'Get-ComplianceClientWin7OSVersion'; Get-ComplianceClientWin7OSVersion
            Write-Output 'Get-ComplianceServerOSVersion'; Get-ComplianceServerOSVersion
            Write-Output 'Get-ComplianceServerUpdatesExceptions'; Get-ComplianceServerUpdatesExceptions
            Write-Output 'Get-ComplianceServerSecurityBaselineExceptions'; Get-ComplianceServerSecurityBaselineExceptions
            Write-Output 'Get-ComplianceServerLocalAdminExceptions'; Get-ComplianceServerLocalAdminExceptions
            Write-Output 'Send-ComplianceBitLockerUSBExceptionsAlert'; Send-ComplianceBitLockerUSBExceptionsAlert
            Write-Output 'Send-ComplianceClientSCCMExclusionsAlert'; Send-ComplianceClientSCCMExclusionsAlert
            Write-Output 'Send-ComplianceClientSecurityBaselineExceptionsAlert'; Send-ComplianceClientSecurityBaselineExceptionsAlert
            Write-Output 'Send-ComplianceClientLocalAdminExceptionsAlert'; Send-ComplianceClientLocalAdminExceptionsAlert
            Write-Output 'Send-ComplianceClientWin10OSVersionRemediationAlert'; Send-ComplianceClientWin10OSVersionRemediationAlert
            Write-Output 'Send-ComplianceClientWin7OSVersionRemediationAlert'; Send-ComplianceClientWin7OSVersionRemediationAlert
            Write-Output 'Send-ComplianceServerOSVersionRemediationAlert'; Send-ComplianceServerOSVersionRemediationAlert
            Write-Output 'Send-ComplianceServerUpdatesExceptionAlert'; Send-ComplianceServerUpdatesExceptionAlert
            Write-Output 'Send-ComplianceServerSecurityBaselineExceptionsAlert'; Send-ComplianceServerSecurityBaselineExceptionsAlert
            Write-Output 'Send-ComplianceServerLocalAdminExceptionsAlert'; Send-ComplianceServerLocalAdminExceptionsAlert
            Write-Output 'Send-ComplianceHyperVBackupAlerts'; Send-ComplianceHyperVBackupAlerts
            Write-Output 'Invoke-ComplianceBitLockerUSBRemediation'; Invoke-ComplianceBitLockerUSBRemediation
            Write-Output 'Invoke-ComplianceClientSCCMExclusionsRemediation'; Invoke-ComplianceClientSCCMExclusionsRemediation
            Write-Output 'Invoke-ComplianceClientSecurityBaselineRemediation'; Invoke-ComplianceClientSecurityBaselineRemediation
            Write-Output 'Invoke-ComplianceClientLocalAdminRemediation'; Invoke-ComplianceClientLocalAdminRemediation
            #Write-Output 'Invoke-ComplianceClientWin10OSVersionRemediation'; Invoke-ComplianceClientWin10OSVersionRemediation
            #Write-Output 'Invoke-ComplianceClientWin7OSVersionRemediation'; Invoke-ComplianceClientWin7OSVersionRemediation
            #Write-Output 'Invoke-ComplianceServerOSVersionRemediation'; Invoke-ComplianceServerOSVersionRemediation
            Write-Output 'Invoke-ComplianceServerUpdatesExceptionRemediation'; Invoke-ComplianceServerUpdatesExceptionRemediation
            Write-Output 'Invoke-ComplianceServerSecurityBaselineRemediation'; Invoke-ComplianceServerSecurityBaselineRemediation
            Write-Output 'Invoke-ComplianceServerLocalAdminRemediation'; Invoke-ComplianceServerLocalAdminRemediation
            Write-Output 'Send-ComplianceExceptionTrackingYearlyReviewAlert'; Send-ComplianceExceptionTrackingYearlyReviewAlert
            #Write-Output 'Invoke-ComplianceExceptionTrackingYearlyReviewRemediation'; Invoke-ComplianceExceptionTrackingYearlyReviewRemediation
            Write-Output 'Invoke-ComplianceBitLockerOSDGroupRemediation'; Invoke-ComplianceBitLockerOSDGroupRemediation
            Write-Output 'Invoke-ComplianceAssignGrafanaTasksServerUpdates'; Invoke-ComplianceAssignGrafanaTasksServerUpdates
            
        }
    }


}
