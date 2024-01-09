
Function Get-QualysVulnerabilityCSV {
    #Sharepoint List "Qualys Report Links" on "" Team is populated via PowerAutomate Flow "Extract Qualys Link"
    <#
    We are only given a CSV export of our Qualys data from a 3rd party vendor, we get the report link using a Flow and then save it to a SharePoint List. 
    This function downloads that report to memory without saving to disk and then parses the relevant CSV information using "$match = $content | Select-String -Pattern $string" because for whatever reason this file has about 4 csv files merged together... good times!.
    
    #> 
    $string = '"IP","Network","DNS","NetBIOS","Tracking Method","OS","IP Status","QID","Title","Vuln Status","Type","Severity","Port","Protocol","FQDN","SSL","First Detected","Last Detected","Times Detected","Date Last Fixed","CVE ID","Vendor Reference","Bugtraq ID","CVSS","CVSS Base","CVSS Temporal","CVSS Environment","CVSS3.1","CVSS3.1 Base","CVSS3.1 Temporal","Threat","Impact","Solution","Exploitability","Associated Malware","PCI Vuln","Ticket State","Instance","Category","Associated Tags"(,"Source)?'
    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Qualys Report Links' -Connection $SharePoint
    $items = Get-PnPListItem -List $list -Connection $SharePoint
    $daily = $items | Where-Object { ([datetime]$_.FieldValues.Title).ToString('yyyy-MM-dd') -eq ([datetime]::now).ToString('yyyy-MM-dd')  -and $_.FieldValues.Imported -eq $false -and $_.FieldValues.ScanType -eq 'Daily' }
    $weekly = $items | Where-Object { ([datetime]$_.FieldValues.Title).ToString('yyyy-MM-dd') -eq ([datetime]::now).ToString('yyyy-MM-dd') -and $_.FieldValues.Imported -eq $false -and $_.FieldValues.ScanType -eq 'Weekly' }
    if ($daily) {

        $request = [System.Net.WebRequest]::Create($daily.FieldValues.Link.Url)
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        [void]$reader.Dispose()
        [void]$response.Dispose()
        $content = $content -split "`n"

        if ($content) {
            $match = $content | Select-String -Pattern $string
            if ($match) { 
                try {
                    $vuln = $content | Select-Object -Skip ($match.linenumber - 1) 
                    $inputobject = $vuln -join "`r`n" | ConvertFrom-Csv | Select-Object *, @{Name = 'CVSS3_1'; Expression = { $_.'CVSS3.1' } } , @{Name = 'CVSS3_1 Base'; Expression = { $_.'CVSS3.1 Base' } }, @{Name = 'CVSS3_1 Temporal'; Expression = { $_.'CVSS3.1 Temporal' } } -ExcludeProperty "CVSS3.1", "CVSS3.1 Base", "CVSS3.1 Temporal" #-Unique
                    $inputobject = $inputobject.Where({ [string]$_.QID -ne '' -and ([datetime]$_.'Last Detected').Date -eq (Get-Date).Date -and $_.'Tracking Method' -ne 'IP'})
                    Invoke-PGSqlQuery -Type Insert -InputObject ($inputobject) -Schema 'qualys' -Table 'vulnerabilities' -OnConflict 'Set Excluded' -Truncate $true
                    Set-PnPListItem -List $list -Identity $daily -Values @{'Imported' = 'True' } -Connection $SharePoint
                    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) - Daily" -Severity 1 -Schedule $Schedule
                }
                catch {
                    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
                }
                finally {
                    $content = $null
                    $inputobject = $null
                }
            }
        }
    }

    if ($weekly) {

        $request = [System.Net.WebRequest]::Create($weekly.FieldValues.Link.Url)
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        [void]$reader.Dispose()
        [void]$response.Dispose()
        $content = $content -split "`n"

        if ($content) {
            $match = $content | Select-String -Pattern $string
            if ($match) { 
                try {
                    $vuln = $content | Select-Object -Skip ($match.linenumber - 1) 
                    $inputobject = $vuln -join "`r`n" | ConvertFrom-Csv | Select-Object *, @{Name = 'CVSS3_1'; Expression = { $_.'CVSS3.1' } } , @{Name = 'CVSS3_1 Base'; Expression = { $_.'CVSS3.1 Base' } }, @{Name = 'CVSS3_1 Temporal'; Expression = { $_.'CVSS3.1 Temporal' } } -ExcludeProperty "CVSS3.1", "CVSS3.1 Base", "CVSS3.1 Temporal" #-Unique
                    $inputobject = $inputobject.Where({ [string]$_.QID -ne '' -and $_.'Tracking Method' -eq 'IP' -and $_.port -ne ''})
                    Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema 'qualys' -Table 'network_scan' -OnConflict 'Set Excluded' -Truncate $true
                    Set-PnPListItem -List $list -Identity $weekly -Values @{'Imported' = 'True' } -Connection $SharePoint
                    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name) - Weekly" -Severity 1 -Schedule $Schedule
                }
                catch {
                    Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
                }
                finally {
                    $content = $null
                    $inputobject = $null
                }
            }
        }
    }
}


Function Get-QualysQIDTotals {
    $query = @'
    insert into qualys.network_scan_qid_history (
        select now()::date, qid, count(*) as total, severity
        from qualys.network_scan
        where tracking_method = 'IP'
        group by qid,severity
        ) on conflict (date,qid,severity) do update set total=EXCLUDED.total;
    
        insert into qualys.qid_history(
        select now()::date,qid,count(*) as total,severity
        FROM QUALYS.VULNERABILITIES
        group by qid,severity
        ) on conflict (date,qid,severity) do update set total=EXCLUDED.total;
'@

    try {
        Invoke-PGSqlQuery -Type Select -Query $query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Get-QualysVulnCategoryTotals {
    
    $query = @'
	insert into qualys.vuln_category_history (
    SELECT 	count(*) as total,
	CATEGORY,
    now()::date
    FROM QUALYS.VULNERABILITIES
    group by CATEGORY
	) on conflict (category, date) do update set total=EXCLUDED.total;

	insert into qualys.network_scan_vuln_category_history (
    SELECT 	count(*) as total,
	CATEGORY,
    now()::date
    from qualys.network_scan
    where tracking_method = 'IP'
    group by CATEGORY
	) on conflict (category, date) do update set total=EXCLUDED.total;
'@

    try {
        Invoke-PGSqlQuery -Type Select -Query $query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}


Function Get-QualysVulnOSTotals {
    $query = @'
	insert into qualys.vuln_os_history(
    SELECT now()::date, os, count(*) as total
    FROM qualys.Vulnerabilities
    where os is not null
    group by os
	) on conflict (date,os) do update set total=EXCLUDED.total;

	insert into qualys.network_scan_vuln_os_history (
    SELECT now()::date, case when os is null then 'N/A' else os end, count(*) as total
    from qualys.network_scan
    where tracking_method = 'IP'
    group by os
	) on conflict (date,os) do update set total=EXCLUDED.total;
'@

    try {
        Invoke-PGSqlQuery -Type Select -Query $query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-QualysVulnSiteTotals {
  
    $query = @"
    insert into qualys.vuln_site_history(
        select count(qid) as total,site,now()::date
      from qualys.Vulnerabilities
      right join "ActiveDirectory".subnets on v_vulnerabilities.ip << subnets.name
      where site is not null and site not in ('HUW','VAN')
      group by site
          ) on conflict (site,date) do update set total=EXCLUDED.total;
      
          insert into qualys.network_scan_vuln_site_history (
              select count(qid) as total,site,now()::date
          from qualys.network_scan
          right join "ActiveDirectory".subnets on network_scan.ip << subnets.name
          where tracking_method = 'IP' and site is not null
          group by site
          ) on conflict (site,date) do update set total=EXCLUDED.total;
"@

    try {
        Invoke-PGSqlQuery -Type Select -Query $query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-QualysVulnSeverityTotals {
    $query = @'
	insert into qualys.vuln_severity_history(
    SELECT 	now()::date,
	severity,
    count(*) as total
    FROM QUALYS.VULNERABILITIES
    group by severity
	) on conflict (date,severity) do update set total=EXCLUDED.total;

	insert into qualys.network_scan_vuln_severity_history (
    SELECT 	now()::date,
	severity,
    count(*) as total
	from qualys.network_scan	
    where tracking_method = 'IP'
    group by severity
	) on conflict (date,severity) do update set total=EXCLUDED.total;
'@

    try {
        Invoke-PGSqlQuery -Type Select -Query $query
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }

}

Function Get-QualysExceptionsList {
    $cred = Get-O365Creds
    $SPSite = "https://$mycompany.sharepoint.com/sites/site"
    $SharePoint = Connect-PnPOnline -Url $SPSite -Credentials $cred -ReturnConnection
    $list = Get-PnPList -Identity 'Qualys Exceptions' -Connection $SharePoint
    $items = Get-PnPListItem -List $list -Connection $SharePoint
  
    $properties = @(
        @{name = 'QID'; expression = { $_.Title } }, 
        @{name = 'dns'; expression = { $_.Hostname } }, 
        @{name = 'Reason'; expression = { $_.Reason } }, 
        @{name = 'DateOfReview'; expression = { $_.DateofReview } },
        @{name = 'EndDate'; expression = { $_.EndDate } }
    )

  
    $inputobject = $items.FieldValues | Select-Object -Property $properties 
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'qualys' -Table 'exceptions' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}



Function Invoke-QualysScheduledFunction {
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
            Write-Output 'Get-QualysVulnerabilityCSV'; Get-QualysVulnerabilityCSV
            Write-Output 'Get-QualysQIDTotals'; Get-QualysQIDTotals
            Write-Output 'Get-QualysVulnCategoryTotals'; Get-QualysVulnCategoryTotals 
            Write-Output 'Get-QualysVulnOSTotals'; Get-QualysVulnOSTotals
            Write-Output 'Get-QualysVulnSiteTotals'; Get-QualysVulnSiteTotals
            Write-Output 'Get-QualysVulnSeverityTotals'; Get-QualysVulnSeverityTotals
            Write-Output 'Get-QualysExceptionsList'; Get-QualysExceptionsList
        }
        'Daily' {

        }
    }
  
    
}

