Function Get-DefenderATPIncidentHeaders {

    
    $resourceAppIdUri = 'https://api.security.microsoft.com'
    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $body = [Ordered] @{
        resource      = "$resourceAppIdUri"
        client_id     = "$ClientID"
        client_secret = "$ClientSecret"
        grant_type    = 'client_credentials'
    }
    $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
    $aadToken = $response.access_token
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $aadToken" 
    }
    return $headers

}
Function Get-DefenderATPHeaders {

    if ([int]$DFEAuthResponse.expires_on -lt [int](Get-Date (Get-Date).AddSeconds(30).ToUniversalTime() -UFormat "%s")) {
    
        $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
        $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        $body = [Ordered] @{
            resource      = "$resourceAppIdUri"
            client_id     = "$ClientID"
            client_secret = "$ClientSecret"
            grant_type    = 'client_credentials'
        }
        $global:DFEAuthResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
    }
    $DFEToken = $DFEAuthResponse.access_token
    $DFEAuthHeaders = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $DFEToken" 
    }
    return $DFEAuthHeaders
}

Function Get-DefenderforEndpointPagedData($Uri) {
    $Data = @()
    $Headers = Get-DefenderATPHeaders
    $Response = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers
    $Data += $Response.value
    $nextLink = $Response.'@odata.nextLink'
    while ($null -ne $nextLink) {
        $Response = (Invoke-RestMethod -Uri $nextLink -Headers $Headers -Method Get)
        $nextLink = $Response.'@odata.nextLink'
        $Data += $Response.value
    }
    return $Data
}

Function Get-DefenderForEndpointIndicators {
  
    $url = 'https://api-us.securitycenter.windows.com/api/indicators'
    $indicators = Get-DefenderforEndpointPagedData -Uri $url 
    $properties = @(
        "action",
        "additionalinfo",
        "application",
        "bypassdurationhours",
        "category" ,
        "certificateinfo",
        "createdby",
        "createdbydisplayname",
        "createdbysource",
        "creationtimedatetimeutc",
        "description",
        "educateurl",
        "expirationtime",
        "externalid",
        "generatealert",
        "historicaldetection",
        "id" ,
        "indicatortype",
        "indicatorvalue",
        "lastupdatedby",
        "lastupdatetime",
        "lookbackperiod",
        @{Name='mitretechniques';Expression={$_.mitretechniques | ConvertTo-Json -WarningAction SilentlyContinue}},
        "notificationbody",
        "notificationid",
        @{Name='rbacgroupids';Expression={$_.rbacgroupids | ConvertTo-Json -WarningAction SilentlyContinue}},
        @{Name='rbacgroupnames';Expression={$_.rbacgroupnames | ConvertTo-Json -WarningAction SilentlyContinue}},
        "recommendedactions",
        "severity",
        "title",
        "version"
    )
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject ($indicators | Select-Object -Property $properties) -OnConflict 'Do Nothing' -Schema 'defenderatp' -Table 'indicators' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-DefenderATPMachines {
    $url = 'https://api-us.securitycenter.windows.com/api/machines'
    $machines = Get-DefenderforEndpointPagedData -Uri $url | Select-Object *, @{name = 'name'; expression = { $_.computerDnsName.Replace("$dns_suffix", '').ToUpper() } }
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $machines -OnConflict 'Do Nothing' -Schema 'defenderatp' -Table 'machines' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-DefenderATPCanbeOnboardedMachines {
    $headers = Get-DefenderATPHeaders 
    $url = "https://api-us.securitycenter.windows.com/api/machines?`$filter=onboardingStatus eq 'CanBeOnboarded'"
    $machines = (Invoke-RestMethod -Uri $url -Headers $headers -Method Get).value | Select-Object *, @{name = 'name'; expression = { $_.computerDnsName.Replace("$dns_suffix", '').ToUpper() } }
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $machines -OnConflict 'Do Nothing' -Schema 'defenderatp' -Table 'canbeonboardedmachines' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-DefenderATPIncidents {
    $seconds = (Get-Date).Second
    $minutes = (Get-Date).Minute
    $date = (Get-Date).ToUniversalTime().AddDays(-8).AddMinutes(-$minutes).AddSeconds(-$seconds).ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
    $IncidentsURL = "https://api-us.security.microsoft.com/api/incidents?`$filter=lastUpdateTime ge $date"
    $HeaderParams = Get-DefenderATPIncidentHeaders
    $incidents = @()
    try {  
        $incidentRaw = (Invoke-RestMethod -Uri $IncidentsURL -Method Get -Headers $HeaderParams)
        $incidents += $incidentRaw.value
        while ($incidentRaw.'@odata.nextlink') {
            $incidentRaw = (Invoke-RestMethod -Uri $($incidentRaw.'@odata.nextlink') -Headers $HeaderParams -Method Get)
            $incidents += $incidentRaw.value
        }
    }
    catch {
        $_.Exception
    }
    if ($incidents.count -gt 0) {
        $inputobject = $incidents | Select-Object * -Unique
        $inputobject = $incidents | Select-Object *, @{name = 'alerts'; expression = { $_.alerts | ConvertTo-Json -Compress -WarningAction SilentlyContinue } } -ExcludeProperty alerts
        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'defenderatp' -Table 'incidents' -Truncate $false
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }    

}   

Function Get-DefenderATPDeviceLogons {
    
    $query = @"
DeviceLogonEvents 
    | where ActionType == @'LogonSuccess'
    | where AccountDomain == @'$mycompany'
    | where Timestamp > ago(30d)
    | join (DeviceInfo
    //| where DeviceType == @'Workstation'
    | summarize max(Timestamp) by DeviceId,DeviceType) on DeviceId
    | summarize by DeviceName,AccountName,DeviceType
"@

    $json = [PSCustomObject]@{
        Query = $query
    } | ConvertTo-Json -Compress


    $url = 'https://api-us.securitycenter.microsoft.com/api/advancedqueries/run'
    $result = Invoke-RestMethod -Uri $url -Headers (Get-DefenderATPHeaders) -Method post -Body $json

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $result.Results -OnConflict 'Do Nothing' -Schema 'defenderatp' -Table 'devicelogonsuccess' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-DefenderForEndpointDeviceNetworkInfo {
    
    $query = @"
    DeviceNetworkInfo
    //| summarize arg_max(Timestamp, *) by DeviceId,MacAddress
    | mvexpand parse_json(IPAddresses)
    | extend IP=tostring(IPAddresses.IPAddress)
    | where ipv4_is_in_range(IP,'10.0.0.0/8') 
    and not(DeviceName matches regex "switch\\d+") 
    and NetworkAdapterType != 'Wireless80211' 
    //exclude switches from devices returned based on vendor and IP
    and not(NetworkAdapterVendor == 'Cisco Systems, Inc' and IP matches regex ".$")
    and MacAddress != ''
    | distinct DeviceId,DeviceName,MacAddress,NetworkAdapterStatus,NetworkAdapterType,NetworkAdapterVendor,IP
"@

    $json = [PSCustomObject]@{
        Query = $query
    } | ConvertTo-Json -Compress


    $url = 'https://api-us.securitycenter.microsoft.com/api/advancedqueries/run'
    $result = Invoke-RestMethod -Uri $url -Headers (Get-DefenderATPHeaders) -Method post -Body $json

    $properties = @(
        'deviceid',
        'timestamp',
        'devicename',
        'networkadaptername',
        'macaddress',
        'networkadaptertype',
        'networkadapterstatus',
        'tunneltype',
        'connectednetworks',
        'dnsaddresses',
        'ipv4dhcp',
        'ipv6dhcp',
        'defaultgateways',
        'ipaddresses',
        'reportid',
        'networkadaptervendor'
    )

    $inputobject = $result.Results | Select-Object -Property $properties



    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'defenderatp' -Table 'devicenetworkinfo' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}


Function Get-DefenderforEndpointFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $url
    )

    try {
        $request = [System.Net.WebRequest]::Create($url)
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $decompressionStream = New-Object System.IO.Compression.GzipStream($stream, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object System.IO.StreamReader($decompressionStream)
        $contents = $reader.ReadToEnd()
        $contents -split "`n" | ConvertFrom-Json
    }

    catch {
        $_.Exception
    }
    finally {
        $reader.Close()
        $decompressionStream.Close()
        $stream.Close()
        $response.Close()
    }
}

Function Get-DefenderSoftwareInventoryExport {

    $headers = Get-DefenderATPHeaders 
    $result = Invoke-RestMethod -Uri 'https://api-us.securitycenter.windows.com/api/machines/SoftwareInventoryExport' -Headers $headers -Method Get
    
    if ($result.generatedTime.ToLocalTime() -gt (Get-Date).AddHours(-2)) {

        $GetDefenderforEndpointFile = ${function:Get-DefenderforEndpointFile}.ToString()
        $inputobject = $result.exportFiles | ForEach-Object -ThrottleLimit 3 -Parallel {
    
            ${function:Get-DefenderforEndpointFile} = $using:GetDefenderforEndpointFile 

            $properties = @(
                @{name = 'DeviceId'; expression = { $_.DeviceId } },
                @{name = 'DeviceName'; expression = { $_.DeviceName -replace "$dns_suffix", '' } },
                @{name = 'OSPlatform'; expression = { $_.OSPlatform } },
                @{name = 'SoftwareVendor'; expression = { $_.SoftwareVendor } },
                @{name = 'SoftwareName'; expression = { $_.SoftwareName } },
                @{name = 'SoftwareVersion'; expression = { if ($_.SoftwareVersion) { $_.SoftwareVersion } else { 0 } } },
                @{name = 'NumberOfWeaknesses'; expression = { $_.NumberOfWeaknesses } },
                @{name = 'DiskPaths'; expression = { $_.DiskPaths | ConvertTo-Json -Compress -AsArray } },
                @{name = 'RegistryPaths'; expression = { $_.RegistryPaths | ConvertTo-Json -Compress -AsArray } },
                @{name = 'SoftwareFirstSeenTimestamp'; expression = { $_.SoftwareFirstSeenTimestamp } },
                @{name = 'SoftwareLastSeenTimestamp'; expression = { $_.SoftwareLastSeenTimestamp } },
                @{name = 'EndOfSupportStatus'; expression = { $_.EndOfSupportStatus } },
                @{name = 'RbacGroupId'; expression = { $_.RbacGroupId } },
                @{name = 'RbacGroupName'; expression = { $_.RbacGroupName } }
            )

            Get-DefenderforEndpointFile -url $_ | Select-Object -Property $properties
        }

        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'defenderatp' -Table 'software_inventory_assessment' -Truncate $true
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
            $inputobject = $null
            
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }

}



Function Add-DefenderForEndPointIndicator {

    $headers = Get-DefenderATPHeaders 
    $uri = 'https://api-us.securitycenter.microsoft.com/api/indicators'

    $files = Import-Csv E:\PowerShell\temp\asr.csv
    $indicators = $files | Where-Object { [int]$_.Total -gt 1 -and $_.SHA1 -ne '' } | Select-Object FileName, SHA1, Total


    foreach ($file in $indicators) {

        $details = Invoke-RestMethod -Method Get -Uri "https://api-us.securitycenter.microsoft.com/api/files/$($file.SHA1)" -Headers $headers
    

        $body = [PSCustomObject]@{
            indicatorValue = $details.sha256
            indicatorType  = 'FileSha256'
            action         = 'Allowed'
            title          = $file.FileName
            description    = "Allow $($file.FileName) for ASR Rule ID 01443614-cd74-433a-b99e-2ecdc07bfc25"
        }

        $bodyjson = $body | ConvertTo-Json -Compress

        Invoke-RestMethod -Method Post -Uri $uri -Body $bodyjson -Headers $headers

    }

}

Function Get-DefenderforEndpointWindowsOffDomainMachines {

    $query = @'
    select offdomain.*,subnets.site from
    (SELECT regexp_replace(name,':-ADMINISTRATOR:|.WORKGROUP','') as name, lastipaddress,osplatform,lastseen
        FROM defenderatp.machines
	 where osplatform like 'Windows%' and osplatform not in ('WindowsCE','Windows') and osplatform not like '%Server%' and lastipaddress is not null
        ) offdomain
        left join "ActiveDirectory".subnets on offdomain.lastipaddress << subnets.name
		where offdomain.name not in (select name from "ActiveDirectory".computers)
'@

    $machines = Invoke-PGSqlQuery -Type Select -Query $query

    $hosts_status = $machines | ForEach-Object -ThrottleLimit 50 -Parallel {
        
        $pingable = if ([System.Net.NetworkInformation.Ping]::new().Send($_.lastipaddress, 5000).Status -eq 'Success') { $true } else { $false }
        try {
            $dns_ip = @([System.Net.Dns]::GetHostAddresses(($_.name)).IPAddressToString)[0]
        }
        catch {
        }
        if ($_.lastipaddress -ne $dns_ip -and $null -ne $dns_ip -and $dns_ip -isnot [array]) {
            $dns_ip_pingable = if ([System.Net.NetworkInformation.Ping]::new().Send($dns_ip, 5000).Status -eq 'Success') { $true } else { $false }
        }

        [PSCustomObject]@{
            site            = $_.site
            name            = $_.name
            osplatform      = $_.osplatform
            lastseen        = $_.lastseen
            ip              = $_.lastipaddress
            ip_pingable     = $pingable
            dns_ip          = $dns_ip
            dns_ip_pingable = $dns_ip_pingable
        } 
    }

    $groups = $hosts_status | Group-Object -Property osplatform

    foreach ($group in $groups) {
        # all hosts
        Write-Host $group.name - Total: $group.Group.Count - Online: ($group.group | Sort-Object -Property site, name | Where-Object { $_.ip_pingable -eq $true -or $_.dns_ip_pingable -eq $true }).count 
        #$group.group | Sort-Object -Property site, name | Format-Table

        # only pingable
        #$group.group | Sort-Object -Property site, name | Where-Object { $_.ip_pingable -eq $true -or $_.dns_ip_pingable -eq $true } | Format-Table
    }
}


Function Get-DefenderSoftwareInventoryHistory {
    $query = @'
    select count(*) as total,softwarename,softwarevendor,softwareversion,site
	FROM defenderatp.software_inventory_assessment
	join "ActiveDirectory".computers on lower(software_inventory_assessment.devicename) = lower(computers.name)
	group by softwarename,softwarevendor,softwareversion,site
'@

    $results = Invoke-PGSqlQuery -Type Select -Query $query

    $inputobject = $results | Select-Object total, softwarename, softwarevendor, softwareversion, site, numberofweaknesses, @{name = 'date'; expression = { '{0:d}' -f $(Get-Date).ToUniversalTime() } }

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Set Excluded' -Schema 'defenderatp' -Table 'software_inventory_assessment_hist' -Truncate $false
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Remove-DefenderForEndpointInactiveMachines {


    $query = @'
    SELECT id, machines.name, computerdnsname, firstseen, lastseen, osplatform, osversion, osprocessor, version,
    lastipaddress, lastexternalipaddress, agentversion, osbuild, healthstatus, 
    devicevalue, rbacgroupid, rbacgroupname, riskscore, exposurelevel, isaadjoined, aaddeviceid
        FROM defenderatp.machines
        where osplatform in ('Windows10','Windows11','WindowsServer2016','WindowsServer2019','WindowsServer2022') 
        and healthstatus = 'Inactive' 
        and lastseen < now() - interval '14 day' 
        and rbacgroupname != 'SecurityRecommendationExclusion' 
        and onboardingstatus = 'Onboarded'
        order by name
'@

    $inactive = Invoke-PGSqlQuery -Type Select -Query $query

    $headers = Get-DefenderATPHeaders 
    foreach ($machine in $inactive) {
        
        $offboardurl = "https://api-us.securitycenter.microsoft.com/api/machines/$($machine.id)/offboard"
        $tagsurl = "https://api-us.securitycenter.microsoft.com/api/machines/$($machine.id)/tags"

        $tagbody = [PSCustomObject]@{
            'Value'  = 'SecurityRecommendationExclusion'
            'Action' = 'Add'
        } | ConvertTo-Json

        $offboardbody = [PSCustomObject]@{
            Comment = "Offboard $($Machine.name) - $($machine.id)"
        } | ConvertTo-Json -Compress

        Invoke-RestMethod -Uri $offboardurl -Headers $headers -Method Post -Body $offboardbody | Out-Null
        Invoke-RestMethod -Uri $tagsurl -Headers $headers -Method Post -Body $tagbody | Out-Null

    }

}

Function Remove-DefenderForEndpointOrphanedMachines {


    $query = @'
    SELECT id, machines.name, computerdnsname, firstseen, lastseen, osplatform, osversion, osprocessor, version,
    lastipaddress, lastexternalipaddress, agentversion, osbuild, healthstatus, 
    devicevalue, rbacgroupid, rbacgroupname, riskscore, exposurelevel, isaadjoined, aaddeviceid
        FROM defenderatp.machines
        where osplatform in ('Windows10','Windows11','WindowsServer2016','WindowsServer2019','WindowsServer2022') 
        --and healthstatus = 'Inactive' 
        --and lastseen > now() - interval '14 day' 
        and rbacgroupname != 'SecurityRecommendationExclusion' 
        and onboardingstatus = 'Onboarded'
        and name not in (select name from "ActiveDirectory".computers)
        order by lastseen
'@

    $inactive = Invoke-PGSqlQuery -Type Select -Query $query

    $headers = Get-DefenderATPHeaders 
    foreach ($machine in $inactive) {
        
        $offboardurl = "https://api-us.securitycenter.microsoft.com/api/machines/$($machine.id)/offboard"
        $tagsurl = "https://api-us.securitycenter.microsoft.com/api/machines/$($machine.id)/tags"

        $tagbody = [PSCustomObject]@{
            'Value'  = 'SecurityRecommendationExclusion'
            'Action' = 'Add'
        } | ConvertTo-Json

        $offboardbody = [PSCustomObject]@{
            Comment = "Offboard $($Machine.name) - $($machine.id)"
        } | ConvertTo-Json -Compress

        Invoke-RestMethod -Uri $offboardurl -Headers $headers -Method Post -Body $offboardbody | Out-Null
        Invoke-RestMethod -Uri $tagsurl -Headers $headers -Method Post -Body $tagbody | Out-Null

    }

}


Function Remove-DefenderForEndpointHealthyMachineTags {
    $query = @'
select id,name from defenderatp.machines
where healthstatus = 'Active'
and rbacgroupname = 'SecurityRecommendationExclusion'
'@

    $active = Invoke-PGSqlQuery -Type Select -Query $query

    $headers = Get-DefenderATPHeaders 
    foreach ($machine in $active) {
    
        $tagsurl = "https://api-us.securitycenter.microsoft.com/api/machines/$($machine.id)/tags"
        $tagbody = [PSCustomObject]@{
            'Value'  = 'SecurityRecommendationExclusion'
            'Action' = 'Remove'
        } | ConvertTo-Json
        Invoke-RestMethod -Uri $tagsurl -Headers $headers -Method Post -Body $tagbody

    }
}

Function Get-DefenderForEndpointChromeClients {


 

    $query = @"
    DeviceTvmSoftwareVulnerabilities 
    | where SoftwareName == @"chrome"
    | distinct DeviceId,DeviceName
    | join  (DeviceInfo
    | where RegistryDeviceTag == @"SCCM"
    | distinct DeviceId
    ) on DeviceId
    | join kind=leftouter (DeviceProcessEvents
    | where FileName == @"chrome.exe"
        | distinct DeviceId
    ) on (DeviceId) 
    | where DeviceId2 == ''
    | project DeviceId,DeviceName
"@

    $json = [PSCustomObject]@{
        Query = $query
    } | ConvertTo-Json -Compress

    $url = 'https://api-us.securitycenter.microsoft.com/api/advancedqueries/run'
    $result = Invoke-RestMethod -Uri $url -Headers (Get-DefenderATPHeaders) -Method post -Body $json
    $results = $result.Results | Select-Object deviceid, devicename,@{Name='ad_name';Expression={$_.devicename.ToUpper() -replace "\..*$",""}}
 

    Invoke-PGSqlQuery -Type Insert -InputObject $results -Schema 'defenderatp' -Table 'chromeclients' -OnConflict 'Do Nothing' -Truncate $true

}

Function Get-DefenderForEndpointZoomClients {


 

    $query = @'
    DeviceTvmSoftwareVulnerabilities 
    | where SoftwareVendor == "zoom" and SoftwareName in ('meetings','rooms')
    | distinct DeviceId,DeviceName
    | join  (DeviceInfo
    | where RegistryDeviceTag == @"SCCM"
    | distinct DeviceId
    ) on DeviceId
    | join kind=leftouter (DeviceProcessEvents
        | where  FileName == @"Zoom.exe"
        | where Timestamp > ago(30d)
        | distinct(DeviceId)
    ) on DeviceId
'@

    $json = [PSCustomObject]@{
        Query = $query
    } | ConvertTo-Json -Compress

    $url = 'https://api-us.securitycenter.microsoft.com/api/advancedqueries/run'
    $result = Invoke-RestMethod -Uri $url -Headers (Get-DefenderATPHeaders) -Method post -Body $json
    $results = $result.Results | Select-Object deviceid, deviceid2, @{Name = 'devicename'; Expression = { $_.devicename -replace $dns_suffix, '' } } 
 

    Invoke-PGSqlQuery -Type Insert -InputObject $results -Schema 'defenderatp' -Table 'zoomclients' -OnConflict 'Do Nothing' -Truncate $true

}

Function Get-DefenderforEndpointRecommendations {

    $properties = @(
        'activealert',
        @{Name = 'associatedthreats'; Expression = { $_.associatedthreats | ConvertTo-Json -Compress } },
        'configscoreimpact',
        'exposedmachinescount',
        'exposureimpact',
        'hasunpatchablecve',
        'id',
        'nonproductivityimpactedassets',
        'productname',
        'publicexploit',
        'recommendationcategory',
        'recommendationname',
        'recommendedprogram',
        'recommendedvendor',
        'recommendedversion',
        'relatedcomponent',
        'remediationtype',
        'severityscore',
        'status',
        'subcategory',
        @{Name = 'tags'; Expression = { $_.tags | ConvertTo-Json -Compress } },
        'totalmachinecount',
        'vendor',
        'weaknesses')

    $url = 'https://api-us.securitycenter.windows.com/api/recommendations'
    $recommendations = Get-DefenderforEndpointPagedData -Uri $url
    $inputobject = $recommendations | Select-Object -Property $properties

    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -Schema 'defenderatp' -Table 'recommendations' -OnConflict 'Do Nothing' -Truncate $true
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-DefenderforEndpointExposureScore {

    $headers = Get-DefenderATPHeaders 
    $url = 'https://api-us.securitycenter.windows.com/api/exposureScore'
    $exposurescore = (Invoke-RestMethod -Uri $url -Headers $headers -Method Get) | Select-Object time, score
        
    try {
        Invoke-PGSqlQuery -Type Insert -InputObject $exposurescore -Schema 'defenderatp' -Table 'exposurescore' -OnConflict 'Set Excluded' -Truncate $false
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
    }
    catch {
        Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
    }
}

Function Get-DefenderInfoGatheringExport {
    $headers = Get-DefenderATPHeaders 
    $result = Invoke-RestMethod -Uri 'https://api-us.securitycenter.windows.com/api/machines/InfoGatheringExport' -Headers $headers -Method Get
    
    if ($result.generatedTime.ToLocalTime() -gt (Get-Date).AddHours(-2)) {

        $GetDefenderforEndpointFile = ${function:Get-DefenderforEndpointFile}.ToString()
        $inputobject = $result.exportFiles | ForEach-Object -ThrottleLimit 3 -Parallel {

            ${function:Get-DefenderforEndpointFile} = $using:GetDefenderforEndpointFile 

            $properties = @(
                'DeviceId',
                'DeviceName',
                @{Name = 'LastSeenTime'; Expression = { [datetime]$_.LastSeenTime } },
                'OsPlatform',
                'OsVersion',
                'RbacGroupId',
                'RbacGroupName',
                @{Name = 'Timestamp'; Expression = { [datetime]$_.Timestamp } },
                'DeviceGatheredInfo'
            )
            Get-DefenderforEndpointFile -url $_ | Select-Object -Property $properties
        }

        try {
            Invoke-PGSqlQuery -Type Insert -InputObject $inputobject -OnConflict 'Do Nothing' -Schema 'defenderatp' -Table 'info_gathering_export' -Truncate $true
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$((Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name)" -Severity 1 -Schedule $Schedule
            $inputobject = $null
            
        }
        catch {
            Write-PGSQLLog -Log $PSCommandPath.Split('\')[-1] -Component $MyInvocation.MyCommand -Value "$($_.Exception)" -Severity 3 -Schedule $Schedule
        }
    }
}


Function Invoke-DFEScheduledFunction {
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
            Write-Output 'Get-DefenderATPIncidents'; Get-DefenderATPIncidents
            Write-Output 'Get-DefenderATPMachines'; Get-DefenderATPMachines
            Write-Output 'Get-DefenderATPCanbeOnboardedMachines'; Get-DefenderATPCanbeOnboardedMachines
            Write-Output 'Get-DefenderforEndpointRecommendations'; Get-DefenderforEndpointRecommendations
            Write-Output 'Get-DefenderforEndpointExposureScore'; Get-DefenderforEndpointExposureScore
            Write-Output 'Get-DefenderSoftwareInventoryExport'; Get-DefenderSoftwareInventoryExport
            Write-Output 'Get-DefenderInfoGatheringExport'; Get-DefenderInfoGatheringExport
            Write-Output 'Get-DefenderSoftwareInventoryHistory'; Get-DefenderSoftwareInventoryHistory
            Write-Output 'Get-DefenderForEndpointChromeClients'; Get-DefenderForEndpointChromeClients

        }
        'Daily' {
            Write-Output 'Get-DefenderATPDeviceLogons'; Get-DefenderATPDeviceLogons
            Write-Output 'Remove-DefenderForEndpointInactiveMachines'; Remove-DefenderForEndpointInactiveMachines
            Write-Output 'Remove-DefenderForEndpointOrphanedMachines'; Remove-DefenderForEndpointOrphanedMachines
            Write-Output 'Remove-DefenderForEndpointHealthyMachineTags'; Remove-DefenderForEndpointHealthyMachineTags
            Write-Output 'Get-DefenderForEndpointIndicators'; Get-DefenderForEndpointIndicators
            Write-Output 'Get-DefenderForEndpointZoomClients'; Get-DefenderForEndpointZoomClients
            Write-Output 'Get-DefenderForEndpointDeviceNetworkInfo'; Get-DefenderForEndpointDeviceNetworkInfo
        }
    }

}

